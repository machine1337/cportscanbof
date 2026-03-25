#include <windows.h>
#include "beacon.h"

#define MAX_RESULTS 128
#define MAX_IPS 64
#define TIMEOUT_MS 3000

static char outbuf[4096];
static int outpos = 0;

static int my_atoi(const char *s) {
    int n = 0;
    while (*s >= '0' && *s <= '9') n = n * 10 + (*s++ - '0');
    return n;
}

static int my_strlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return p - s;
}

static void my_strcpy(char *d, const char *s) {
    while ((*d++ = *s++));
}

static void my_strcat(char *d, const char *s) {
    while (*d) d++;
    while ((*d++ = *s++));
}

static void my_itoa(int n, char *b) {
    int i = 0, j, t;
    if (!n) { b[0] = '0'; b[1] = 0; return; }
    while (n) { b[i++] = '0' + (n % 10); n /= 10; }
    b[i] = 0;
    for (j = 0; j < i/2; j++) { t = b[j]; b[j] = b[i-1-j]; b[i-1-j] = t; }
}

static void* get_func(const char *dll, const char *func) {
    HMODULE h = LoadLibraryA(dll);
    return h ? (void*)GetProcAddress(h, func) : NULL;
}

typedef int (WINAPI *WSASTARTUP)(WORD, LPWSADATA);
typedef int (WINAPI *WSACLEANUP)(void);
typedef SOCKET (WINAPI *SOC)(int, int, int);
typedef int (WINAPI *CLS)(SOCKET);
typedef int (WINAPI *CONN)(SOCKET, const struct sockaddr*, int);
typedef unsigned long (WINAPI *INET_ADDR)(const char*);
typedef u_short (WINAPI *HTONS)(u_short);
typedef int (WINAPI *SETOPT)(SOCKET, int, int, const char*, int);
typedef int (WINAPI *WSAGLE)(void);

static unsigned long ip2ulong(const char *ip) {
    unsigned long r = 0;
    int o = 0, s = 24;
    while (*ip) {
        if (*ip >= '0' && *ip <= '9') o = o * 10 + (*ip - '0');
        else if (*ip == '.') { r |= ((unsigned long)o << s); o = 0; s -= 8; }
        ip++;
    }
    return r | ((unsigned long)o << s);
}

static void ulong2ip(unsigned long ip, char *buf) {
    unsigned char *o = (unsigned char*)&ip;
    char tmp[8];
    int p = 0, i, j;
    for (i = 0; i < 4; i++) {
        my_itoa(o[i], tmp);
        for (j = 0; tmp[j]; j++) buf[p++] = tmp[j];
        if (i < 3) buf[p++] = '.';
    }
    buf[p] = 0;
}

static int has_cidr(const char *s) {
    while (*s) if (*s++ == '/') return 1;
    return 0;
}

static int parse_cidr(const char *in, char *ip, int *pre) {
    int i = 0;
    while (in[i] && in[i] != '/') ip[i] = in[i++];
    ip[i] = 0;
    if (in[i] == '/') { *pre = my_atoi(&in[i+1]); return 1; }
    return 0;
}
static char open_ips[MAX_RESULTS][16];
static int open_ports[MAX_RESULTS];
static int open_cnt = 0;

static char closed_ips[MAX_RESULTS][16];
static int closed_ports[MAX_RESULTS];
static int closed_cnt = 0;

static int scan_port(const char *ip, int port, SOC pSocket, CONN pConnect,
                     INET_ADDR pInetAddr, HTONS pHtons, SETOPT pSetOpt,
                     CLS pClose, WSAGLE pGLE) {
    SOCKET s;
    struct sockaddr_in a;
    DWORD timeout = TIMEOUT_MS;
    int r;
    
    s = pSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return -1;
    
    pSetOpt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    pSetOpt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    a.sin_family = AF_INET;
    a.sin_port = pHtons((u_short)port);
    a.sin_addr.s_addr = pInetAddr(ip);
    if (a.sin_addr.s_addr == INADDR_NONE) { pClose(s); return -1; }
    
    r = pConnect(s, (struct sockaddr*)&a, sizeof(a));
    pClose(s);
    
    if (r == 0) {
        if (open_cnt < MAX_RESULTS) {
            my_strcpy(open_ips[open_cnt], ip);
            open_ports[open_cnt] = port;
            open_cnt++;
        }
        return 0;
    } else {
        if (closed_cnt < MAX_RESULTS) {
            my_strcpy(closed_ips[closed_cnt], ip);
            closed_ports[closed_cnt] = port;
            closed_cnt++;
        }
        return 1;
    }
}

static void scan_ip(const char *ip, const char *ports, SOC pSocket, CONN pConnect,
                    INET_ADDR pInetAddr, HTONS pHtons, SETOPT pSetOpt,
                    CLS pClose, WSAGLE pGLE) {
    char pb[8];
    int i = 0, j = 0, port;
    
    while (ports[i]) {
        if (ports[i] == ',') {
            if (j > 0) {
                pb[j] = 0; port = my_atoi(pb);
                if (port > 0 && port <= 65535) {
                    scan_port(ip, port, pSocket, pConnect, pInetAddr, pHtons,
                              pSetOpt, pClose, pGLE);
                }
                j = 0;
            }
        } else if (j < 7 && ports[i] >= '0' && ports[i] <= '9') pb[j++] = ports[i];
        i++;
    }
    
    if (j > 0) {
        pb[j] = 0; port = my_atoi(pb);
        if (port > 0 && port <= 65535) {
            scan_port(ip, port, pSocket, pConnect, pInetAddr, pHtons,
                      pSetOpt, pClose, pGLE);
        }
    }
}

static void expand_cidr(const char *cidr, char *out_ips, int *cnt) {
    char ipb[32];
    int pre;
    unsigned long start, end, i, mask;
    
    parse_cidr(cidr, ipb, &pre);
    if (pre < 24 || pre > 32) return;
    
    start = ip2ulong(ipb);
    mask = 0xFFFFFFFF << (32 - pre);
    start &= mask;
    end = start | (~mask);
    
    for (i = start; i <= end && *cnt < MAX_IPS; i++) {
        ulong2ip(i, out_ips + (*cnt * 16));
        (*cnt)++;
    }
}

static void output(const char *targets, const char *ports) {
    char ps[8];
    int i;
    my_strcpy(outbuf, "[*] Targets: ");
    my_strcat(outbuf, targets);
    my_strcat(outbuf, "\n[*] Ports: ");
    my_strcat(outbuf, ports);
    outpos = my_strlen(outbuf);
    
    if (open_cnt > 0) {
        my_strcat(outbuf, "\n\n[+] OPEN PORTS:");
        for (i = 0; i < open_cnt; i++) {
            my_strcat(outbuf, "\n[+] ");
            my_strcat(outbuf, open_ips[i]);
            my_strcat(outbuf, ":");
            my_itoa(open_ports[i], ps);
            my_strcat(outbuf, ps);
        }
    }
    
    if (closed_cnt > 0) {
        my_strcat(outbuf, "\n\n[-] CLOSED/FILTERED PORTS:");
        for (i = 0; i < closed_cnt; i++) {
            my_strcat(outbuf, "\n[-] ");
            my_strcat(outbuf, closed_ips[i]);
            my_strcat(outbuf, ":");
            my_itoa(closed_ports[i], ps);
            my_strcat(outbuf, ps);
        }
    }
    
    my_strcat(outbuf, "\n\n[*] Scan complete");
    outpos = my_strlen(outbuf);
    
    BeaconOutput(CALLBACK_OUTPUT, outbuf, outpos);
}

void go(char *args, int len) {
    datap parser;
    char *targets, *ports;
    int tl, pl;
    static char ips[MAX_IPS * 16];
    int ip_cnt = 0;
    int i;
    char tb[64];
    int ti = 0, tj = 0;
    
    WSASTARTUP pWSA = (WSASTARTUP)get_func("ws2_32.dll", "WSAStartup");
    WSACLEANUP pWC = (WSACLEANUP)get_func("ws2_32.dll", "WSACleanup");
    SOC pSocket = (SOC)get_func("ws2_32.dll", "socket");
    CLS pClose = (CLS)get_func("ws2_32.dll", "closesocket");
    CONN pConn = (CONN)get_func("ws2_32.dll", "connect");
    INET_ADDR pInet = (INET_ADDR)get_func("ws2_32.dll", "inet_addr");
    HTONS pHtons = (HTONS)get_func("ws2_32.dll", "htons");
    SETOPT pSetOpt = (SETOPT)get_func("ws2_32.dll", "setsockopt");
    WSAGLE pGLE = (WSAGLE)get_func("ws2_32.dll", "WSAGetLastError");
    
    open_cnt = 0;
    closed_cnt = 0;
    
    BeaconDataParse(&parser, args, len);
    targets = BeaconDataExtract(&parser, &tl);
    ports = BeaconDataExtract(&parser, &pl);
    
    if (!targets || !ports) {
        BeaconOutput(CALLBACK_ERROR, "[-] Missing arguments", 21);
        return;
    }
    
    {
        WSADATA wsa;
        if (!pWSA || pWSA(0x0202, &wsa) != 0) {
            BeaconOutput(CALLBACK_ERROR, "[-] WSAStartup failed", 21);
            return;
        }
    }
    
    /* Parse targets */
    while (targets[ti]) {
        if (targets[ti] == ',') {
            if (tj > 0 && ip_cnt < MAX_IPS) {
                tb[tj] = 0;
                if (has_cidr(tb)) expand_cidr(tb, (char*)ips, &ip_cnt);
                else { my_strcpy(ips + (ip_cnt * 16), tb); ip_cnt++; }
                tj = 0;
            }
        } else if (tj < 63) tb[tj++] = targets[ti];
        ti++;
    }
    if (tj > 0 && ip_cnt < MAX_IPS) {
        tb[tj] = 0;
        if (has_cidr(tb)) expand_cidr(tb, (char*)ips, &ip_cnt);
        else { my_strcpy(ips + (ip_cnt * 16), tb); ip_cnt++; }
    }
    
    if (ip_cnt == 0) {
        BeaconOutput(CALLBACK_ERROR, "[-] No valid targets", 20);
        pWC();
        return;
    }
    
    for (i = 0; i < ip_cnt; i++) {
        scan_ip(ips + (i * 16), ports, pSocket, pConn, pInet, pHtons,
                pSetOpt, pClose, pGLE);
    }
    
    output(targets, ports);
    pWC();
}
/* Developed By: machine1337 */
