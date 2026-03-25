# cportscan - Cobalt Strike TCP Port Scanner BOF

A fast and efficient TCP port scanner implemented as a Beacon Object File (BOF) for Cobalt Strike.

## Features

- **Fast scanning** - Uses socket timeouts for efficient parallel-like scanning
- **Multiple target support** - Scan single IPs, multiple IPs, or CIDR ranges
- **Grouped results** - Open and closed/filtered ports shown separately
- **No external dependencies** - Dynamically resolves all required APIs
- **BOF compatible** - Runs in Beacon's memory without dropping files

## Usage

```
cportscan <targets> <ports>
```

### Target Formats

- **Single IP**: `192.168.1.1`
- **Multiple IPs**: `192.168.1.1,192.168.1.2,192.168.1.3`
- **CIDR Range**: `192.168.1.0/24` (max /24 = 256 hosts)
- **Mixed**: `192.168.1.1,10.0.0.0/24,172.16.1.5`

### Port Formats

- **Single port**: `80`
- **Multiple ports**: `80,443,445,3389`

## Examples

```
# Scan single IP on single port
cportscan 192.168.1.1 80

# Scan multiple IPs on multiple ports
cportscan 192.168.1.1,192.168.1.2 80,443,445

# Scan entire /24 subnet for common ports
cportscan 192.168.1.0/24 22,3389,5985,5986

# Mixed targets
cportscan 10.0.0.0/24,192.168.1.5,172.16.1.10 445,3389
```

## Sample Output

```
[*] Targets: 192.168.1.1,192.168.1.2
[*] Ports: 80,443,445

[+] OPEN PORTS:
[+] 192.168.1.1:445
[+] 192.168.1.2:80
[+] 192.168.1.2:445

[-] CLOSED/FILTERED PORTS:
[-] 192.168.1.1:80
[-] 192.168.1.1:443
[-] 192.168.1.2:443

[*] Scan complete
```

## Compilation

### Requirements
- MinGW-w64 (x86_64-w64-mingw32-gcc)
- MinGW-w32 (i686-w64-mingw32-gcc) for 32-bit support

### Build

```bash
# Build for x64 (64-bit Beacon)
x86_64-w64-mingw32-gcc -Os -fno-stack-check -mno-stack-arg-probe -c cportscan.c -o cportscan.x64.o

# Build for x86 (32-bit Beacon)
i686-w64-mingw32-gcc -Os -fno-stack-check -mno-stack-arg-probe -c cportscan.c -o cportscan.x86.o
```

## Installation

1. Copy `cportscan.cna` and the compiled `.o` files to your Cobalt Strike scripts folder
2. Load `cportscan.cna` in Cobalt Strike: **Cobalt Strike** → **Script Manager** → **Load**
3. Use `cportscan` command in Beacon console

## Technical Details

- **Timeout**: 3 seconds per port
- **Max targets**: 64 IPs (CIDR expansion included)
- **Max results**: 128 ports total
- **CIDR limit**: /24 maximum (256 hosts)
- **Output buffer**: 4KB

## Notes

- The BOF uses blocking sockets with `SO_SNDTIMEO`/`SO_RCVTIMEO` for timeout handling
- Results are buffered and sent as a single output block for clean display
- Scanning large CIDR ranges (/24) with multiple ports will take time due to sequential scanning

## Credits

Based on the Cobalt Strike BOF template and Beacon API.
