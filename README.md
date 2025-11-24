# Forwarding

A high-performance TCP connection forwarding tool written in Go. Forward traffic from public interfaces to loopback interfaces with extremely high performance, similar to `nc` but optimized for throughput and low latency.

## Features

- **High Performance**: Uses 32KB buffers, TCP NoDelay, and buffer pooling for optimal throughput
- **Auto Outbound Interface Detection**: Detects the local interface IP used to reach the public Internet and uses that for binding listeners; it also detects the external public IP (for informational/logging purposes) but does not bind to the external public IP (which may belong to a load balancer or NAT).
- **Multiple Port Mappings**: Support for forwarding multiple ports simultaneously
- **Flexible Configuration**: Comma-separated or multiple `-p` flags for port mappings
- **TCP Keepalive**: Built-in connection management with TCP keepalive
- **Concurrent Connections**: Handles multiple concurrent connections efficiently

## Installation

```bash
go install github.com/worthies/forwarding@latest
```

Or build from source:

```bash
git clone https://github.com/worthies/forwarding
cd forwarding
go build -o forwarding .
```

## Usage

```bash
forwarding -p <public_port:private_port> [-d <detect_ip>] [-l <listen_addr>]
```

### Options

- `-p`: Port mapping in format 'public:private' (can be specified multiple times or comma-separated)
- `-d`: Optional local interface IP to use as the source for public IP detection (instead of auto-detecting the outbound interface). This is not the external/public IP.
- `-l`: Optional listen address (default: auto-detected local outbound interface IP; use 0.0.0.0 for all interfaces)

### Examples

Forward port 8080 to local port 80:
```bash
forwarding -p 8080:80
```

Forward multiple ports:
```bash
forwarding -p 8080:80 -p 8443:443
```

Forward multiple ports using comma-separated format:
```bash
forwarding -p 8080:80,8443:443
```

Listen on all interfaces:
```bash
forwarding -p 8080:80 -l 0.0.0.0
```

Use specific IP for public IP detection:
```bash
forwarding -p 8080:80 -d 192.168.1.100
```

## How It Works

1. The tool detects the local outbound interface IP used to reach the public Internet, and optionally the public IP.
2. It binds to the detected (or explicitly specified) local interface IP (not the external public IP) on the public port(s)
3. When a connection is received, it forwards the traffic to `127.0.0.1:<private_port>`
4. Data is bidirectionally forwarded between the public and private connections
5. Connections are managed with TCP keepalive and proper cleanup

## Performance Optimizations

- **Buffer Pooling**: Uses `sync.Pool` to reuse 32KB buffers across connections, reducing GC pressure
- **TCP NoDelay**: Disables Nagle's algorithm for lower latency
- **Large Buffers**: 32KB buffers for high throughput
- **TCP Keepalive**: Maintains connections efficiently with 30-second keepalive periods
- **Concurrent Handling**: Each connection is handled in a separate goroutine

## License

See LICENSE file for details.
