# ssrf proxy

A lightweight, zero dependency, standalone SSRF detection proxy.


## Features

### Detection Capabilities

- Internal IP Address Detection
- DNS Rebinding Attack Detection
- Uncommon HTTP Method Detection
- Redirect Chain attacks


## Quick Start

### Installation Options

#### Option 1: Pre-built Binaries

Ready-to-use executables for all platforms:


| Platform | Download & Run |
|----------|----------------|
| **Windows** | Download `ssrf-proxy-windows-amd64.exe` → Run: `.\ssrf-proxy-windows-amd64.exe` |
| **Linux** | Download `ssrf-proxy-linux-amd64` → Run: `chmod +x ssrf-proxy-linux-amd64 && ./ssrf-proxy-linux-amd64` |
| **macOS Intel** | Download `ssrf-proxy-darwin-amd64` → Run: `chmod +x ssrf-proxy-darwin-amd64 && ./ssrf-proxy-darwin-amd64` |
| **macOS Apple Silicon** | Download `ssrf-proxy-darwin-arm64` → Run: `chmod +x ssrf-proxy-darwin-arm64 && ./ssrf-proxy-darwin-arm64` |

#### Option 2: Docker Container
```bash
docker build -t ssrf-proxy .
docker run -p 8080:8080 ssrf-proxy
```

### Quick Test
```bash
# Test the health endpoint (works with any installation method)
curl http://localhost:8080/health
```

### Basic Usage

The proxy works in two modes:

#### Mode 1: URL in Path
```bash
# This request will be proxied to http://example.com
curl http://localhost:8080/http://example.com

# This will be blocked (internal IP)
curl http://localhost:8080/http://192.168.1.1
```

#### Mode 2: Custom Header
```bash
# Use X-Target-URL header to specify the target
curl -H "X-Target-URL: http://example.com" http://localhost:8080/
```

## License

Licensed under the MIT License