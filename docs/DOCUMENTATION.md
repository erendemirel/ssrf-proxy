## Configuration Options

| Flag | Default | Description |
|------|---------|-------------|
| `-port` | `8080` | Port to listen on |
| `-verbose` | `false` | Enable verbose logging |
| `-allow-internal` | `false` | Allow requests to internal IP addresses |
| `-allow-dns-rebinding` | `false` | Allow potential DNS rebinding requests |
| `-max-redirects` | `3` | Maximum number of redirects to follow |
| `-timeout` | `30s` | Request timeout duration |

### Example Configurations

#### Development Mode (Permissive)
```bash
./ssrf-proxy \
  -port 8080 \
  -verbose \
  -allow-internal \
  -allow-dns-rebinding \
  -max-redirects 10
```

#### Production Mode (Strict)
```bash
./ssrf-proxy \
  -port 8080 \
  -max-redirects 1 \
  -timeout 10s
```

#### Custom Port with Verbose Logging
```bash
./ssrf-proxy -port 3000 -verbose
```


## Detection Capabilities

### 1. Internal IP Address Detection

The proxy detects and blocks requests to:
- **Private IPv4 ranges**: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- **Loopback addresses**: 127.0.0.0/8, ::1/128
- **Link-local addresses**: 169.254.0.0/16, fe80::/10
- **Unique local IPv6**: fc00::/7

**Example blocked requests**:
```bash
curl http://localhost:8080/http://192.168.1.1      # Blocked
curl http://localhost:8080/http://10.0.0.1         # Blocked  
curl http://localhost:8080/http://127.0.0.1        # Blocked
curl http://localhost:8080/http://localhost        # Blocked
```

### 2. DNS Rebinding Attack Detection

Detects suspicious DNS patterns that could indicate DNS rebinding:
- IP addresses followed by domains (`192.168.1.1.evil.com`)
- localhost subdomains (`localhost.evil.com`)
- Domains ending with internal IPs (`evil.com.127.0.0.1`)
- Hosts resolving to both internal and external IPs

**Example blocked requests**:
```bash
curl http://localhost:8080/http://192.168.1.1.evil.com    # Blocked
curl http://localhost:8080/http://localhost.attacker.com  # Blocked
```

### 3. Uncommon HTTP Method Detection

By default, only these methods are allowed:
- GET, POST, PUT, DELETE, HEAD, PATCH

**Example blocked requests**:
```bash
curl -X TRACE http://localhost:8080/http://example.com     # Blocked
curl -X CONNECT http://localhost:8080/http://example.com   # Blocked
curl -X OPTIONS http://localhost:8080/http://example.com   # Blocked
```


## Integration Examples

### With Docker
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ssrf-proxy main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/ssrf-proxy .
EXPOSE 8080
CMD ["./ssrf-proxy"]
```

### With Kubernetes
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ssrf-proxy
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ssrf-proxy
  template:
    metadata:
      labels:
        app: ssrf-proxy
    spec:
      containers:
      - name: ssrf-proxy
        image: ssrf-proxy:latest
        ports:
        - containerPort: 8080
        args: ["-port", "8080", "-verbose"]
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
```

### With Nginx (Reverse Proxy)
```nginx
upstream ssrf_proxy {
    server 127.0.0.1:8080;
}

server {
    listen 80;
    server_name proxy.example.com;
    
    location / {
        proxy_pass http://ssrf_proxy;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```


## Logging and Monitoring

### Log Format

The proxy uses Go's standard `log/slog` package for structured JSON logging:

```json
{
  "time": "2025-06-06T17:14:29.8581776+03:00",
  "level": "WARN",
  "msg": "SSRF attempt detected",
  "type": "internal_ip",
  "description": "Request to internal IP address detected: 127.0.0.1 -> 127.0.0.1",
  "url": "http://127.0.0.1:8080/test",
  "method": "GET",
  "ip": "127.0.0.1",
  "client_ip": "[::1]:58465",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.19045; en-US) PowerShell/7.6.0"
}
```

### Monitoring Integration

The proxy provides a health check endpoint for monitoring:

```bash
curl http://localhost:8080/health
# Response: {"status": "healthy", "service": "ssrf-proxy"}
```


## Security Considerations

### 1. Trust Boundaries
- Deploy the proxy within your trusted network perimeter
- Use HTTPS for production deployments
- Implement proper authentication for management endpoints

### 2. Rate Limiting
Consider implementing rate limiting for production use:
```bash
# Example with iptables
iptables -A INPUT -p tcp --dport 8080 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
```

### 3. Monitoring and Alerting
- Monitor logs for repeated SSRF attempts
- Set up alerts for high volumes of blocked requests
- Track successful vs. blocked request ratios

## Troubleshooting

### Common Issues

**1. Connection Refused**
```
Error: Proxy request failed
```
- Check if the target service is accessible
- Verify network connectivity
- Check firewall rules

**2. DNS Resolution Failures**
```
Failed to resolve host
```
- Verify DNS server configuration
- Check if the domain exists
- Test with `nslookup` or `dig`

**3. Certificate Errors**
```
TLS handshake failed
```
- The proxy validates TLS certificates by default
- For development, target services must have valid certificates
- Self-signed certificates will be rejected

### Debug Mode

Enable verbose logging for troubleshooting:
```bash
./ssrf-proxy -verbose
```

This will show detailed information about DNS resolution, IP validation, and request processing.
