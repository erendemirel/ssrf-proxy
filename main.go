package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type SSRFProxy struct {
	logger            *slog.Logger
	allowedMethods    map[string]bool
	maxRedirects      int
	timeoutDuration   time.Duration
	blockInternalIPs  bool
	blockDNSRebinding bool
	verbose           bool
}

type SSRFDetection struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Method      string `json:"method"`
	IP          string `json:"ip,omitempty"`
}

type ssrfBlockError struct {
	detections []SSRFDetection
	reason     string
}

func (e *ssrfBlockError) Error() string {
	if e.reason != "" {
		return e.reason
	}
	return "SSRF attempt detected"
}

func NewSSRFProxy() *SSRFProxy {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	return &SSRFProxy{
		logger: logger,
		allowedMethods: map[string]bool{
			"GET":    true,
			"POST":   true,
			"PUT":    true,
			"DELETE": true,
			"HEAD":   true,
			"PATCH":  true,
		},
		maxRedirects:      3,
		timeoutDuration:   30 * time.Second,
		blockInternalIPs:  true,
		blockDNSRebinding: true,
	}
}

// parseHostIP parses dotted IP literals and decimal IPv4 forms such as 2130706433.
func parseHostIP(host string) net.IP {
	if host == "" {
		return nil
	}

	if ip := net.ParseIP(host); ip != nil {
		return ip
	}

	if n, err := strconv.ParseUint(host, 10, 32); err == nil {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, uint32(n))
		return ip
	}

	return nil
}

func (p *SSRFProxy) isInternalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}

	if ip4 := ip.To4(); ip4 != nil {
		// Broadcast
		if ip4[0] == 255 && ip4[1] == 255 && ip4[2] == 255 && ip4[3] == 255 {
			return true
		}
	}

	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
		"::/128",
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

func (p *SSRFProxy) resolveHost(host string) ([]net.IP, error) {
	if ip := parseHostIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	return net.LookupIP(host)
}

func (p *SSRFProxy) hasSuspiciousDNSPattern(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}

	suspiciousPatterns := []string{
		`\d+\.\d+\.\d+\.\d+\..*\..*`,
		`localhost\..*`,
		`127\.0\.0\.1\..*`,
		`.*\.127\.0\.0\.1`,
		`.*\.localhost`,
	}

	for _, pattern := range suspiciousPatterns {
		matched, _ := regexp.MatchString(pattern, host)
		if matched {
			return true
		}
	}

	return false
}

func (p *SSRFProxy) detectDNSRebinding(host string) bool {
	if p.hasSuspiciousDNSPattern(host) {
		return true
	}

	ips, err := p.resolveHost(host)
	if err != nil {
		return false
	}

	hasExternal := false
	hasInternal := false

	for _, ip := range ips {
		if p.isInternalIP(ip) {
			hasInternal = true
		} else {
			hasExternal = true
		}
	}

	return hasExternal && hasInternal
}

// validateURL checks a concrete target URL. It never reads X-Target-URL, so
// redirect validation cannot be confused by a forwarded header.
func (p *SSRFProxy) validateURL(method string, targetURL *url.URL, checkMethod bool) []SSRFDetection {
	var detections []SSRFDetection

	if targetURL == nil {
		return detections
	}

	if checkMethod && !p.allowedMethods[method] {
		detections = append(detections, SSRFDetection{
			Type:        "uncommon_method",
			Description: fmt.Sprintf("Uncommon HTTP method detected: %s", method),
			URL:         targetURL.String(),
			Method:      method,
		})
	}

	host := targetURL.Hostname()
	if host == "" {
		return detections
	}

	if p.blockDNSRebinding && p.detectDNSRebinding(host) {
		detections = append(detections, SSRFDetection{
			Type:        "dns_rebinding",
			Description: fmt.Sprintf("Potential DNS rebinding attack detected for host: %s", host),
			URL:         targetURL.String(),
			Method:      method,
		})
	}

	ips, err := p.resolveHost(host)
	if err != nil {
		if p.verbose {
			p.logger.Warn("Failed to resolve host", "host", host, "error", err)
		}
		return detections
	}

	for _, ip := range ips {
		if p.blockInternalIPs && p.isInternalIP(ip) {
			detections = append(detections, SSRFDetection{
				Type:        "internal_ip",
				Description: fmt.Sprintf("Request to internal IP address detected: %s -> %s", host, ip.String()),
				URL:         targetURL.String(),
				Method:      method,
				IP:          ip.String(),
			})
		}
	}

	return detections
}

// validateRequest validates the initial inbound request. X-Target-URL may
// override the request URL for the initial check only.
func (p *SSRFProxy) validateRequest(req *http.Request) []SSRFDetection {
	targetURL := req.URL
	if req.Header.Get("X-Target-URL") != "" {
		parsedURL, err := url.Parse(req.Header.Get("X-Target-URL"))
		if err == nil {
			targetURL = parsedURL
		}
	}
	return p.validateURL(req.Method, targetURL, true)
}

func (p *SSRFProxy) validateRedirect(req *http.Request) []SSRFDetection {
	return p.validateURL(req.Method, req.URL, false)
}

func (p *SSRFProxy) safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	if p.blockDNSRebinding && p.hasSuspiciousDNSPattern(host) {
		return nil, &ssrfBlockError{
			reason: fmt.Sprintf("blocked suspicious DNS rebinding host at dial time: %s", host),
			detections: []SSRFDetection{{
				Type:        "dns_rebinding",
				Description: fmt.Sprintf("Potential DNS rebinding attack detected for host: %s", host),
				URL:         host,
			}},
		}
	}

	ips, err := p.resolveHost(host)
	if err != nil {
		return nil, err
	}

	var lastErr error
	tried := 0
	for _, ip := range ips {
		if p.blockInternalIPs && p.isInternalIP(ip) {
			lastErr = &ssrfBlockError{
				reason: fmt.Sprintf("blocked internal IP at dial time: %s", ip.String()),
				detections: []SSRFDetection{{
					Type:        "internal_ip",
					Description: fmt.Sprintf("Request to internal IP address detected: %s -> %s", host, ip.String()),
					URL:         host,
					IP:          ip.String(),
				}},
			}
			continue
		}

		tried++
		dialer := &net.Dialer{Timeout: p.timeoutDuration}
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}

	if tried == 0 && lastErr != nil {
		return nil, lastErr
	}
	if lastErr == nil {
		return nil, fmt.Errorf("no usable addresses for host %s", host)
	}
	return nil, lastErr
}

func (p *SSRFProxy) writeDetections(w http.ResponseWriter, r *http.Request, detections []SSRFDetection) {
	for _, detection := range detections {
		p.logger.Warn("SSRF attempt detected",
			"type", detection.Type,
			"description", detection.Description,
			"url", detection.URL,
			"method", detection.Method,
			"ip", detection.IP,
			"client_ip", r.RemoteAddr,
			"user_agent", r.UserAgent(),
		)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":      "SSRF attempt detected",
		"detections": detections,
		"count":      len(detections),
	})
}

func (p *SSRFProxy) extractTargetURL(r *http.Request) (string, error) {
	if target := r.Header.Get("X-Target-URL"); target != "" {
		return target, nil
	}

	if target := r.URL.Query().Get("url"); target != "" {
		return target, nil
	}

	rawPath := r.URL.Path
	if r.URL.RawPath != "" {
		rawPath = r.URL.RawPath
	}

	// Prefer RequestURI so Go 1.22+ ServeMux cleaning cannot rewrite http:// in the path.
	if r.RequestURI != "" && !strings.HasPrefix(r.RequestURI, "/?") {
		reqURI := r.RequestURI
		if idx := strings.Index(reqURI, "?"); idx >= 0 {
			reqURI = reqURI[:idx]
		}
		if reqURI != "/" && reqURI != "" {
			rawPath = reqURI
		}
	}

	if rawPath == "/" || rawPath == "" {
		return "", fmt.Errorf("no target URL specified")
	}

	targetURL := strings.TrimPrefix(rawPath, "/")
	if unescaped, err := url.QueryUnescape(targetURL); err == nil {
		targetURL = unescaped
	}

	// Repair ServeMux cleaning that turns http://host into http:/host
	if strings.HasPrefix(targetURL, "http:/") && !strings.HasPrefix(targetURL, "http://") {
		targetURL = "http://" + strings.TrimPrefix(targetURL, "http:/")
	}
	if strings.HasPrefix(targetURL, "https:/") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + strings.TrimPrefix(targetURL, "https:/")
	}

	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}

	return targetURL, nil
}

func (p *SSRFProxy) newHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
		DisableKeepAlives:   true,
		MaxIdleConnsPerHost: 0,
		DialContext:         p.safeDialContext,
	}

	return &http.Client{
		Timeout:   p.timeoutDuration,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= p.maxRedirects {
				return fmt.Errorf("too many redirects")
			}

			// Never trust a forwarded target header on redirects.
			req.Header.Del("X-Target-URL")

			detections := p.validateRedirect(req)
			if len(detections) > 0 {
				return &ssrfBlockError{
					detections: detections,
					reason:     "SSRF detected in redirect",
				}
			}

			return nil
		},
	}
}

func (p *SSRFProxy) proxyHandler(w http.ResponseWriter, r *http.Request) {
	targetURL, err := p.extractTargetURL(r)
	if err != nil {
		http.Error(w, "No target URL specified. Use X-Target-URL header, ?url= query parameter, or provide URL in path.", http.StatusBadRequest)
		return
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil || parsedURL.Host == "" {
		p.logger.Error("Invalid target URL", "url", targetURL, "error", err)
		http.Error(w, "Invalid target URL", http.StatusBadRequest)
		return
	}

	detections := p.validateURL(r.Method, parsedURL, true)
	if len(detections) > 0 {
		p.writeDetections(w, r, detections)
		return
	}

	client := p.newHTTPClient()

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, parsedURL.String(), r.Body)
	if err != nil {
		p.logger.Error("Failed to create proxy request", "error", err)
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}

	for name, values := range r.Header {
		canonical := http.CanonicalHeaderKey(name)
		if canonical == "X-Target-Url" {
			continue
		}
		for _, value := range values {
			proxyReq.Header.Add(name, value)
		}
	}
	proxyReq.Header.Del("X-Target-URL")

	resp, err := client.Do(proxyReq)
	if err != nil {
		var blockErr *ssrfBlockError
		if errors.As(err, &blockErr) {
			detections := blockErr.detections
			if len(detections) == 0 {
				detections = []SSRFDetection{{
					Type:        "ssrf",
					Description: blockErr.Error(),
					URL:         targetURL,
					Method:      r.Method,
				}}
			}
			p.writeDetections(w, r, detections)
			return
		}

		// url.Error may wrap ssrfBlockError from CheckRedirect or DialContext
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			if errors.As(urlErr.Err, &blockErr) {
				detections := blockErr.detections
				if len(detections) == 0 {
					detections = []SSRFDetection{{
						Type:        "ssrf",
						Description: blockErr.Error(),
						URL:         targetURL,
						Method:      r.Method,
					}}
				}
				p.writeDetections(w, r, detections)
				return
			}
		}

		p.logger.Error("Proxy request failed", "url", targetURL, "error", err)
		http.Error(w, "Proxy request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	p.logger.Info("Proxy request completed",
		"url", targetURL,
		"method", r.Method,
		"status_code", resp.StatusCode,
		"client_ip", r.RemoteAddr,
		"user_agent", r.UserAgent(),
	)

	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}

	w.WriteHeader(resp.StatusCode)

	_, err = io.Copy(w, resp.Body)
	if err != nil {
		p.logger.Error("Failed to copy response body", "error", err)
	}
}

func (p *SSRFProxy) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status": "healthy", "service": "ssrf-proxy"}`)
}

func (p *SSRFProxy) rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" || strings.HasPrefix(r.RequestURI, "/health?") {
		p.healthHandler(w, r)
		return
	}
	p.proxyHandler(w, r)
}

func main() {
	var (
		port              = flag.String("port", "8080", "Port to listen on")
		verbose           = flag.Bool("verbose", false, "Enable verbose logging")
		allowInternalIPs  = flag.Bool("allow-internal", false, "Allow requests to internal IP addresses")
		allowDNSRebinding = flag.Bool("allow-dns-rebinding", false, "Allow potential DNS rebinding requests")
		maxRedirects      = flag.Int("max-redirects", 3, "Maximum number of redirects to follow")
		timeout           = flag.Duration("timeout", 30*time.Second, "Request timeout duration")
	)
	flag.Parse()

	proxy := NewSSRFProxy()
	proxy.verbose = *verbose
	proxy.blockInternalIPs = !*allowInternalIPs
	proxy.blockDNSRebinding = !*allowDNSRebinding
	proxy.maxRedirects = *maxRedirects
	proxy.timeoutDuration = *timeout

	if *verbose {
		proxy.logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	}

	// Use a single handler instead of ServeMux so path mode URLs like
	// /http://example.com are not rewritten by Go 1.22+ path cleaning.
	server := &http.Server{
		Addr:         ":" + *port,
		Handler:      http.HandlerFunc(proxy.rootHandler),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		proxy.logger.Info("Starting SSRF detection proxy", "port", *port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			proxy.logger.Error("Server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	proxy.logger.Info("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		proxy.logger.Error("Server forced to shutdown", "error", err)
	} else {
		proxy.logger.Info("Server gracefully stopped")
	}
}
