package main

import (
	"context"
	"crypto/tls"
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

func (p *SSRFProxy) isInternalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	if ip.IsLoopback() {
		return true
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

func (p *SSRFProxy) detectDNSRebinding(host string) bool {
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

	ips, err := net.LookupIP(host)
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

func (p *SSRFProxy) validateRequest(req *http.Request) []SSRFDetection {
	var detections []SSRFDetection

	if !p.allowedMethods[req.Method] {
		detections = append(detections, SSRFDetection{
			Type:        "uncommon_method",
			Description: fmt.Sprintf("Uncommon HTTP method detected: %s", req.Method),
			URL:         req.URL.String(),
			Method:      req.Method,
		})
	}

	targetURL := req.URL
	if req.Header.Get("X-Target-URL") != "" {
		parsedURL, err := url.Parse(req.Header.Get("X-Target-URL"))
		if err == nil {
			targetURL = parsedURL
		}
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
			Method:      req.Method,
		})
	}

	ips, err := net.LookupIP(host)
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
				Method:      req.Method,
				IP:          ip.String(),
			})
		}
	}

	return detections
}

func (p *SSRFProxy) proxyHandler(w http.ResponseWriter, r *http.Request) {
	var targetURL string
	if r.Header.Get("X-Target-URL") != "" {
		targetURL = r.Header.Get("X-Target-URL")
	} else if r.URL.Path != "/" {
		targetURL = strings.TrimPrefix(r.URL.Path, "/")
		if unescaped, err := url.QueryUnescape(targetURL); err == nil {
			targetURL = unescaped
		}

		if !strings.HasPrefix(targetURL, "http") {
			targetURL = "http://" + targetURL
		}
	} else {
		http.Error(w, "No target URL specified. Use X-Target-URL header or provide URL in path.", http.StatusBadRequest)
		return
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		p.logger.Error("Invalid target URL", "url", targetURL, "error", err)
		http.Error(w, "Invalid target URL", http.StatusBadRequest)
		return
	}

	testReq := &http.Request{
		Method: r.Method,
		URL:    parsedURL,
		Header: r.Header,
	}

	detections := p.validateRequest(testReq)

	if len(detections) > 0 {
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
		fmt.Fprintf(w, `{"error": "SSRF attempt detected", "detections": %d}`, len(detections))
		return
	}

	client := &http.Client{
		Timeout: p.timeoutDuration,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= p.maxRedirects {
				return fmt.Errorf("too many redirects")
			}

			detections := p.validateRequest(req)
			if len(detections) > 0 {
				return fmt.Errorf("SSRF detected in redirect")
			}

			return nil
		},
	}

	proxyReq, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		p.logger.Error("Failed to create proxy request", "error", err)
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}

	for name, values := range r.Header {
		if name == "X-Target-URL" {
			continue
		}
		for _, value := range values {
			proxyReq.Header.Add(name, value)
		}
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
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

	mux := http.NewServeMux()
	mux.HandleFunc("/health", proxy.healthHandler)
	mux.HandleFunc("/", proxy.proxyHandler)

	server := &http.Server{
		Addr:         ":" + *port,
		Handler:      mux,
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
