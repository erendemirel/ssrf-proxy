package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNewSSRFProxy(t *testing.T) {
	proxy := NewSSRFProxy()

	if proxy == nil {
		t.Fatal("NewSSRFProxy() returned nil")
	}

	if proxy.logger == nil {
		t.Error("Logger not initialized")
	}

	if !proxy.blockInternalIPs {
		t.Error("blockInternalIPs should be true by default")
	}

	if !proxy.blockDNSRebinding {
		t.Error("blockDNSRebinding should be true by default")
	}

	expectedMethods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"}
	for _, method := range expectedMethods {
		if !proxy.allowedMethods[method] {
			t.Errorf("Method %s should be allowed by default", method)
		}
	}
}

func TestIsInternalIP(t *testing.T) {
	proxy := NewSSRFProxy()

	testCases := []struct {
		ip       string
		expected bool
		name     string
	}{
		{"10.0.0.1", true, "Private 10.x.x.x"},
		{"172.16.0.1", true, "Private 172.16.x.x"},
		{"192.168.1.1", true, "Private 192.168.x.x"},
		{"192.168.0.1", true, "Private 192.168.0.x"},
		{"127.0.0.1", true, "Loopback IPv4"},
		{"::1", true, "Loopback IPv6"},
		{"169.254.1.1", true, "Link local IPv4"},
		{"fe80::1", true, "Link local IPv6"},
		{"8.8.8.8", false, "Google DNS"},
		{"1.1.1.1", false, "Cloudflare DNS"},
		{"93.184.216.34", false, "Example.com IP"},
		{"2606:2800:220:1:248:1893:25c8:1946", false, "Example.com IPv6"},
		{"0.0.0.0", true, "Unspecified IPv4"},
		{"::", true, "Unspecified IPv6"},
		{"255.255.255.255", true, "Broadcast IP"},
		{"fc00::1", true, "IPv6 unique local"},
		{"fd00::1", true, "IPv6 unique local fd"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tc.ip)
			}

			result := proxy.isInternalIP(ip)
			if result != tc.expected {
				t.Errorf("isInternalIP(%s) = %v, expected %v", tc.ip, result, tc.expected)
			}
		})
	}
}

func TestParseHostIP(t *testing.T) {
	testCases := []struct {
		host     string
		expected string
	}{
		{"127.0.0.1", "127.0.0.1"},
		{"2130706433", "127.0.0.1"},
		{"0", "0.0.0.0"},
		{"8.8.8.8", "8.8.8.8"},
		{"not-an-ip", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.host, func(t *testing.T) {
			ip := parseHostIP(tc.host)
			if tc.expected == "" {
				if ip != nil {
					t.Fatalf("expected nil, got %s", ip)
				}
				return
			}
			if ip == nil || ip.String() != tc.expected {
				t.Fatalf("parseHostIP(%s) = %v, expected %s", tc.host, ip, tc.expected)
			}
		})
	}
}

func TestDetectDNSRebinding(t *testing.T) {
	proxy := NewSSRFProxy()

	testCases := []struct {
		host     string
		expected bool
		name     string
	}{
		{"192.168.1.1.evil.com", true, "IP followed by domain"},
		{"localhost.evil.com", true, "localhost subdomain"},
		{"127.0.0.1.attacker.com", true, "127.0.0.1 subdomain"},
		{"evil.com.127.0.0.1", true, "domain ending with 127.0.0.1"},
		{"test.localhost", true, "domain ending with localhost"},
		{"10.0.0.1.example.com", true, "private IP in domain"},
		{"example.com", false, "Normal domain"},
		{"google.com", false, "Normal domain google"},
		{"sub.example.com", false, "Normal subdomain"},
		{"api.service.com", false, "Normal API domain"},
		{"localhost123.com", false, "Domain containing localhost but not as subdomain"},
		{"", false, "Empty host"},
		{"localhost", false, "Just localhost (handled by IP check)"},
		{"127.0.0.1", false, "Just IP (handled by IP check)"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := proxy.detectDNSRebinding(tc.host)
			if result != tc.expected {
				t.Errorf("detectDNSRebinding(%s) = %v, expected %v", tc.host, result, tc.expected)
			}
		})
	}
}

func TestValidateRequest(t *testing.T) {
	proxy := NewSSRFProxy()

	testCases := []struct {
		name          string
		method        string
		url           string
		headers       map[string]string
		expectedTypes []string
		shouldDetect  bool
	}{
		{
			name:         "Valid GET request",
			method:       "GET",
			url:          "http://example.com/path",
			shouldDetect: false,
		},
		{
			name:          "Uncommon HTTP method",
			method:        "TRACE",
			url:           "http://example.com/path",
			expectedTypes: []string{"uncommon_method"},
			shouldDetect:  true,
		},
		{
			name:          "Request to localhost",
			method:        "GET",
			url:           "http://localhost/path",
			expectedTypes: []string{"internal_ip"},
			shouldDetect:  true,
		},
		{
			name:          "Request to private IP",
			method:        "GET",
			url:           "http://192.168.1.1/path",
			expectedTypes: []string{"internal_ip"},
			shouldDetect:  true,
		},
		{
			name:          "DNS rebinding pattern",
			method:        "GET",
			url:           "http://127.0.0.1.evil.com/path",
			expectedTypes: []string{"dns_rebinding"},
			shouldDetect:  true,
		},
		{
			name:          "Multiple issues uncommon method and internal IP",
			method:        "CONNECT",
			url:           "http://127.0.0.1/path",
			expectedTypes: []string{"uncommon_method", "internal_ip"},
			shouldDetect:  true,
		},
		{
			name:         "Valid POST request",
			method:       "POST",
			url:          "http://example.com/post",
			shouldDetect: false,
		},
		{
			name:         "Valid request with X-Target-URL header",
			method:       "GET",
			url:          "http://proxy.local/",
			headers:      map[string]string{"X-Target-URL": "http://example.com/api"},
			shouldDetect: false,
		},
		{
			name:          "X-Target-URL header with internal IP",
			method:        "GET",
			url:           "http://proxy.local/",
			headers:       map[string]string{"X-Target-URL": "http://127.0.0.1:8080"},
			expectedTypes: []string{"internal_ip"},
			shouldDetect:  true,
		},
		{
			name:          "Decimal IP form of loopback",
			method:        "GET",
			url:           "http://2130706433/",
			expectedTypes: []string{"internal_ip"},
			shouldDetect:  true,
		},
		{
			name:          "Unspecified 0.0.0.0",
			method:        "GET",
			url:           "http://0.0.0.0/",
			expectedTypes: []string{"internal_ip"},
			shouldDetect:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqURL, err := url.Parse(tc.url)
			if err != nil {
				t.Fatalf("Failed to parse URL: %v", err)
			}

			req := &http.Request{
				Method: tc.method,
				URL:    reqURL,
				Header: make(http.Header),
			}

			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}

			detections := proxy.validateRequest(req)

			if tc.shouldDetect {
				if len(detections) == 0 {
					t.Errorf("Expected detections but got none")
					return
				}

				detectedTypes := make(map[string]bool)
				for _, detection := range detections {
					detectedTypes[detection.Type] = true
				}

				for _, expectedType := range tc.expectedTypes {
					if !detectedTypes[expectedType] {
						t.Errorf("Expected detection type '%s' not found. Got: %v", expectedType, detectedTypes)
					}
				}
			} else {
				if len(detections) > 0 {
					var types []string
					for _, d := range detections {
						types = append(types, d.Type)
					}
					t.Errorf("Expected no detections but got: %v", types)
				}
			}
		})
	}
}

func TestValidateRequestWithDisabledChecks(t *testing.T) {
	proxy := NewSSRFProxy()
	proxy.blockInternalIPs = false
	proxy.blockDNSRebinding = false

	reqURL, _ := url.Parse("http://127.0.0.1/path")
	req := &http.Request{
		Method: "GET",
		URL:    reqURL,
		Header: make(http.Header),
	}

	detections := proxy.validateRequest(req)

	for _, detection := range detections {
		if detection.Type == "internal_ip" || detection.Type == "dns_rebinding" {
			t.Errorf("Detection type '%s' should be disabled", detection.Type)
		}
	}
}

func TestValidateRedirectIgnoresTargetHeader(t *testing.T) {
	proxy := NewSSRFProxy()

	reqURL, _ := url.Parse("http://127.0.0.1/secret")
	req := &http.Request{
		Method: "GET",
		URL:    reqURL,
		Header: make(http.Header),
	}
	// Poisoned header pointing at an external host must not hide the redirect target.
	req.Header.Set("X-Target-URL", "http://example.com/")

	detections := proxy.validateRedirect(req)
	if len(detections) == 0 {
		t.Fatal("expected internal_ip detection for redirect target")
	}

	found := false
	for _, d := range detections {
		if d.Type == "internal_ip" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected internal_ip, got %#v", detections)
	}
}

func TestEdgeCases(t *testing.T) {
	proxy := NewSSRFProxy()

	t.Run("Empty URL", func(t *testing.T) {
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{},
			Header: make(http.Header),
		}
		_ = proxy.validateRequest(req)
	})

	t.Run("Malformed host", func(t *testing.T) {
		reqURL, _ := url.Parse("http://[invalid-ipv6]/path")
		req := &http.Request{
			Method: "GET",
			URL:    reqURL,
			Header: make(http.Header),
		}
		_ = proxy.validateRequest(req)
	})

	t.Run("Port in URL", func(t *testing.T) {
		reqURL, _ := url.Parse("http://example.com:8080/path")
		req := &http.Request{
			Method: "GET",
			URL:    reqURL,
			Header: make(http.Header),
		}

		detections := proxy.validateRequest(req)
		if len(detections) > 0 {
			t.Errorf("Valid external URL with port should not be detected")
		}
	})
}

func TestAllowedMethods(t *testing.T) {
	proxy := NewSSRFProxy()

	allowedMethods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"}
	blockedMethods := []string{"TRACE", "CONNECT", "OPTIONS", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}

	reqURL, _ := url.Parse("http://example.com/test")

	for _, method := range allowedMethods {
		t.Run("Allowed_"+method, func(t *testing.T) {
			req := &http.Request{
				Method: method,
				URL:    reqURL,
				Header: make(http.Header),
			}

			detections := proxy.validateRequest(req)
			for _, detection := range detections {
				if detection.Type == "uncommon_method" {
					t.Errorf("Method %s should be allowed but was detected as uncommon", method)
				}
			}
		})
	}

	for _, method := range blockedMethods {
		t.Run("Blocked_"+method, func(t *testing.T) {
			req := &http.Request{
				Method: method,
				URL:    reqURL,
				Header: make(http.Header),
			}

			detections := proxy.validateRequest(req)
			found := false
			for _, detection := range detections {
				if detection.Type == "uncommon_method" && strings.Contains(detection.Description, method) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Method %s should be detected as uncommon but wasn't", method)
			}
		})
	}
}

func TestForbiddenResponseIncludesDetections(t *testing.T) {
	proxy := NewSSRFProxy()
	server := httptest.NewServer(http.HandlerFunc(proxy.rootHandler))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Target-URL", "http://127.0.0.1/")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}

	var body struct {
		Error      string          `json:"error"`
		Count      int             `json:"count"`
		Detections []SSRFDetection `json:"detections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Count < 1 || len(body.Detections) < 1 {
		t.Fatalf("expected detection details, got %#v", body)
	}
	if body.Detections[0].Type == "" {
		t.Fatal("expected detection type in response")
	}
}

func TestPathModeAndQueryParam(t *testing.T) {
	proxy := NewSSRFProxy()
	server := httptest.NewServer(http.HandlerFunc(proxy.rootHandler))
	defer server.Close()

	t.Run("path mode blocks internal", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/http://127.0.0.1/")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 403, got %d body=%s", resp.StatusCode, body)
		}
	})

	t.Run("query param blocks internal", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/?url=" + url.QueryEscape("http://192.168.1.1/"))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 403, got %d body=%s", resp.StatusCode, body)
		}
	})
}

func TestRedirectToInternalIsBlocked(t *testing.T) {
	internalHit := false
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		internalHit = true
		io.WriteString(w, "INTERNAL_REACHED")
	}))
	defer internal.Close()

	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL, http.StatusFound)
	}))
	defer external.Close()

	proxy := NewSSRFProxy()
	firstHop := external.Listener.Addr().String()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Allow the first hop test server; enforce SSRF checks afterward.
				if addr == firstHop {
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				}
				return proxy.safeDialContext(ctx, network, addr)
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			req.Header.Del("X-Target-URL")
			detections := proxy.validateRedirect(req)
			if len(detections) > 0 {
				return &ssrfBlockError{detections: detections, reason: "SSRF detected in redirect"}
			}
			return nil
		},
	}

	proxyReq, err := http.NewRequest("GET", external.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	proxyReq.Header.Set("X-Target-URL", external.URL)
	proxyReq.Header.Del("X-Target-URL")

	resp, err := client.Do(proxyReq)
	if resp != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	if internalHit {
		t.Fatal("internal server was reached via redirect")
	}
	if err == nil {
		t.Fatal("expected SSRF error from redirect validation")
	}
	if !strings.Contains(err.Error(), "SSRF") && !strings.Contains(err.Error(), "blocked internal") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHeaderStrippingOnOutbound(t *testing.T) {
	sawHeader := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Target-URL") != "" {
			sawHeader = true
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	proxy := NewSSRFProxy()
	proxy.blockInternalIPs = false
	proxy.blockDNSRebinding = false
	server := httptest.NewServer(http.HandlerFunc(proxy.rootHandler))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Target-URL", upstream.URL)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if sawHeader {
		t.Fatal("X-Target-URL was forwarded to upstream")
	}
}

func BenchmarkIsInternalIP(b *testing.B) {
	proxy := NewSSRFProxy()
	ip := net.ParseIP("192.168.1.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proxy.isInternalIP(ip)
	}
}

func BenchmarkDetectDNSRebinding(b *testing.B) {
	proxy := NewSSRFProxy()
	host := "192.168.1.1.evil.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proxy.detectDNSRebinding(host)
	}
}

func BenchmarkValidateRequest(b *testing.B) {
	proxy := NewSSRFProxy()
	reqURL, _ := url.Parse("http://127.0.0.1/test")
	req := &http.Request{
		Method: "GET",
		URL:    reqURL,
		Header: make(http.Header),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proxy.validateRequest(req)
	}
}
