package main

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
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
		// Private IPv4 ranges
		{"10.0.0.1", true, "Private 10.x.x.x"},
		{"172.16.0.1", true, "Private 172.16.x.x"},
		{"192.168.1.1", true, "Private 192.168.x.x"},
		{"192.168.0.1", true, "Private 192.168.0.x"},

		// Loopback
		{"127.0.0.1", true, "Loopback IPv4"},
		{"::1", true, "Loopback IPv6"},

		// Link-local
		{"169.254.1.1", true, "Link-local IPv4"},
		{"fe80::1", true, "Link-local IPv6"},

		// Public IPs (should not be internal)
		{"8.8.8.8", false, "Google DNS"},
		{"1.1.1.1", false, "Cloudflare DNS"},
		{"93.184.216.34", false, "Example.com IP"},
		{"2606:2800:220:1:248:1893:25c8:1946", false, "Example.com IPv6"},

		// Edge cases
		{"0.0.0.0", false, "Zero IP"},
		{"255.255.255.255", false, "Broadcast IP"},

		// IPv6 unique local
		{"fc00::1", true, "IPv6 unique local"},
		{"fd00::1", true, "IPv6 unique local"},
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

func TestDetectDNSRebinding(t *testing.T) {
	proxy := NewSSRFProxy()

	testCases := []struct {
		host     string
		expected bool
		name     string
	}{
		// Suspicious patterns
		{"192.168.1.1.evil.com", true, "IP followed by domain"},
		{"localhost.evil.com", true, "localhost subdomain"},
		{"127.0.0.1.attacker.com", true, "127.0.0.1 subdomain"},
		{"evil.com.127.0.0.1", true, "domain ending with 127.0.0.1"},
		{"test.localhost", true, "domain ending with localhost"},
		{"10.0.0.1.example.com", true, "private IP in domain"},

		// Safe domains
		{"example.com", false, "Normal domain"},
		{"google.com", false, "Normal domain"},
		{"sub.example.com", false, "Normal subdomain"},
		{"api.service.com", false, "Normal API domain"},
		{"localhost123.com", false, "Domain containing localhost but not as subdomain"},

		// Edge cases
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
			name:          "Multiple issues - uncommon method + internal IP",
			method:        "CONNECT",
			url:           "http://127.0.0.1/path",
			expectedTypes: []string{"uncommon_method", "internal_ip"},
			shouldDetect:  true,
		},
		{
			name:         "Valid POST request",
			method:       "POST",
			url:          "http://httpbin.org/post",
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create request
			reqURL, err := url.Parse(tc.url)
			if err != nil {
				t.Fatalf("Failed to parse URL: %v", err)
			}

			req := &http.Request{
				Method: tc.method,
				URL:    reqURL,
				Header: make(http.Header),
			}

			// Add headers
			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}

			// Test validation
			detections := proxy.validateRequest(req)

			if tc.shouldDetect {
				if len(detections) == 0 {
					t.Errorf("Expected detections but got none")
					return
				}

				// Check if all expected types are present
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

	// Request to internal IP should not be detected when disabled
	reqURL, _ := url.Parse("http://127.0.0.1/path")
	req := &http.Request{
		Method: "GET",
		URL:    reqURL,
		Header: make(http.Header),
	}

	detections := proxy.validateRequest(req)

	// Should only detect uncommon methods, not internal IPs or DNS rebinding
	for _, detection := range detections {
		if detection.Type == "internal_ip" || detection.Type == "dns_rebinding" {
			t.Errorf("Detection type '%s' should be disabled", detection.Type)
		}
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

		detections := proxy.validateRequest(req)
		// Should not panic and may or may not detect based on implementation
		_ = detections
	})

	t.Run("Malformed host", func(t *testing.T) {
		reqURL, _ := url.Parse("http://[invalid-ipv6]/path")
		req := &http.Request{
			Method: "GET",
			URL:    reqURL,
			Header: make(http.Header),
		}

		detections := proxy.validateRequest(req)
		// Should not panic
		_ = detections
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

			// Check that uncommon_method detection is present
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
