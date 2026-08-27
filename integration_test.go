package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func startTestProxy(t *testing.T, allowInternal, allowDNSRebinding bool) (string, func()) {
	t.Helper()

	proxy := NewSSRFProxy()
	proxy.blockInternalIPs = !allowInternal
	proxy.blockDNSRebinding = !allowDNSRebinding
	proxy.verbose = false
	proxy.timeoutDuration = 5 * time.Second

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := &http.Server{
		Handler:      http.HandlerFunc(proxy.rootHandler),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	go func() {
		_ = server.Serve(ln)
	}()

	baseURL := "http://" + ln.Addr().String()
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get(baseURL + "/health")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			server.Close()
			t.Fatalf("Server failed to start within timeout: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}

	return baseURL, cleanup
}

func TestIntegrationHealthCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	baseURL, cleanup := startTestProxy(t, false, false)
	defer cleanup()

	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if !strings.Contains(string(body), "healthy") {
		t.Errorf("Expected health response to contain 'healthy', got: %s", string(body))
	}
}

func TestIntegrationBlockInternalIPs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testCases := []struct {
		name          string
		allowInternal bool
		targetURL     string
		expectBlocked bool
	}{
		{"Block localhost strict", false, "http://127.0.0.1:9/test", true},
		{"Block private IP strict", false, "http://192.168.1.1/test", true},
		{"Allow localhost permissive", true, "http://127.0.0.1:9/test", false},
		{"Block decimal loopback", false, "http://2130706433/", true},
		{"Block unspecified", false, "http://0.0.0.0/", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			baseURL, cleanup := startTestProxy(t, tc.allowInternal, false)
			defer cleanup()

			client := &http.Client{Timeout: 5 * time.Second}
			req, err := http.NewRequest("GET", baseURL+"/", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("X-Target-URL", tc.targetURL)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if tc.expectBlocked {
				if resp.StatusCode != http.StatusForbidden {
					body, _ := io.ReadAll(resp.Body)
					t.Errorf("Expected status 403 (blocked), got %d. Body: %s", resp.StatusCode, string(body))
				}
			} else if resp.StatusCode == http.StatusForbidden {
				t.Errorf("Expected request to be allowed, got 403 (blocked)")
			}
		})
	}
}

func TestIntegrationUncommonMethods(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	baseURL, cleanup := startTestProxy(t, true, true)
	defer cleanup()

	testCases := []struct {
		method        string
		expectBlocked bool
	}{
		{"GET", false},
		{"DELETE", false},
		{"HEAD", false},
		{"TRACE", true},
		{"CONNECT", true},
		{"OPTIONS", true},
	}

	client := &http.Client{Timeout: 5 * time.Second}

	for _, tc := range testCases {
		t.Run(tc.method, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, baseURL+"/", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("X-Target-URL", upstream.URL)

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if tc.expectBlocked {
				if resp.StatusCode != http.StatusForbidden {
					t.Errorf("Method %s should be blocked (403), got %d", tc.method, resp.StatusCode)
				}
			} else if resp.StatusCode == http.StatusForbidden {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("Method %s should be allowed, got 403. Body: %s", tc.method, string(body))
			}
		})
	}
}

func TestIntegrationCustomHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	baseURL, cleanup := startTestProxy(t, true, true)
	defer cleanup()

	// External via header should work when internals are allowed for httptest hosts.
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", baseURL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Target-URL", upstream.URL)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("expected allowed upstream, got 403")
	}

	strictURL, strictCleanup := startTestProxy(t, false, false)
	defer strictCleanup()

	for _, target := range []string{"http://127.0.0.1:9/test", "http://192.168.1.1/test"} {
		req, err := http.NewRequest("GET", strictURL+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Target-URL", target)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 for %s, got %d body=%s", target, resp.StatusCode, body)
		}
	}
}

func TestIntegrationDNSRebinding(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testCases := []struct {
		name              string
		allowDNSRebinding bool
		targetURL         string
		expectBlocked     bool
	}{
		{"DNS rebinding strict", false, "http://127.0.0.1.evil.example/test", true},
		{"DNS rebinding permissive", true, "http://127.0.0.1.evil.example/test", false},
		{"Localhost subdomain strict", false, "http://localhost.evil.example/test", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			baseURL, cleanup := startTestProxy(t, true, tc.allowDNSRebinding)
			defer cleanup()

			client := &http.Client{Timeout: 5 * time.Second}
			req, err := http.NewRequest("GET", baseURL+"/", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("X-Target-URL", tc.targetURL)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if tc.expectBlocked {
				if resp.StatusCode != http.StatusForbidden {
					body, _ := io.ReadAll(resp.Body)
					t.Errorf("Expected 403 (blocked), got %d. Body: %s", resp.StatusCode, string(body))
				}
			} else if resp.StatusCode == http.StatusForbidden {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("Expected allowed, got 403. Body: %s", string(body))
			}
		})
	}
}

func TestIntegrationPathMode(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	baseURL, cleanup := startTestProxy(t, false, false)
	defer cleanup()

	resp, err := http.Get(baseURL + "/http://127.0.0.1/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("path mode should block internal target, got %d body=%s", resp.StatusCode, body)
	}
}

func TestIntegrationRedirectChain(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	internalHit := false
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		internalHit = true
		fmt.Fprint(w, "PWNED")
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

	resp, err := client.Get(external.URL)
	if resp != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if internalHit {
		t.Fatal("redirect to internal server was followed")
	}
	if err == nil {
		t.Fatal("expected SSRF block error on redirect")
	}
}

func TestIntegrationExternalService(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	baseURL, cleanup := startTestProxy(t, true, true)
	defer cleanup()

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", baseURL+"/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Target-URL", upstream.URL)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("External service was blocked: %s", string(body))
	}
}
