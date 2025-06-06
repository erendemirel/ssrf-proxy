package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type TestServer struct {
	server  *http.Server
	port    string
	baseURL string
	ctx     context.Context
	cancel  context.CancelFunc
	started chan bool
	mu      sync.Mutex
}

func NewTestServer(allowInternal, allowDNSRebinding bool) (*TestServer, error) {
	proxy := NewSSRFProxy()
	proxy.blockInternalIPs = !allowInternal
	proxy.blockDNSRebinding = !allowDNSRebinding
	proxy.verbose = false // Keep logs quiet during tests

	mux := http.NewServeMux()
	mux.HandleFunc("/health", proxy.healthHandler)
	mux.HandleFunc("/", proxy.proxyHandler)

	server := &http.Server{
		Addr:         ":0", // Use any available port
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())

	ts := &TestServer{
		server:  server,
		ctx:     ctx,
		cancel:  cancel,
		started: make(chan bool, 1),
	}

	go ts.start()

	select {
	case <-ts.started:
		return ts, nil
	case <-time.After(5 * time.Second):
		ts.cancel()
		return nil, fmt.Errorf("server failed to start within timeout")
	}
}

func (ts *TestServer) start() {
	// Note: This function is no longer used with the simplified approach

	// Start the server
	go func() {
		if err := ts.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Server failed to start
			return
		}
	}()

	time.Sleep(100 * time.Millisecond)

	addr := ts.server.Addr
	if strings.HasPrefix(addr, ":") {
		ts.port = strings.TrimPrefix(addr, ":")
		ts.baseURL = "http://localhost" + addr
	} else {
		parts := strings.Split(addr, ":")
		if len(parts) == 2 {
			ts.port = parts[1]
			ts.baseURL = "http://localhost:" + ts.port
		}
	}

	client := &http.Client{Timeout: 2 * time.Second}
	for i := 0; i < 10; i++ {
		resp, err := client.Get(ts.baseURL + "/health")
		if err == nil {
			resp.Body.Close()
			ts.started <- true
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	// If we get here, server didn't start properly
	ts.started <- false
}

func (ts *TestServer) Stop() {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ts.server.Shutdown(ctx)
		ts.cancel()
	}
}

func (ts *TestServer) URL() string {
	return ts.baseURL
}

func startTestProxy(t *testing.T, allowInternal, allowDNSRebinding bool) (string, func()) {
	proxy := NewSSRFProxy()
	proxy.blockInternalIPs = !allowInternal
	proxy.blockDNSRebinding = !allowDNSRebinding
	proxy.verbose = false

	mux := http.NewServeMux()
	mux.HandleFunc("/health", proxy.healthHandler)
	mux.HandleFunc("/", proxy.proxyHandler)

	port := 18080
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Logf("Server error: %v", err)
		}
	}()

	baseURL := fmt.Sprintf("http://localhost:%d", port)
	client := &http.Client{Timeout: 1 * time.Second}

	for i := 0; i < 30; i++ {
		resp, err := client.Get(baseURL + "/health")
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
		if i == 29 {
			t.Fatalf("Server failed to start within timeout")
		}
	}

	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
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
		{"Block localhost - strict", false, "http://127.0.0.1:8080/test", true},
		{"Block private IP - strict", false, "http://192.168.1.1/test", true},
		{"Allow localhost - permissive", true, "http://127.0.0.1:8080/test", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			baseURL, cleanup := startTestProxy(t, tc.allowInternal, false)
			defer cleanup()

			client := &http.Client{Timeout: 5 * time.Second}
			// Use X-Target-URL header instead of path to avoid URL encoding issues
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
			} else {
				if resp.StatusCode == http.StatusForbidden {
					t.Errorf("Expected request to be allowed, got 403 (blocked)")
				}
			}
		})
	}
}

func TestIntegrationUncommonMethods(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	baseURL, cleanup := startTestProxy(t, true, true) // Allow everything except methods
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
			req.Header.Set("X-Target-URL", "http://httpbin.org/get")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if tc.expectBlocked {
				if resp.StatusCode != http.StatusForbidden {
					t.Errorf("Method %s should be blocked (403), got %d", tc.method, resp.StatusCode)
				}
			} else {
				if resp.StatusCode == http.StatusForbidden {
					body, _ := io.ReadAll(resp.Body)
					t.Errorf("Method %s should be allowed, got 403. Body: %s", tc.method, string(body))
				}
			}
		})
	}
}

func TestIntegrationCustomHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	baseURL, cleanup := startTestProxy(t, false, false) // Strict mode
	defer cleanup()

	testCases := []struct {
		name          string
		targetURL     string
		expectBlocked bool
	}{
		{"External URL via header", "http://httpbin.org/get", false},
		{"Internal IP via header", "http://127.0.0.1:8080/test", true},
		{"Private IP via header", "http://192.168.1.1/test", true},
	}

	client := &http.Client{Timeout: 5 * time.Second}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
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
			} else {
				if resp.StatusCode == http.StatusForbidden {
					body, _ := io.ReadAll(resp.Body)
					t.Errorf("Expected allowed, got 403. Body: %s", string(body))
				}
			}
		})
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
		{"DNS rebinding - strict", false, "http://127.0.0.1.evil.example/test", true},
		{"DNS rebinding - permissive", true, "http://127.0.0.1.evil.example/test", false},
		{"Localhost subdomain - strict", false, "http://localhost.evil.example/test", true},
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
			} else {
				if resp.StatusCode == http.StatusForbidden {
					body, _ := io.ReadAll(resp.Body)
					t.Errorf("Expected allowed, got 403. Body: %s", string(body))
				}
			}
		})
	}
}

func TestIntegrationExternalService(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	baseURL, cleanup := startTestProxy(t, false, false)
	defer cleanup()

	// Test with httpbin.org if available
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", baseURL+"/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Target-URL", "http://httpbin.org/status/200")
	resp, err := client.Do(req)
	if err != nil {
		t.Skipf("Skipping external service test due to connectivity: %v", err)
		return
	}
	defer resp.Body.Close()

	// Should not be blocked
	if resp.StatusCode == http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("External service was blocked: %s", string(body))
	}

	t.Logf("External service test completed with status: %d", resp.StatusCode)
}

// Benchmark integration test
func BenchmarkIntegrationProxy(b *testing.B) {
	server, err := NewTestServer(false, false)
	if err != nil {
		b.Fatalf("Failed to start test server: %v", err)
	}
	defer server.Stop()

	client := &http.Client{Timeout: 5 * time.Second}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Test blocking internal IP (should be fast)
			resp, err := client.Get(server.URL() + "/http://127.0.0.1:8080/test")
			if err != nil {
				b.Error(err)
				continue
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusForbidden {
				b.Errorf("Expected 403, got %d", resp.StatusCode)
			}
		}
	})
}
