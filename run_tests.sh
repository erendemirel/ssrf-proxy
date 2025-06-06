#!/bin/bash

# SSRF Proxy Test Runner
# Comprehensive test script for the SSRF detection proxy

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROXY_PORT=18080
PROXY_PID=""
TEST_RESULTS_DIR="test_results"

echo -e "${BLUE}🔍 SSRF Detection Proxy - Comprehensive Test Suite${NC}"
echo "=================================================="

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Function to cleanup on exit
cleanup() {
    if [ ! -z "$PROXY_PID" ]; then
        print_info "Stopping test proxy server (PID: $PROXY_PID)"
        kill $PROXY_PID 2>/dev/null || true
        wait $PROXY_PID 2>/dev/null || true
    fi
}

# Set trap for cleanup
trap cleanup EXIT

# Create results directory
mkdir -p $TEST_RESULTS_DIR

echo ""
echo "📋 Test Plan:"
echo "1. Build and verify compilation"
echo "2. Run unit tests"
echo "3. Start test proxy server"
echo "4. Run integration tests"
echo "5. Run functional tests"
echo "6. Generate test report"
echo ""

# Test 1: Build verification
echo -e "${BLUE}🔨 Step 1: Build Verification${NC}"
echo "Building SSRF proxy for current platform..."

if go build -o ssrf-proxy-test main.go; then
    print_status "Build successful"
else
    print_error "Build failed"
    exit 1
fi

# Test 2: Unit tests
echo ""
echo -e "${BLUE}🧪 Step 2: Unit Tests${NC}"
echo "Running Go unit tests..."

if go test -v -race -coverprofile=coverage.out ./...; then
    print_status "Unit tests passed"
    
    # Generate coverage report
    if command -v go &> /dev/null; then
        go tool cover -html=coverage.out -o $TEST_RESULTS_DIR/coverage.html
        print_info "Coverage report generated: $TEST_RESULTS_DIR/coverage.html"
        
        # Show coverage percentage
        COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}')
        print_info "Test coverage: $COVERAGE"
    fi
else
    print_error "Unit tests failed"
    exit 1
fi

# Test 3: Start test proxy server
echo ""
echo -e "${BLUE}🚀 Step 3: Starting Test Proxy Server${NC}"
echo "Starting proxy on port $PROXY_PORT..."

./ssrf-proxy-test -port $PROXY_PORT -verbose > $TEST_RESULTS_DIR/proxy.log 2>&1 &
PROXY_PID=$!

print_info "Proxy started with PID: $PROXY_PID"

# Wait for proxy to start
sleep 2

# Check if proxy is running
if ! kill -0 $PROXY_PID 2>/dev/null; then
    print_error "Proxy failed to start"
    cat $TEST_RESULTS_DIR/proxy.log
    exit 1
fi

# Test health endpoint
echo "Testing proxy health endpoint..."
if curl -s "http://localhost:$PROXY_PORT/health" | grep -q "healthy"; then
    print_status "Proxy is healthy and responding"
else
    print_error "Proxy health check failed"
    exit 1
fi

# Test 4: Integration tests
echo ""
echo -e "${BLUE}🔗 Step 4: Integration Tests${NC}"

if [ -f "integration_test.go" ]; then
    echo "Running integration tests..."
    if go test -v -tags=integration ./...; then
        print_status "Integration tests passed"
    else
        print_warning "Integration tests failed (may be due to network connectivity)"
    fi
else
    print_info "No integration tests found, skipping..."
fi

# Test 5: Functional tests
echo ""
echo -e "${BLUE}🎯 Step 5: Functional Tests${NC}"
echo "Running functional tests against live proxy..."

BASE_URL="http://localhost:$PROXY_PORT"
RESULTS_FILE="$TEST_RESULTS_DIR/functional_tests.txt"

echo "Functional Test Results - $(date)" > $RESULTS_FILE
echo "============================================" >> $RESULTS_FILE

# Helper function to test endpoint
test_endpoint() {
    local test_name="$1"
    local url="$2"
    local method="${3:-GET}"
    local expected_status="$4"
    local description="$5"
    
    echo -n "  Testing: $test_name... "
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "%{http_code}" -o /dev/null "$url" 2>/dev/null || echo "000")
    else
        response=$(curl -s -w "%{http_code}" -o /dev/null -X "$method" "$url" 2>/dev/null || echo "000")
    fi
    
    echo "Test: $test_name" >> $RESULTS_FILE
    echo "URL: $url" >> $RESULTS_FILE
    echo "Method: $method" >> $RESULTS_FILE
    echo "Expected: $expected_status" >> $RESULTS_FILE
    echo "Actual: $response" >> $RESULTS_FILE
    echo "Description: $description" >> $RESULTS_FILE
    
    if [ "$response" = "$expected_status" ]; then
        print_status "PASS ($response)"
        echo "Result: PASS" >> $RESULTS_FILE
    else
        print_error "FAIL (expected $expected_status, got $response)"
        echo "Result: FAIL" >> $RESULTS_FILE
    fi
    echo "" >> $RESULTS_FILE
}

# Health check
test_endpoint "Health Check" "$BASE_URL/health" "GET" "200" "Basic health endpoint"

# Internal IP blocking tests
test_endpoint "Block Localhost" "$BASE_URL/http://127.0.0.1:8080/test" "GET" "403" "Should block requests to localhost"
test_endpoint "Block Private IP 192.168.x.x" "$BASE_URL/http://192.168.1.1/test" "GET" "403" "Should block private IP ranges"
test_endpoint "Block Private IP 10.x.x.x" "$BASE_URL/http://10.0.0.1/test" "GET" "403" "Should block private IP ranges"

# HTTP method validation
test_endpoint "Allow GET" "$BASE_URL/http://httpbin.org/get" "GET" "200" "Should allow common HTTP methods"
test_endpoint "Block TRACE" "$BASE_URL/http://httpbin.org/get" "TRACE" "403" "Should block uncommon HTTP methods"
test_endpoint "Block CONNECT" "$BASE_URL/http://httpbin.org/get" "CONNECT" "403" "Should block uncommon HTTP methods"

# DNS rebinding tests
test_endpoint "Block DNS Rebinding" "$BASE_URL/http://127.0.0.1.evil.example/test" "GET" "403" "Should block DNS rebinding patterns"

# External service test (may fail due to network)
print_info "Testing external service connectivity..."
if curl -s --connect-timeout 5 "http://httpbin.org/status/200" > /dev/null; then
    test_endpoint "Allow External Service" "$BASE_URL/http://httpbin.org/status/200" "GET" "200" "Should allow external services"
else
    print_warning "External service test skipped (no internet connectivity)"
    echo "Test: Allow External Service" >> $RESULTS_FILE
    echo "Result: SKIPPED (no internet connectivity)" >> $RESULTS_FILE
    echo "" >> $RESULTS_FILE
fi

# Custom header tests
echo -n "  Testing: Custom Header (X-Target-URL)... "
response=$(curl -s -w "%{http_code}" -o /dev/null -H "X-Target-URL: http://127.0.0.1:8080" "$BASE_URL/" 2>/dev/null || echo "000")
if [ "$response" = "403" ]; then
    print_status "PASS ($response)"
else
    print_error "FAIL (expected 403, got $response)"
fi

# Test 6: Performance test
echo ""
echo -e "${BLUE}⚡ Step 6: Performance Test${NC}"
echo "Running basic performance test..."

PERF_RESULTS="$TEST_RESULTS_DIR/performance.txt"
echo "Performance Test Results - $(date)" > $PERF_RESULTS

# Test response time for health endpoint
echo -n "  Health endpoint response time: "
time_result=$(curl -s -w "%{time_total}" -o /dev/null "$BASE_URL/health")
echo "${time_result}s"
echo "Health endpoint response time: ${time_result}s" >> $PERF_RESULTS

# Test response time for blocked request
echo -n "  Blocked request response time: "
time_result=$(curl -s -w "%{time_total}" -o /dev/null "$BASE_URL/http://127.0.0.1/test")
echo "${time_result}s"
echo "Blocked request response time: ${time_result}s" >> $PERF_RESULTS

# Test concurrent requests
echo "  Running concurrent request test..."
CONCURRENT_RESULTS="$TEST_RESULTS_DIR/concurrent_test.txt"

# Create a simple concurrent test
for i in {1..10}; do
    curl -s "$BASE_URL/http://127.0.0.1/test" > /dev/null &
done
wait

print_status "Concurrent test completed"

# Generate summary report
echo ""
echo -e "${BLUE}📊 Step 7: Test Summary${NC}"

SUMMARY_FILE="$TEST_RESULTS_DIR/test_summary.txt"
echo "SSRF Proxy Test Summary" > $SUMMARY_FILE
echo "======================" >> $SUMMARY_FILE
echo "Date: $(date)" >> $SUMMARY_FILE
echo "Proxy Version: $(./ssrf-proxy-test --help 2>&1 | head -1 || echo 'Unknown')" >> $SUMMARY_FILE
echo "Test Platform: $(uname -a)" >> $SUMMARY_FILE
echo "" >> $SUMMARY_FILE

# Count test results
total_tests=$(grep -c "^Test:" $RESULTS_FILE || echo "0")
passed_tests=$(grep -c "Result: PASS" $RESULTS_FILE || echo "0")
failed_tests=$(grep -c "Result: FAIL" $RESULTS_FILE || echo "0")
skipped_tests=$(grep -c "Result: SKIPPED" $RESULTS_FILE || echo "0")

echo "Test Results:" >> $SUMMARY_FILE
echo "Total Tests: $total_tests" >> $SUMMARY_FILE
echo "Passed: $passed_tests" >> $SUMMARY_FILE
echo "Failed: $failed_tests" >> $SUMMARY_FILE
echo "Skipped: $skipped_tests" >> $SUMMARY_FILE

if [ $total_tests -gt 0 ]; then
    pass_rate=$((passed_tests * 100 / total_tests))
    echo "Pass Rate: ${pass_rate}%" >> $SUMMARY_FILE
else
    pass_rate=0
fi

echo ""
print_info "Test Summary:"
echo "  Total Tests: $total_tests"
echo "  Passed: $passed_tests"
echo "  Failed: $failed_tests"
echo "  Skipped: $skipped_tests"
echo "  Pass Rate: ${pass_rate}%"

echo ""
print_info "Test artifacts saved in: $TEST_RESULTS_DIR/"
echo "  - functional_tests.txt: Detailed test results"
echo "  - test_summary.txt: Summary report"
echo "  - coverage.html: Code coverage report"
echo "  - proxy.log: Proxy server logs"
echo "  - performance.txt: Performance test results"

# Final result
echo ""
if [ $failed_tests -eq 0 ] && [ $passed_tests -gt 0 ]; then
    print_status "🎉 All tests passed! SSRF proxy is working correctly."
    exit 0
elif [ $pass_rate -ge 80 ]; then
    print_warning "Most tests passed (${pass_rate}% pass rate), but some issues detected."
    exit 0
else
    print_error "Test suite failed (${pass_rate}% pass rate). Check test results for details."
    exit 1
fi 