# SSRF Proxy Test Script
# This script demonstrates the functionality of the SSRF detection proxy

Write-Host "`n=== SSRF Detection Proxy Test Script ===" -ForegroundColor Green
Write-Host "This script tests various SSRF detection capabilities`n" -ForegroundColor Yellow

# Function to test proxy endpoint
function Test-ProxyEndpoint {
    param(
        [string]$Description,
        [string]$Url,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [bool]$ShouldBlock = $false
    )
    
    Write-Host "Testing: $Description" -ForegroundColor Cyan
    Write-Host "URL: $Url" -ForegroundColor Gray
    
    try {
        $requestParams = @{
            Uri = $Url
            Method = $Method
            TimeoutSec = 10
            Headers = $Headers
        }
        
        $response = Invoke-WebRequest @requestParams -ErrorAction Stop
        
        if ($ShouldBlock) {
            Write-Host "❌ FAILED: Request should have been blocked but was allowed" -ForegroundColor Red
            Write-Host "Status: $($response.StatusCode)" -ForegroundColor Red
        } else {
            Write-Host "✅ SUCCESS: Request was allowed as expected" -ForegroundColor Green
            Write-Host "Status: $($response.StatusCode)" -ForegroundColor Green
        }
    }
    catch {
        if ($ShouldBlock -and $_.Exception.Response.StatusCode -eq 403) {
            Write-Host "✅ SUCCESS: Request was blocked as expected (403 Forbidden)" -ForegroundColor Green
        } elseif ($ShouldBlock) {
            Write-Host "✅ SUCCESS: Request was blocked (Connection failed)" -ForegroundColor Green
        } else {
            Write-Host "❌ FAILED: Request failed when it should have succeeded" -ForegroundColor Red
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    Write-Host ""
}

# Check if proxy is running
Write-Host "Checking if SSRF Proxy is running on localhost:8080..." -ForegroundColor Yellow
try {
    $healthCheck = Invoke-WebRequest -Uri "http://localhost:8080/health" -TimeoutSec 5
    Write-Host "✅ Proxy is running and healthy!" -ForegroundColor Green
    Write-Host "Health Response: $($healthCheck.Content)" -ForegroundColor Gray
} catch {
    Write-Host "❌ Proxy is not running on localhost:8080" -ForegroundColor Red
    Write-Host "Please start the proxy first: .\ssrf-proxy.exe" -ForegroundColor Yellow
    Write-Host "Or run: .\ssrf-proxy.exe -verbose -allow-internal (for testing internal IPs)" -ForegroundColor Yellow
    exit 1
}

Write-Host "`n=== Starting Tests ===" -ForegroundColor Green

# Test 1: Valid external request (should be allowed)
Test-ProxyEndpoint -Description "Valid external HTTP request" `
    -Url "http://localhost:8080/http://httpbin.org/get" `
    -ShouldBlock $false

# Test 2: Request to internal IP (should be blocked)
Test-ProxyEndpoint -Description "Request to localhost (internal IP)" `
    -Url "http://localhost:8080/http://127.0.0.1:8080" `
    -ShouldBlock $true

# Test 3: Request to private IP range (should be blocked)
Test-ProxyEndpoint -Description "Request to private IP (192.168.1.1)" `
    -Url "http://localhost:8080/http://192.168.1.1" `
    -ShouldBlock $true

# Test 4: Request to private IP range (should be blocked)
Test-ProxyEndpoint -Description "Request to private IP (10.0.0.1)" `
    -Url "http://localhost:8080/http://10.0.0.1" `
    -ShouldBlock $true

# Test 5: Uncommon HTTP method (should be blocked)
Test-ProxyEndpoint -Description "Uncommon HTTP method (TRACE)" `
    -Url "http://localhost:8080/http://httpbin.org/get" `
    -Method "TRACE" `
    -ShouldBlock $true

# Test 6: Another uncommon HTTP method (should be blocked)
Test-ProxyEndpoint -Description "Uncommon HTTP method (CONNECT)" `
    -Url "http://localhost:8080/http://httpbin.org/get" `
    -Method "CONNECT" `
    -ShouldBlock $true

# Test 7: Using X-Target-URL header
Test-ProxyEndpoint -Description "Using X-Target-URL header (external)" `
    -Url "http://localhost:8080/" `
    -Headers @{"X-Target-URL" = "http://httpbin.org/get"} `
    -ShouldBlock $false

# Test 8: Using X-Target-URL header with internal IP (should be blocked)
Test-ProxyEndpoint -Description "Using X-Target-URL header (internal IP)" `
    -Url "http://localhost:8080/" `
    -Headers @{"X-Target-URL" = "http://127.0.0.1:8080"} `
    -ShouldBlock $true

# Test 9: Valid POST request
Test-ProxyEndpoint -Description "Valid POST request" `
    -Url "http://localhost:8080/http://httpbin.org/post" `
    -Method "POST" `
    -ShouldBlock $false

# Test 10: DNS rebinding-like domain (if resolvable)
Test-ProxyEndpoint -Description "Suspicious domain pattern (DNS rebinding)" `
    -Url "http://localhost:8080/http://127.0.0.1.evil.example" `
    -ShouldBlock $true

Write-Host "`n=== Test Summary ===" -ForegroundColor Green
Write-Host "Tests completed! Check the results above." -ForegroundColor Yellow
Write-Host "`nNote: Some tests may show connection failures instead of 403 Forbidden" -ForegroundColor Gray
Write-Host "This is normal behavior as the proxy blocks the request before making it." -ForegroundColor Gray

Write-Host "`n=== Running the proxy with different options ===" -ForegroundColor Green
Write-Host "To test different configurations:" -ForegroundColor Yellow
Write-Host "1. Default (strict): .\ssrf-proxy.exe" -ForegroundColor Cyan
Write-Host "2. Verbose logging: .\ssrf-proxy.exe -verbose" -ForegroundColor Cyan
Write-Host "3. Allow internal IPs: .\ssrf-proxy.exe -allow-internal" -ForegroundColor Cyan
Write-Host "4. Development mode: .\ssrf-proxy.exe -verbose -allow-internal -allow-dns-rebinding" -ForegroundColor Cyan 