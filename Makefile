.PHONY: build run test clean install deps help

.DEFAULT_GOAL := help

BINARY_NAME=ssrf-proxy
BUILD_DIR=./bin
MAIN_FILE=main.go

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_FILE)
	@echo "Binary built: $(BUILD_DIR)/$(BINARY_NAME)"

build-all:
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(MAIN_FILE)
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(MAIN_FILE)
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(MAIN_FILE)
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(MAIN_FILE)
	@echo "Built binaries:"
	@ls -la $(BUILD_DIR)/

deps:
	@echo "Installing dependencies..."
	go mod tidy
	go mod download

run: build
	@echo "Starting SSRF Proxy on port 8080..."
	$(BUILD_DIR)/$(BINARY_NAME)

run-dev: build
	@echo "Starting SSRF Proxy in development mode..."
	$(BUILD_DIR)/$(BINARY_NAME) -verbose -allow-internal -allow-dns-rebinding

test:
	@echo "Running unit tests..."
	go test -v -race -coverprofile=coverage.out ./...

test-all:
	@echo "Running comprehensive test suite..."
	@chmod +x run_tests.sh
	./run_tests.sh

test-coverage:
	@echo "Running tests with coverage..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-integration:
	@echo "Running integration tests..."
	go test -v -tags=integration ./...

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	go clean

install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "$(BINARY_NAME) installed successfully"

fmt:
	@echo "Formatting code..."
	go fmt ./...

lint:
	@echo "Linting code..."
	golangci-lint run

security:
	@echo "Running security scan..."
	gosec ./...

help:
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST) 