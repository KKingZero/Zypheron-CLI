# Zypheron CLI - Makefile
# Build system for Go implementation

VERSION := 1.0.0
BINARY := zypheron
BUILD_DIR := build
INSTALL_DIR := /usr/local/bin
GO := go
GOFLAGS := -ldflags="-s -w -X main.version=$(VERSION)"

.PHONY: all
all: build

.PHONY: build
build:
	@echo "Building Zypheron v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY) cmd/zypheron/main.go
	@echo "✓ Built: $(BUILD_DIR)/$(BINARY)"
	@ls -lh $(BUILD_DIR)/$(BINARY)

.PHONY: build-all
build-all:
	@echo "Cross-compiling for all platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64 cmd/zypheron/main.go
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-arm64 cmd/zypheron/main.go
	GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-amd64 cmd/zypheron/main.go
	GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-arm64 cmd/zypheron/main.go
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe cmd/zypheron/main.go
	@echo "✓ Built all platforms in $(BUILD_DIR)/"
	@ls -lh $(BUILD_DIR)/

.PHONY: install
install: build
	@echo "Installing to $(INSTALL_DIR)..."
	@sudo cp $(BUILD_DIR)/$(BINARY) $(INSTALL_DIR)/
	@sudo chmod +x $(INSTALL_DIR)/$(BINARY)
	@echo "✓ Installed! Run: zypheron --version"

.PHONY: uninstall
uninstall:
	@echo "Uninstalling from $(INSTALL_DIR)..."
	@sudo rm -f $(INSTALL_DIR)/$(BINARY)
	@echo "✓ Uninstalled"

.PHONY: deps
deps:
	@echo "Installing Go dependencies..."
	$(GO) get github.com/spf13/cobra@latest
	$(GO) get github.com/spf13/viper@latest
	$(GO) get github.com/fatih/color@latest
	$(GO) get github.com/briandowns/spinner@latest
	$(GO) get github.com/olekukonko/tablewriter@latest
	$(GO) get github.com/AlecAivazis/survey/v2@latest
	$(GO) get github.com/gorilla/websocket@latest
	$(GO) mod tidy
	@echo "✓ Dependencies installed"

.PHONY: test
test:
	@echo "Running tests with coverage..."
	$(GO) test -v -cover -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out
	@echo ""
	@echo "Generate HTML coverage report with: make coverage-html"

.PHONY: coverage-html
coverage-html: test
	@echo "Generating HTML coverage report..."
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report: coverage.html"

.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "✓ Cleaned"

.PHONY: dev
dev:
	@echo "Running in development mode..."
	$(GO) run cmd/zypheron/main.go

.PHONY: fmt
fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...
	@echo "✓ Formatted"

.PHONY: lint
lint:
	@echo "Running linter..."
	golangci-lint run ./...

.PHONY: compress
compress: build
	@echo "Compressing binary with UPX..."
	@command -v upx >/dev/null 2>&1 || { echo "UPX not found. Install with: apt-get install upx-ucl"; exit 1; }
	upx --best --lzma $(BUILD_DIR)/$(BINARY)
	@echo "✓ Compressed!"
	@ls -lh $(BUILD_DIR)/$(BINARY)

.PHONY: release
release: clean build-all
	@echo "Creating release packages..."
	@mkdir -p release/v$(VERSION)
	@for binary in $(BUILD_DIR)/$(BINARY)-*; do \
		filename=$$(basename $$binary); \
		if [[ "$$filename" != *.exe ]]; then \
			tar -czf release/v$(VERSION)/$$filename.tar.gz -C $(BUILD_DIR) $$filename; \
		else \
			zip -j release/v$(VERSION)/$$filename.zip $$binary; \
		fi; \
	done
	@cd release/v$(VERSION) && sha256sum * > SHA256SUMS
	@echo "✓ Release packages created in release/v$(VERSION)/"
	@ls -lh release/v$(VERSION)/

.PHONY: help
help:
	@echo "Zypheron CLI - Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build        Build for current platform"
	@echo "  build-all    Cross-compile for all platforms"
	@echo "  install      Install to system"
	@echo "  uninstall    Remove from system"
	@echo "  deps         Install Go dependencies"
	@echo "  test         Run tests"
	@echo "  clean        Clean build artifacts"
	@echo "  dev          Run in development mode"
	@echo "  fmt          Format code"
	@echo "  lint         Run linter"
	@echo "  compress     Compress binary with UPX"
	@echo "  release      Create release packages"
	@echo "  help         Show this help message"

