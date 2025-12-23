# Passbook Makefile
# Set these for releases
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GITHUB_CLIENT_ID ?=

# Build flags
LDFLAGS := -X main.Version=$(VERSION)
ifdef GITHUB_CLIENT_ID
	LDFLAGS += -X passbook/internal/auth.GitHubClientID=$(GITHUB_CLIENT_ID)
endif

.PHONY: build install clean test release

# Development build
build:
	go build -ldflags "$(LDFLAGS)" -o bin/passbook ./cmd/passbook

# Install to GOPATH/bin
install:
	go install -ldflags "$(LDFLAGS)" ./cmd/passbook

# Run tests
test:
	go test ./...

# Clean build artifacts
clean:
	rm -rf bin/
	rm -rf dist/

# Build for all platforms (for releases)
release:
ifndef GITHUB_CLIENT_ID
	$(error GITHUB_CLIENT_ID is required for release builds. Set with: make release GITHUB_CLIENT_ID=your_id)
endif
	@mkdir -p dist
	@echo "Building for darwin/amd64..."
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/passbook-darwin-amd64 ./cmd/passbook
	@echo "Building for darwin/arm64..."
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/passbook-darwin-arm64 ./cmd/passbook
	@echo "Building for linux/amd64..."
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/passbook-linux-amd64 ./cmd/passbook
	@echo "Building for linux/arm64..."
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/passbook-linux-arm64 ./cmd/passbook
	@echo "Done! Binaries in dist/"

# Show help
help:
	@echo "Passbook Build Targets:"
	@echo "  make build                          - Build for current platform"
	@echo "  make install                        - Install to GOPATH/bin"
	@echo "  make test                           - Run tests"
	@echo "  make clean                          - Remove build artifacts"
	@echo "  make release GITHUB_CLIENT_ID=xxx   - Build release binaries for all platforms"
	@echo ""
	@echo "Environment Variables:"
	@echo "  GITHUB_CLIENT_ID  - GitHub OAuth App client ID (required for release)"
	@echo "  VERSION           - Version string (default: git describe)"
