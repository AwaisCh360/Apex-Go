.PHONY: help build install clean tui-build tui-test

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.0.0-dev")
LDFLAGS := -ldflags="-X main.Version=$(VERSION) -s -w"

help:
	@echo "Available commands:"
	@echo "  build         - Build the apex CLI binary"
	@echo "  install       - Install the apex CLI to ~/go/bin"
	@echo "  clean         - Clean build artifacts"
	@echo "  tui-build     - Build the Bubble Tea TUI binary"
	@echo "  tui-test      - Test the Bubble Tea TUI"

build:
	@echo "🔨 Building apex CLI..."
	cd apex && go build $(LDFLAGS) -o ../build/apex ./interface

install:
	@echo "📦 Installing apex CLI to GOPATH..."
	cd apex && go build $(LDFLAGS) -o $(shell go env GOPATH)/bin/apex ./interface
	@echo "✅ Installed successfully!"

clean:
	@echo "🧹 Cleaning up..."
	rm -rf build/
	@echo "✅ Cleanup complete!"

tui-build:
	@echo "🖥️  Building the TUI sidecar..."
	mkdir -p build/sidecar
	cd apex/interface/tui && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../../../build/sidecar/apex-tui ./cmd/apex-tui
	@echo "✅ TUI built successfully!"

tui-test:
	@echo "🧪 Testing TUI..."
	cd apex/interface/tui && go test -race ./...

