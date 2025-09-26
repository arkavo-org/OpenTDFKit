# Makefile for building OpenTDFKit CLI for xtest integration

SWIFT = swift
BUILD_DIR = ../../../.build
CLI_BINARY = $(BUILD_DIR)/release/OpenTDFKitCLI
DIST_DIR = dist/main
DIST_BINARY = $(DIST_DIR)/OpenTDFKitCLI

.PHONY: all build clean install

# Default target
all: install

# Build the CLI in release mode
build:
	@echo "Building OpenTDFKit CLI..."
	cd ../../.. && $(SWIFT) build -c release --product OpenTDFKitCLI

# Install the built binary to dist directory
install: build
	@echo "Installing CLI to $(DIST_DIR)..."
	@mkdir -p $(DIST_DIR)
	@cp $(CLI_BINARY) $(DIST_BINARY)
	@chmod +x $(DIST_BINARY)
	@echo "Installed: $(DIST_BINARY)"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cd ../../.. && $(SWIFT) package clean
	@rm -rf $(DIST_DIR)

# Test that the CLI works
test: install
	@echo "Testing CLI..."
	@$(DIST_BINARY) supports nano && echo "✓ nano support verified" || echo "✗ nano support failed"
	@$(DIST_BINARY) supports nano_ecdsa && echo "✓ nano_ecdsa support verified" || echo "✗ nano_ecdsa support failed"

# Help target
help:
	@echo "OpenTDFKit CLI Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build and install (default)"
	@echo "  build    - Build the CLI in release mode"
	@echo "  install  - Install CLI to dist directory"
	@echo "  clean    - Remove build artifacts"
	@echo "  test     - Test the installed CLI"
	@echo "  help     - Show this help message"