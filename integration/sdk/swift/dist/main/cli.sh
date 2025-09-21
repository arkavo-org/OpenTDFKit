#!/bin/bash

# XTest CLI wrapper for OpenTDFKit Swift SDK
# This wrapper provides a uniform interface for the xtest harness

# Get the directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Path to the compiled Swift CLI binary
CLI_BINARY="${SCRIPT_DIR}/OpenTDFKitCLI"

# Source any version-specific environment overrides if they exist
if [ -f "${SCRIPT_DIR}/../../main.env" ]; then
    source "${SCRIPT_DIR}/../../main.env"
fi

# Source test.env if it exists (for local testing)
if [ -f "${SCRIPT_DIR}/../../../../test.env" ]; then
    source "${SCRIPT_DIR}/../../../../test.env"
fi

# Check if CLI binary exists
if [ ! -f "$CLI_BINARY" ]; then
    echo "Error: OpenTDFKit CLI not found at $CLI_BINARY" >&2
    echo "Please run 'make -C integration/sdk/swift' to build the CLI" >&2
    exit 1
fi

# Check if binary is executable
if [ ! -x "$CLI_BINARY" ]; then
    chmod +x "$CLI_BINARY"
fi

# Execute the CLI with all arguments
exec "$CLI_BINARY" "$@"