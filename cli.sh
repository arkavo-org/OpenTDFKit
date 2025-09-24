#!/bin/bash
# OpenTDFKit CLI wrapper for xtest compatibility
# This script wraps the OpenTDFKit CLI to match xtest expectations

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CLI_PATH="$SCRIPT_DIR/.build/release/OpenTDFKitCLI"

# Check if CLI is built
if [ ! -f "$CLI_PATH" ]; then
    echo "Error: OpenTDFKitCLI not found. Building..." >&2
    (cd "$SCRIPT_DIR" && swift build -c release --product OpenTDFKitCLI)
    if [ ! -f "$CLI_PATH" ]; then
        echo "Error: Failed to build OpenTDFKitCLI" >&2
        exit 1
    fi
fi

# Ensure we have a token
if [ ! -f "fresh_token.txt" ] || [ ! -s "fresh_token.txt" ]; then
    echo "Getting OAuth token..." >&2
    curl -s -X POST "http://10.0.0.138:8888/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&client_id=opentdf-client&client_secret=secret" \
        | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])" > fresh_token.txt
fi

# Execute the CLI with all arguments passed through
exec "$CLI_PATH" "$@"