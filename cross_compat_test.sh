#!/bin/bash
set -e

OTDFCTL="../../opentdf/otdfctl/otdfctl"

if [ ! -f "$OTDFCTL" ]; then
    echo "✗ otdfctl not found at $OTDFCTL"
    exit 1
fi

# Disable ALPN enforcement for otdfctl
export GRPC_ENFORCE_ALPN_ENABLED=false

# For OpenTDFKit CLI
export PLATFORMURL="http://10.0.0.138:8080"
export KASURL="http://10.0.0.138:8080/kas"
export CLIENTID="opentdf-client"
export CLIENTSECRET="secret"
export XT_WITH_PLAINTEXT_POLICY=true

# Get access token
TOKEN=$(cat fresh_token.txt)

echo "=== Cross-Compatibility Test: OpenTDFKit CLI <-> otdfctl ==="
echo

# Test 1: OpenTDFKit CLI encrypt → otdfctl decrypt (NanoTDF)
echo "1. OpenTDFKit CLI encrypt → otdfctl decrypt (NanoTDF)"
echo "   Creating test data..."
echo "Cross-compatibility test data" > test_cross.txt

echo "   Encrypting with OpenTDFKit CLI..."
.build/release/OpenTDFKitCLI encrypt test_cross.txt swift_to_go.ntdf nano

echo "   Decrypting with otdfctl..."
$OTDFCTL --host http://10.0.0.138:8080 --tls-no-verify --with-access-token "$TOKEN" decrypt swift_to_go.ntdf --out go_recovered.txt

if diff -q test_cross.txt go_recovered.txt > /dev/null; then
    echo "   ✓ OpenTDFKit → otdfctl: SUCCESS"
else
    echo "   ✗ OpenTDFKit → otdfctl: FAILED"
    exit 1
fi

echo ""
echo "2. otdfctl encrypt → OpenTDFKit CLI decrypt (NanoTDF)"
echo "   Encrypting with otdfctl..."
$OTDFCTL --host http://10.0.0.138:8080 --tls-no-verify --with-access-token "$TOKEN" encrypt --tdf-type nano test_cross.txt --out go_to_swift.ntdf

echo "   Decrypting with OpenTDFKit CLI..."
.build/release/OpenTDFKitCLI decrypt go_to_swift.ntdf swift_recovered.txt nano

if diff -q test_cross.txt swift_recovered.txt > /dev/null; then
    echo "   ✓ otdfctl → OpenTDFKit: SUCCESS"
else
    echo "   ✗ otdfctl → OpenTDFKit: FAILED"
    exit 1
fi

echo ""
echo "=== All Cross-Compatibility Tests PASSED ==="

# Cleanup
rm -f test_cross.txt swift_to_go.ntdf go_recovered.txt go_to_swift.ntdf swift_recovered.txt
