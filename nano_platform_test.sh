#!/bin/bash
set -e

echo "=== NanoTDF Platform Integration Test ==="
echo

# Configuration
export PLATFORMURL="http://10.0.0.138:8080"
export KASURL="http://10.0.0.138:8080/kas"
export CLIENTID="opentdf-client"
export CLIENTSECRET="secret"
export XT_WITH_PLAINTEXT_POLICY=true

echo "1. Creating test input..."
echo "Platform integration test for NanoTDF" > test_nano_platform.txt

echo "2. Encrypting with NanoTDF..."
.build/release/OpenTDFKitCLI encrypt test_nano_platform.txt test_nano_platform.ntdf nano

if [ -f test_nano_platform.ntdf ]; then
    SIZE=$(stat -f%z test_nano_platform.ntdf)
    echo "✓ NanoTDF created: $SIZE bytes"
else
    echo "✗ Failed to create NanoTDF"
    exit 1
fi

echo ""
echo "3. Decrypting with KAS rewrap..."
.build/release/OpenTDFKitCLI decrypt test_nano_platform.ntdf test_nano_recovered.txt nano

if [ -f test_nano_recovered.txt ]; then
    echo "✓ Decryption successful"
    echo ""
    echo "4. Verifying content..."
    if diff -q test_nano_platform.txt test_nano_recovered.txt > /dev/null; then
        echo "✓ Content matches perfectly!"
        echo ""
        echo "Original:"
        cat test_nano_platform.txt
        echo ""
        echo "Recovered:"
        cat test_nano_recovered.txt
    else
        echo "✗ Content mismatch"
        exit 1
    fi
else
    echo "✗ Decryption failed"
    exit 1
fi

echo ""
echo "=== NanoTDF Platform Test PASSED ==="
