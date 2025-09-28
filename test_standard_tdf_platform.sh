#!/bin/bash
set -e

export TDF_KAS_URL="http://10.0.0.138:8080/kas"
export TDF_KAS_PUBLIC_KEY_PATH="/tmp/kas_rsa_public.pem"
export TDF_OUTPUT_SYMMETRIC_KEY_PATH="/tmp/tdf_platform_key.txt"

echo "=== Standard TDF Platform Integration Test ==="
echo

echo "1. Creating test input..."
echo "Standard TDF platform integration test" > test_std_platform.txt

echo "2. Encrypting with Standard TDF..."
.build/release/OpenTDFKitCLI encrypt test_std_platform.txt test_platform.tdf tdf

if [ -f test_platform.tdf ]; then
    SIZE=$(stat -f%z test_platform.tdf)
    echo "✓ Standard TDF created: $SIZE bytes"
else
    echo "✗ Failed to create Standard TDF"
    exit 1
fi

echo ""
echo "3. Verifying TDF structure..."
.build/release/OpenTDFKitCLI verify test_platform.tdf

echo ""
echo "4. Decrypting with symmetric key..."
export TDF_SYMMETRIC_KEY_PATH="/tmp/tdf_platform_key.txt"
.build/release/OpenTDFKitCLI decrypt test_platform.tdf test_platform_recovered.txt tdf

if [ -f test_platform_recovered.txt ]; then
    echo "✓ Decryption successful"
    echo ""
    if diff -q test_std_platform.txt test_platform_recovered.txt > /dev/null; then
        echo "5. ✓ Content matches perfectly!"
        echo ""
        echo "Original:"
        cat test_std_platform.txt
        echo ""
        echo "Recovered:"
        cat test_platform_recovered.txt
    else
        echo "✗ Content mismatch"
        exit 1
    fi
else
    echo "✗ Decryption failed"
    exit 1
fi

echo ""
echo "=== Standard TDF Platform Test PASSED ==="

# Cleanup
rm -f test_std_platform.txt test_platform.tdf test_platform_recovered.txt /tmp/tdf_platform_key.txt
