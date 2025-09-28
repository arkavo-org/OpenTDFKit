#!/bin/bash

# Test with integration directory script
cd ../../opentdf/platform || exit 1

export OPENTDF_ENDPOINT="http://10.0.0.138:8080"
export OPENTDF_CLIENT_ID="opentdf-client"
export OPENTDF_CLIENT_SECRET="secret"

echo "Creating test file..."
echo "Integration test" > /tmp/test_nano_in.txt

echo "Encrypting with integration otdfctl..."
./integration/otdfctl encrypt --tdf-type nano /tmp/test_nano_in.txt --out /tmp/test_otdfctl.ntdf

if [ -f /tmp/test_otdfctl.ntdf ]; then
    echo "✓ otdfctl NanoTDF created"
    ls -la /tmp/test_otdfctl.ntdf
    
    cd - > /dev/null
    echo ""
    echo "Decrypting with OpenTDFKit CLI..."
    export PLATFORMURL="http://10.0.0.138:8080"
    export KASURL="http://10.0.0.138:8080/kas"
    export CLIENTID="opentdf-client"
    export CLIENTSECRET="secret"
    
    .build/release/OpenTDFKitCLI decrypt /tmp/test_otdfctl.ntdf /tmp/test_swift_recovered.txt nano
    
    if diff -q /tmp/test_nano_in.txt /tmp/test_swift_recovered.txt > /dev/null; then
        echo "✓ otdfctl → OpenTDFKit: SUCCESS!"
    else
        echo "✗ Content mismatch"
    fi
else
    echo "✗ Failed to create NanoTDF with otdfctl"
fi
