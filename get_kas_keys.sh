#!/bin/bash
TOKEN=$(cat fresh_token.txt)

echo "Fetching KAS public keys..."

# Get EC key for NanoTDF
curl -s "http://10.0.0.138:8080/kas/v2/kas_public_key?algorithm=ec:secp256r1" \
  -H "Authorization: Bearer ${TOKEN}" > /tmp/kas_ec_key.json

# Get RSA key for Standard TDF
curl -s "http://10.0.0.138:8080/kas/v2/kas_public_key" \
  -H "Authorization: Bearer ${TOKEN}" > /tmp/kas_rsa_key.json

echo "Done. Checking responses..."
cat /tmp/kas_ec_key.json
echo ""
cat /tmp/kas_rsa_key.json