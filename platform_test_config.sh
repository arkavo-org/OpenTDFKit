#!/bin/bash
# Platform configuration for 10.0.0.138

export PLATFORMURL="http://10.0.0.138:8080"
export KASURL="http://10.0.0.138:8080/kas"
export OIDC_ENDPOINT="http://10.0.0.138:8888"
export CLIENTID="opentdf-client"
export CLIENTSECRET="secret"

# For Standard TDF
export TDF_KAS_URL="${KASURL}"
export TDF_PLATFORMURL="${PLATFORMURL}"

echo "Platform configuration loaded:"
echo "  PLATFORMURL: ${PLATFORMURL}"
echo "  KASURL: ${KASURL}"
echo "  OIDC_ENDPOINT: ${OIDC_ENDPOINT}"
