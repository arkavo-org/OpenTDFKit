# OpenTDF Service Integration Guide

## Overview

This guide provides instructions for integrating with the OpenTDF service instance running on the local network. The service is configured for cross-platform testing and is accessible from other machines on the network.

## Service Endpoints

### Primary Host Information
- **Host**: Set via `PLATFORMURL` environment variable (defaults to `http://localhost:8080`)
- **OIDC Host**: Set via `OIDC_ENDPOINT` environment variable (defaults to `http://localhost:8888`)

### OpenTDF Platform Service
- **Protocol**: HTTP/gRPC
- **Port**: 8080 (default)
- **Endpoints**:
  - Platform: `${PLATFORMURL:-http://localhost:8080}`
  - Health Check: `/health`

### Mock OIDC Provider
- **Protocol**: HTTP
- **Port**: 8888 (default)
- **Endpoints**:
  - OIDC: `${OIDC_ENDPOINT:-http://localhost:8888}`
  - Discovery: `/.well-known/openid-configuration`
  - JWKS: `/jwks`
  - Token: `/token`

## Authentication

### Registered Clients

| Client ID | Client Secret | Type | Purpose |
|-----------|--------------|------|---------|
| `opentdf-client` | `secret` | Confidential | Server-to-server operations |
| `opentdf-public` | (none) | Public | Browser/mobile applications |

### Obtaining Access Tokens

#### Method 1: Client Credentials Flow (Recommended for Testing)
```bash
curl -X POST "${OIDC_ENDPOINT:-http://localhost:8888}/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=opentdf-client&client_secret=secret"
```

#### Response Format
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiI...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email"
}
```

### Token Details
- **Algorithm**: RS256
- **Expiration**: 3600 seconds (1 hour)
- **Issuer**: Set via `OIDC_ENDPOINT` (defaults to `http://localhost:8888`)
- **Audience**: `opentdf`

## Using otdfctl CLI

### Configuration for Remote Access

Create a profile for network access:
```yaml
# otdfctl-network.yaml
endpoint: ${PLATFORMURL:-http://localhost:8080}
tls:
  insecure: false
  no-verify: true
auth:
  issuer: ${OIDC_ENDPOINT:-http://localhost:8888}
  client_id: opentdf-client
```

### Basic Operations

#### 1. Encrypt a File
```bash
# Get token
TOKEN=$(curl -s -X POST "${OIDC_ENDPOINT:-http://localhost:8888}/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=opentdf-client&client_secret=secret" \
  | jq -r '.access_token')

# Encrypt
./otdfctl --host "${PLATFORMURL:-http://localhost:8080}" \
  --with-access-token "$TOKEN" \
  encrypt input.txt --out output.txt.tdf
```

#### 2. List Policy Attributes
```bash
./otdfctl --host "${PLATFORMURL:-http://localhost:8080}" \
  --with-access-token "$TOKEN" \
  policy attributes list
```

## API Testing Examples

### Health Check
```bash
# No authentication required for health endpoint
curl "${PLATFORMURL:-http://localhost:8080}/health"
```

### KAS Public Key Retrieval
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "${PLATFORMURL:-http://localhost:8080}/kas/v2/kas_public_key"
```

### Policy Operations
```bash
# Create attribute
curl -X POST "${PLATFORMURL:-http://localhost:8080}/attributes" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "classification",
    "namespace": "https://example.com",
    "values": ["public", "internal", "confidential"]
  }'
```

## Cross-Platform Testing Scenarios

### 1. Multi-Client TDF Sharing
Test encrypting on one platform and decrypting on another:
- Platform A encrypts with attribute `classification=internal`
- Platform B attempts decrypt with proper authorization
- Verify access control across platforms

### 2. Policy Synchronization
Test policy consistency across OpenTDF instances:
- Create attributes on primary instance
- Verify replication/synchronization
- Test policy enforcement uniformity

### 3. Token Validation
Test JWT token acceptance across different services:
- Generate token from mock OIDC
- Use token across different OpenTDF instances
- Verify consistent authentication behavior

## Network Configuration

### Firewall Rules
Ensure these ports are accessible from test machines:
- **8080/tcp** - OpenTDF gRPC/HTTP
- **8888/tcp** - Mock OIDC Provider

### DNS/Hosts File
For local development, you can use `localhost`:
- `http://localhost:8080` for OpenTDF
- `http://localhost:8888` for OIDC

For remote servers, set environment variables:
```bash
export PLATFORMURL=http://your-server:8080
export OIDC_ENDPOINT=http://your-server:8888
```

## Troubleshooting

### Common Issues

#### 1. Connection Refused
- Verify services are running: `lsof -i :8080` and `lsof -i :8888`
- Check firewall settings
- Ensure binding to correct interfaces

#### 2. Authentication Failures
- Verify token is properly formatted (JWT with 3 parts)
- Check token expiration
- Ensure issuer URL matches between token and service config

#### 3. TDF Operations Failing
- Verify KAS keys are properly configured
- Check database connectivity
- Review service logs for detailed errors

### Service Logs

View real-time logs:
```bash
# If running in foreground
./opentdf start

# If running in background, check process output
ps aux | grep opentdf
```

### Health Monitoring

Quick health check script:
```bash
#!/bin/bash
echo "Checking OpenTDF services..."
curl -s "${PLATFORMURL:-http://localhost:8080}/health" > /dev/null && echo "✓ OpenTDF: OK" || echo "✗ OpenTDF: FAILED"
curl -s "${OIDC_ENDPOINT:-http://localhost:8888}/.well-known/openid-configuration" > /dev/null && echo "✓ OIDC: OK" || echo "✗ OIDC: FAILED"
```

## Database Information

### PostgreSQL Connection
- **Host**: Set via `DB_HOST` (defaults to `localhost`)
- **Port**: Set via `DB_PORT` (defaults to `5432`)
- **Database**: Set via `DB_NAME` (defaults to `opentdf`)
- **User**: Set via `DB_USER` (defaults to `postgres`)
- **Password**: Set via `DB_PASSWORD` environment variable

### Schema
- Primary schema: `opentdf_policy`
- Migration version: `20250805000000`

## Security Considerations

### Test Environment Only
⚠️ **WARNING**: This configuration is for testing only:
- Mock OIDC server uses static keys
- Client secrets are hardcoded
- No TLS/HTTPS configured
- Simple authentication without proper validation

### Production Requirements
For production deployments:
1. Use proper OIDC provider (Keycloak, Auth0, etc.)
2. Enable TLS/HTTPS
3. Rotate keys regularly
4. Implement proper secret management
5. Configure firewall rules appropriately

## Integration Checklist

Before testing:
- [ ] Set required environment variables (PLATFORMURL, OIDC_ENDPOINT, CLIENTID, CLIENTSECRET)
- [ ] Verify network connectivity to OpenTDF server
- [ ] Confirm ports 8080 and 8888 are accessible
- [ ] Obtain client credentials for testing
- [ ] Configure otdfctl or SDK with proper endpoints
- [ ] Test basic health check endpoints
- [ ] Verify token generation works
- [ ] Test a simple encrypt/decrypt operation

## Support Files

### Required Files on Host
- `kas-private.pem` - KAS RSA private key
- `kas-public.pem` - KAS RSA public key
- `opentdf.yaml` - Service configuration
- `mock-oidc-server-multi.js` - Mock OIDC provider

### Optional Configuration Files
- `otdfctl.yaml` - CLI configuration
- `.opentdf/opentdf.yaml` - Alternative config location

## Quick Start for New Test Agent

```bash
# 1. Set environment variables
export PLATFORMURL=http://localhost:8080
export OIDC_ENDPOINT=http://localhost:8888
export CLIENTID=opentdf-client
export CLIENTSECRET=secret

# 2. Get access token
TOKEN=$(curl -s -X POST "${OIDC_ENDPOINT}/token" \
  -d "grant_type=client_credentials&client_id=${CLIENTID}&client_secret=${CLIENTSECRET}" \
  | jq -r '.access_token')

# 3. Test OpenTDF API
curl -H "Authorization: Bearer $TOKEN" \
  "${PLATFORMURL}/attributes"

# 4. Create test TDF
echo "Test data" > test.txt
./otdfctl --host "${PLATFORMURL}" \
  --with-access-token "$TOKEN" \
  encrypt test.txt --out test.txt.tdf
```

## Tips

For issues or questions about this test environment:
- Check service logs for detailed error messages
- Review the troubleshooting section above
- Consult related documentation files
- Verify network connectivity and firewall rules
