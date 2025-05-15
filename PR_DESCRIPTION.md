# Add PublicKeyStore for Peer-to-Peer Key Exchange

## Summary

This PR introduces a new `PublicKeyStore` feature that improves the security and efficiency of peer-to-peer key exchange workflows. The changes address an issue where peers were exchanging empty or minimal key stores due to incorrect initialization and inappropriate sharing of full key stores.

## Implemented Features

1. **New PublicKeyStore Class:**
   - Created a dedicated `PublicKeyStore` class that contains only public keys for sharing with peers
   - Provides secure one-time use key consumption with `getAndRemovePublicKey()`
   - Includes efficient serialization/deserialization for network exchange

2. **Enhanced KeyStore:**
   - Added `exportPublicKeyStore()` method to separate public keys from private keys
   - Improves security by only sharing what's necessary with peers

3. **Streamlined NanoTDF Creation:**
   - Added convenient `createKasMetadata()` to simplify NanoTDF creation in P2P workflows
   - Maintains compatibility with existing KAS-based workflows

4. **Comprehensive Testing:**
   - Added basic tests for PublicKeyStore serialization and deserialization
   - Added a simple P2P encryption/decryption test
   - Added a comprehensive bidirectional P2P workflow test

5. **Documentation:**
   - Updated README with detailed examples of P2P workflows
   - Added clear explanations of both KAS-based and P2P approaches

## Issue Resolution

This PR resolves the issue where the serialized KeyStore was only containing 5 bytes of header data with no actual keys. The problem occurred because:

1. The app was initializing a KeyStore without generating any keys
2. The serialization method correctly included a 5-byte header (1 byte for curve type + 4 bytes for key count=0)
3. No actual key data was included because no keys were generated

The new approach:
1. Requires explicit key generation after KeyStore initialization
2. Separates private+public key storage from public-only key sharing
3. Provides clear methods for P2P key exchange workflows

## Testing

The implementation has been tested with:
- Unit tests for basic PublicKeyStore functionality
- End-to-end tests demonstrating complete P2P workflow including key exchange, encryption, and decryption
- Tests pass on both secp256r1 curves

## Usage Example

The PR includes detailed examples in the README showing:
1. How to generate keys and export public keys for sharing
2. How peers consume public keys for encryption
3. How to decrypt NanoTDFs using private keys in a P2P context

## Breaking Changes

None. All changes are backward compatible with existing code.

## Next Steps

- Consider adding key rotation mechanisms for PublicKeyStore
- Add support for monitoring key usage and automatic replenishment
- Implement optional signatures for PublicKeyStore authentication