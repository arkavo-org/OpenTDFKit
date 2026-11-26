import CryptoKit
import Foundation

/// Errors specific to the KAS service operations
public enum KASServiceError: Error, Equatable {
    case invalidRequest
    case authenticationFailed
    case accessDenied
    case keyNotFound
    case invalidKeyFormat
    case invalidCurve
    case rewrapFailed
    case serverError(String)
    case networkError(String)

    /// Custom error equality implementation
    public static func == (lhs: KASServiceError, rhs: KASServiceError) -> Bool {
        switch (lhs, rhs) {
        case (.invalidRequest, .invalidRequest),
             (.authenticationFailed, .authenticationFailed),
             (.accessDenied, .accessDenied),
             (.keyNotFound, .keyNotFound),
             (.invalidKeyFormat, .invalidKeyFormat),
             (.invalidCurve, .invalidCurve),
             (.rewrapFailed, .rewrapFailed):
            true
        case let (.serverError(lhsMsg), .serverError(rhsMsg)):
            lhsMsg == rhsMsg
        case let (.networkError(lhsMsg), .networkError(rhsMsg)):
            lhsMsg == rhsMsg
        default:
            false
        }
    }
}

/// KAS entity credentials for authentication
public struct KASCredential: Sendable {
    let clientId: String
    let clientSecret: String?
    let token: String?

    public init(clientId: String, clientSecret: String? = nil, token: String? = nil) {
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.token = token
    }

    var authorizationHeader: String? {
        if let token {
            return "Bearer \(token)"
        } else if let clientSecret {
            let credentials = "\(clientId):\(clientSecret)"
            guard let credentialsData = credentials.data(using: .utf8) else {
                return nil
            }
            let base64Credentials = credentialsData.base64EncodedString()
            return "Basic \(base64Credentials)"
        }
        return nil
    }
}

/// Key rewrap request data structure
public struct RewrapRequest: Sendable, Encodable {
    let ephemeralPublicKey: String
    let encryptedSessionKey: String
    let policyBinding: String?
    let attributes: [String: String]?

    enum CodingKeys: String, CodingKey {
        case ephemeralPublicKey = "ephemeral_public_key"
        case encryptedSessionKey = "wrapped_key"
        case policyBinding = "policy_binding"
        case attributes
    }
}

/// Key rewrap response data structure
public struct RewrapResponse: Sendable, Decodable {
    let rewrappedKey: String

    enum CodingKeys: String, CodingKey {
        case rewrappedKey = "rewrapped_key"
    }
}

/// Actor providing KAS (Key Access Service) functionality
public actor KASService {
    private let keyStore: KeyStore
    private let baseURL: URL
    private let credential: KASCredential?
    private let urlSession: URLSession

    /// Initialize a KAS service with required parameters
    /// - Parameters:
    ///   - keyStore: KeyStore for key lookup
    ///   - baseURL: Base URL for the KAS endpoint
    ///   - credential: Optional credentials for authentication
    ///   - urlSession: URLSession to use for network requests (allows dependency injection for testing)
    public init(keyStore: KeyStore, baseURL: URL, credential: KASCredential? = nil, urlSession: URLSession = .shared) {
        self.keyStore = keyStore
        self.baseURL = baseURL
        self.credential = credential
        self.urlSession = urlSession
    }

    /// Generate metadata for a KAS resource
    /// - Returns: KasMetadata containing the resource locator and public key
    public func generateKasMetadata() async throws -> KasMetadata {
        // Generate a fresh key pair using the store's curve type
        let keyPair = await keyStore.generateKeyPair()

        // Store the key pair in the keystore so it can be retrieved later
        await keyStore.store(keyPair: keyPair)

        // Create a resource locator based on the service base URL
        let resourcePath = baseURL.host ?? "kas.example.com"
        guard let resourceLocator = ResourceLocator(
            protocolEnum: baseURL.scheme == "https" ? .https : .http,
            body: resourcePath,
        ) else {
            throw KASServiceError.serverError("Failed to create resource locator")
        }

        // Create the appropriate public key type based on the curve
        switch keyStore.curve {
        case .secp256r1:
            let publicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: keyPair.publicKey)
            return try KasMetadata(resourceLocator: resourceLocator, publicKey: publicKey, curve: .secp256r1)

        case .secp384r1:
            let publicKey = try P384.KeyAgreement.PublicKey(compressedRepresentation: keyPair.publicKey)
            return try KasMetadata(resourceLocator: resourceLocator, publicKey: publicKey, curve: .secp384r1)

        case .secp521r1:
            let publicKey = try P521.KeyAgreement.PublicKey(compressedRepresentation: keyPair.publicKey)
            return try KasMetadata(resourceLocator: resourceLocator, publicKey: publicKey, curve: .secp521r1)
        }
    }

    /// Rewrap a key using the KAS server
    /// - Parameters:
    ///   - ephemeralPublicKey: The client's ephemeral public key in base64
    ///   - encryptedSessionKey: The encrypted session key to be rewrapped
    ///   - policyBinding: Optional policy binding data
    ///   - attributes: Optional attributes for the KAS server
    /// - Returns: The rewrapped key
    public func rewrapKey(
        ephemeralPublicKey: Data,
        encryptedSessionKey: Data,
        policyBinding: Data? = nil,
        attributes: [String: String]? = nil,
    ) async throws -> Data {
        let rewrapEndpoint = baseURL.appendingPathComponent("kas/v2/rewrap")
        do {
            try validateKasURL(rewrapEndpoint.absoluteString)
        } catch {
            throw KASServiceError.invalidRequest
        }

        var request = URLRequest(url: rewrapEndpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 30
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")

        if let credential, let authHeader = credential.authorizationHeader {
            request.addValue(authHeader, forHTTPHeaderField: "Authorization")
        }

        // Prepare request body
        let requestData = RewrapRequest(
            ephemeralPublicKey: ephemeralPublicKey.base64EncodedString(),
            encryptedSessionKey: encryptedSessionKey.base64EncodedString(),
            policyBinding: policyBinding?.base64EncodedString(),
            attributes: attributes,
        )

        let encoder = JSONEncoder()
        request.httpBody = try encoder.encode(requestData)

        // Perform the network request with no-redirect and bounded response buffering
        let data: Data
        let httpResponse: HTTPURLResponse
        do {
            (data, httpResponse) = try await BoundedHTTPClient.send(
                request,
                on: urlSession,
                maxBytes: BoundedHTTPClient.defaultKASRewrapServiceMaxBytes,
            )
        } catch BoundedHTTPError.nonHTTPResponse {
            throw KASServiceError.networkError("Invalid response type")
        } catch let BoundedHTTPError.responseTooLarge(limit) {
            throw KASServiceError.networkError("Response exceeded \(limit)-byte limit")
        }

        switch httpResponse.statusCode {
        case 200, 201:
            let decoder = JSONDecoder()
            let rewrapResponse = try decoder.decode(RewrapResponse.self, from: data)
            guard let rewrappedKeyData = Data(base64Encoded: rewrapResponse.rewrappedKey) else {
                throw KASServiceError.invalidKeyFormat
            }
            return rewrappedKeyData
        case 400:
            throw KASServiceError.invalidRequest
        case 401:
            throw KASServiceError.authenticationFailed
        case 403:
            throw KASServiceError.accessDenied
        case 404:
            throw KASServiceError.keyNotFound
        default:
            throw KASServiceError.serverError("HTTP \(httpResponse.statusCode)")
        }
    }

    /// Internal helper function to rewrap a key
    /// - Parameters:
    ///   - ephemeralPublicKey: Client's ephemeral public key
    ///   - encryptedKey: The encrypted key to unwrap
    ///   - privateKeyData: The KAS private key to use for decryption
    ///   - policyBody: Optional serialized policy body to verify against `policyBinding`
    ///   - policyBinding: Optional GMAC policy binding to verify before rewrapping
    /// - Returns: Rewrapped key data and the new key pair used for rewrapping
    func rewrapKeyInternal(
        ephemeralPublicKey: Data,
        encryptedKey: Data,
        privateKeyData: Data,
        policyBody: Data? = nil,
        policyBinding: Data? = nil,
        precomputedPrimaryKey: SymmetricKey? = nil,
    ) async throws -> (rewrappedKey: Data, newKeyPair: StoredKeyPair) {
        // 1-2. Derive symmetric key for decryption (using v12 salt) unless already computed by caller
        let primaryKey: SymmetricKey
        if let precomputedPrimaryKey {
            primaryKey = precomputedPrimaryKey
        } else {
            let sharedSecret: SharedSecret

            switch keyStore.curve {
            case .secp256r1:
                let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
                let publicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: ephemeralPublicKey)
                sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)

            case .secp384r1:
                let privateKey = try P384.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
                let publicKey = try P384.KeyAgreement.PublicKey(compressedRepresentation: ephemeralPublicKey)
                sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)

            case .secp521r1:
                let privateKey = try P521.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
                let publicKey = try P521.KeyAgreement.PublicKey(compressedRepresentation: ephemeralPublicKey)
                sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
            }

            primaryKey = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: CryptoConstants.hkdfSaltV12,
                sharedInfo: Data(), // Empty per spec section 4
                outputByteCount: 32,
            )
        }

        // 2b. Verify policy binding when provided (if either is set, both must be present and valid)
        if policyBody != nil || policyBinding != nil {
            guard let body = policyBody, let binding = policyBinding else {
                throw KASServiceError.accessDenied
            }
            let valid = try await verifyPolicyBinding(
                policyBinding: binding,
                policyData: body,
                symmetricKey: primaryKey,
            )
            guard valid else {
                throw KASServiceError.accessDenied
            }
        }

        // 3. Generate a new ephemeral key pair for rewrapping
        let newKeyPair = await keyStore.generateKeyPair()

        // 4. Decrypt the encrypted key using the derived symmetric key
        guard encryptedKey.count >= 28 else { // Minimum size for AES-GCM: 12 bytes nonce + 16 bytes tag
            throw KASServiceError.invalidKeyFormat
        }

        // Parse the encrypted key format (split into nonce, ciphertext, and tag)
        let nonce = encryptedKey.prefix(12)
        let tag = encryptedKey.suffix(16)
        let ciphertext = encryptedKey.dropFirst(12).dropLast(16)

        let sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonce),
            ciphertext: ciphertext,
            tag: tag,
        )

        var decryptedKey = try AES.GCM.open(sealedBox, using: primaryKey)
        defer { decryptedKey.secureZero() }

        // 5. Create new shared secret for rewrapping
        let newSharedSecret: SharedSecret

        switch keyStore.curve {
        case .secp256r1:
            let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: newKeyPair.privateKey)
            let publicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: ephemeralPublicKey)
            newSharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)

        case .secp384r1:
            let privateKey = try P384.KeyAgreement.PrivateKey(rawRepresentation: newKeyPair.privateKey)
            let publicKey = try P384.KeyAgreement.PublicKey(compressedRepresentation: ephemeralPublicKey)
            newSharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)

        case .secp521r1:
            let privateKey = try P521.KeyAgreement.PrivateKey(rawRepresentation: newKeyPair.privateKey)
            let publicKey = try P521.KeyAgreement.PublicKey(compressedRepresentation: ephemeralPublicKey)
            newSharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        }

        // 6. Derive new symmetric key for encryption (using v12 format)
        let newSymmetricKey = newSharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: CryptoConstants.hkdfSaltV12,
            sharedInfo: Data(), // Empty per spec section 4
            outputByteCount: 32,
        )

        // 7. Re-encrypt the key with the new symmetric key
        let newNonce = AES.GCM.Nonce()
        let newSealedBox = try AES.GCM.seal(decryptedKey, using: newSymmetricKey, nonce: newNonce)

        // 8. Combine the new ephemeral public key with the encrypted data
        let newPublicKey = newKeyPair.publicKey
        var result = Data(capacity: newPublicKey.count + 12 + newSealedBox.ciphertext.count + newSealedBox.tag.count)
        result.append(newPublicKey)
        newNonce.withUnsafeBytes { result.append(contentsOf: $0) }
        result.append(newSealedBox.ciphertext)
        result.append(newSealedBox.tag)

        return (rewrappedKey: result, newKeyPair: newKeyPair)
    }

    /// Process key access request locally (server-side KAS implementation), always verifying
    /// the policy binding before rewrapping.
    public func processKeyAccess(
        ephemeralPublicKey: Data,
        encryptedKey: Data,
        kasPublicKey: Data,
        policyBody: Data,
        policyBinding: Data,
    ) async throws -> Data {
        guard var privateKeyData = await keyStore.getPrivateKey(forPublicKey: kasPublicKey) else {
            throw KASServiceError.keyNotFound
        }
        defer { privateKeyData.secureZero() }

        let (rewrappedKey, _) = try await rewrapKeyInternal(
            ephemeralPublicKey: ephemeralPublicKey,
            encryptedKey: encryptedKey,
            privateKeyData: privateKeyData,
            policyBody: policyBody,
            policyBinding: policyBinding,
        )

        return rewrappedKey
    }

    /// Process key access request locally without policy binding verification.
    @available(*, deprecated, message: "Use processKeyAccess(ephemeralPublicKey:encryptedKey:kasPublicKey:policyBody:policyBinding:) or processKeyAccess(header:encryptedKey:kasPublicKey:) to enforce policy binding verification.")
    public func processKeyAccess(
        ephemeralPublicKey: Data,
        encryptedKey: Data,
        kasPublicKey: Data,
    ) async throws -> Data {
        guard var privateKeyData = await keyStore.getPrivateKey(forPublicKey: kasPublicKey) else {
            throw KASServiceError.keyNotFound
        }
        defer { privateKeyData.secureZero() }

        let (rewrappedKey, _) = try await rewrapKeyInternal(
            ephemeralPublicKey: ephemeralPublicKey,
            encryptedKey: encryptedKey,
            privateKeyData: privateKeyData,
        )

        return rewrappedKey
    }

    /// Process a NanoTDF key access request locally, resolving v12 headers (which omit `kasPublicKey`
    /// on the wire) and always verifying the header's policy binding before rewrapping.
    public func processKeyAccess(
        header: Header,
        encryptedKey: Data,
        kasPublicKey: Data? = nil,
    ) async throws -> Data {
        guard let resolved = await keyStore.resolveKeyPair(for: header, explicitPublicKey: kasPublicKey) else {
            throw KASServiceError.keyNotFound
        }
        var privateKeyData = resolved.privateKey
        defer { privateKeyData.secureZero() }

        let symmetricKey = try keyStore.derivePayloadSymmetricKey(
            kasPrivateKeyData: privateKeyData,
            tdfEphemeralPublicKey: header.ephemeralPublicKey,
        )
        do {
            try header.verifyPolicyBinding(symmetricKey: symmetricKey)
        } catch {
            throw KASServiceError.accessDenied
        }
        let (rewrappedKey, _) = try await rewrapKeyInternal(
            ephemeralPublicKey: header.ephemeralPublicKey,
            encryptedKey: encryptedKey,
            privateKeyData: privateKeyData,
            precomputedPrimaryKey: symmetricKey,
        )
        return rewrappedKey
    }

    /// Verify whether a policy binding is valid
    /// - Parameters:
    ///   - policyBinding: The policy binding data to verify
    ///   - policyData: The policy data that was bound
    ///   - symmetricKey: The symmetric key used for verification
    /// - Returns: True if binding is valid, false otherwise
    public func verifyPolicyBinding(
        policyBinding: Data,
        policyData: Data,
        symmetricKey: SymmetricKey,
    ) async throws -> Bool {
        // For GMAC binding verification, create a tag with empty ciphertext and the policy data as authenticated data.
        // Use the same deterministic zero nonce that createGMACBinding uses so the tag can be reproduced.
        let nonce = try AES.GCM.Nonce(data: Data(count: 12))
        let fullTag = try AES.GCM.seal(Data(), using: symmetricKey, nonce: nonce, authenticating: policyData).tag
        guard policyBinding.count == 8 || policyBinding.count == fullTag.count else {
            return false
        }
        let expectedTag = Data(fullTag.prefix(policyBinding.count))
        return CryptoHelper.constantTimeEquals(policyBinding, expectedTag)
    }

    /// Atomically processes a one-time key access request, verifies the policy binding,
    /// and reports a deterministic RFC 9562 v8 UUID derived from `kasPublicKey`.
    /// Restores the key to the store if validation or decryption fails so malformed
    /// requests cannot permanently consume a one-time key.
    public func processKeyAccessWithKeyIdentifier(
        ephemeralPublicKey: Data,
        encryptedKey: Data,
        kasPublicKey: Data,
        policyBody: Data,
        policyBinding: Data,
    ) async throws -> (rewrappedKey: Data, keyID: UUID) {
        try await processKeyAccessWithKeyIdentifierInternal(
            ephemeralPublicKey: ephemeralPublicKey,
            encryptedKey: encryptedKey,
            kasPublicKey: kasPublicKey,
            policyBody: policyBody,
            policyBinding: policyBinding,
        )
    }

    /// Atomically processes a one-time key access request without policy binding verification.
    @available(*, deprecated, message: "Use processKeyAccessWithKeyIdentifier(ephemeralPublicKey:encryptedKey:kasPublicKey:policyBody:policyBinding:) to enforce policy binding verification.")
    public func processKeyAccessWithKeyIdentifier(
        ephemeralPublicKey: Data,
        encryptedKey: Data,
        kasPublicKey: Data,
    ) async throws -> (rewrappedKey: Data, keyID: UUID) {
        try await processKeyAccessWithKeyIdentifierInternal(
            ephemeralPublicKey: ephemeralPublicKey,
            encryptedKey: encryptedKey,
            kasPublicKey: kasPublicKey,
            policyBody: nil,
            policyBinding: nil,
        )
    }

    private func processKeyAccessWithKeyIdentifierInternal(
        ephemeralPublicKey: Data,
        encryptedKey: Data,
        kasPublicKey: Data,
        policyBody: Data?,
        policyBinding: Data?,
    ) async throws -> (rewrappedKey: Data, keyID: UUID) {
        // Peek first so malformed/unauthorized requests neither consume the one-time key
        // nor open a transient `keyNotFound` window for concurrent legitimate callers.
        guard var privateKeyData = await keyStore.getPrivateKey(forPublicKey: kasPublicKey) else {
            throw KASServiceError.keyNotFound
        }
        defer { privateKeyData.secureZero() }

        let (rewrappedKey, _) = try await rewrapKeyInternal(
            ephemeralPublicKey: ephemeralPublicKey,
            encryptedKey: encryptedKey,
            privateKeyData: privateKeyData,
            policyBody: policyBody,
            policyBinding: policyBinding,
        )

        // Atomically commit one-time consumption; if another valid caller won the race, fail.
        guard var consumedKey = await keyStore.popPrivateKey(forPublicKey: kasPublicKey) else {
            throw KASServiceError.keyNotFound
        }
        consumedKey.secureZero()

        let keyID = Self.deterministicUUID(for: kasPublicKey)
        return (rewrappedKey: rewrappedKey, keyID: keyID)
    }

    /// Derives a deterministic RFC 9562 version 8 (custom SHA-256) UUID from the KAS public key bytes.
    private static func deterministicUUID(for publicKey: Data) -> UUID {
        var digest = Array(SHA256.hash(data: publicKey).prefix(16))
        digest[6] = (digest[6] & 0x0F) | 0x80 // RFC 9562 version 8 marker
        digest[8] = (digest[8] & 0x3F) | 0x80 // RFC 4122/9562 variant
        return UUID(uuid: (
            digest[0], digest[1], digest[2], digest[3],
            digest[4], digest[5], digest[6], digest[7],
            digest[8], digest[9], digest[10], digest[11],
            digest[12], digest[13], digest[14], digest[15],
        ))
    }
}
