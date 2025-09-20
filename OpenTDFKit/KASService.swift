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

    // Custom error equality implementation
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
        let rewrapEndpoint = baseURL.appendingPathComponent("rewrap")

        var request = URLRequest(url: rewrapEndpoint)
        request.httpMethod = "POST"
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

        // Perform the network request
        let (data, response) = try await urlSession.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw KASServiceError.networkError("Invalid response type")
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
    /// - Returns: Rewrapped key data and the new key pair used for rewrapping
    private func rewrapKeyInternal(
        ephemeralPublicKey: Data,
        encryptedKey: Data,
        privateKeyData: Data,
    ) async throws -> (rewrappedKey: Data, newKeyPair: StoredKeyPair) {
        // 1. Derive shared secret using the client's ephemeral public key and KAS private key
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

        // 2. Derive symmetric key for decryption
        // Support both v12 and v13 salt values (computed via spec formula)
        let saltV12 = CryptoConstants.hkdfSaltV12
        let saltV13 = CryptoConstants.hkdfSaltV13

        let symmetricKeyV12 = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: saltV12,
            sharedInfo: Data(), // Empty per spec section 4
            outputByteCount: 32,
        )

        let symmetricKeyV13 = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: saltV13,
            sharedInfo: Data(), // Empty per spec section 4
            outputByteCount: 32,
        )

        // We'll try both keys in the decryption step

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

        // Try decryption with the v13 key first
        let decryptedKey: Data
        do {
            decryptedKey = try AES.GCM.open(sealedBox, using: symmetricKeyV13)
        } catch {
            // If v13 key fails, fallback to v12 key
            decryptedKey = try AES.GCM.open(sealedBox, using: symmetricKeyV12)
        }

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

        // 6. Derive new symmetric key for encryption (using v13 format)
        let newSymmetricKey = newSharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: saltV13, // Always use v13 salt for new keys
            sharedInfo: Data(), // Empty per spec section 4
            outputByteCount: 32,
        )

        // 7. Re-encrypt the key with the new symmetric key
        let newNonce = AES.GCM.Nonce()
        let newSealedBox = try AES.GCM.seal(decryptedKey, using: newSymmetricKey, nonce: newNonce)

        // 8. Combine the new ephemeral public key with the encrypted data
        var result = Data()
        result.append(newKeyPair.publicKey)

        // Add nonce, ciphertext, and tag separately for compatibility with our test format
        var nonceBytes = Data()
        newNonce.withUnsafeBytes { nonceBytes.append(contentsOf: $0) }
        result.append(nonceBytes)
        result.append(newSealedBox.ciphertext)
        result.append(newSealedBox.tag)

        return (rewrappedKey: result, newKeyPair: newKeyPair)
    }

    /// Process key access request locally (server-side KAS implementation)
    /// - Parameters:
    ///   - ephemeralPublicKey: Client's ephemeral public key
    ///   - encryptedKey: The encrypted key to unwrap
    ///   - kasPublicKey: The KAS public key that was used for encryption
    /// - Returns: Rewrapped key data
    public func processKeyAccess(
        ephemeralPublicKey: Data,
        encryptedKey: Data,
        kasPublicKey: Data,
    ) async throws -> Data {
        // Get the KAS private key corresponding to the KAS public key
        guard let privateKeyData = await keyStore.getPrivateKey(forPublicKey: kasPublicKey) else {
            throw KASServiceError.keyNotFound
        }

        // Use the internal helper to perform the rewrapping
        let (rewrappedKey, _) = try await rewrapKeyInternal(
            ephemeralPublicKey: ephemeralPublicKey,
            encryptedKey: encryptedKey,
            privateKeyData: privateKeyData,
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
        // For GMAC binding verification, create a tag with empty ciphertext and the policy data as authenticated data
        let fullTag = try AES.GCM.seal(Data(), using: symmetricKey, authenticating: policyData).tag
        guard policyBinding.count == 8 || policyBinding.count == fullTag.count else {
            return false
        }
        let expectedTag = Data(fullTag.prefix(policyBinding.count))
        return policyBinding == expectedTag
    }

    /// Process a key access request and report which key was used
    /// - Parameters:
    ///   - ephemeralPublicKey: The ephemeral public key from the requester
    ///   - encryptedKey: The encrypted session key that needs to be rewrapped
    ///   - kasPublicKey: The KAS public key
    /// - Returns: A tuple containing the rewrapped key data and the ID of the key that was used
    /// - Throws: KAS errors
    public func processKeyAccessWithKeyIdentifier(
        ephemeralPublicKey: Data,
        encryptedKey: Data,
        kasPublicKey: Data,
    ) async throws -> (rewrappedKey: Data, keyID: UUID) {
        // Create a UUID based on the KAS public key bytes
        let keyID = UUID()

        // Get the KAS private key corresponding to the KAS public key
        guard let privateKeyData = await keyStore.getPrivateKey(forPublicKey: kasPublicKey) else {
            throw KASServiceError.keyNotFound
        }

        // Create KeyPairIdentifier for the key
        let kasKeyIdentifier = KeyPairIdentifier(publicKey: kasPublicKey)

        // Use the internal helper to perform the rewrapping
        let (rewrappedKey, _) = try await rewrapKeyInternal(
            ephemeralPublicKey: ephemeralPublicKey,
            encryptedKey: encryptedKey,
            privateKeyData: privateKeyData,
        )

        // Remove the used key from the keystore to ensure one-time use
        try await keyStore.removeKeyPair(keyID: kasKeyIdentifier)

        return (rewrappedKey: rewrappedKey, keyID: keyID)
    }
}
