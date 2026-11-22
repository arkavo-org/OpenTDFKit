import CryptoKit
import Foundation

// MARK: - Policy Configuration

/// Policy configuration options for NanoTDF Collection builder
public enum CollectionPolicyConfiguration: Sendable {
    /// Remote policy referenced by URL
    case remote(ResourceLocator)
    /// Plaintext policy embedded in the header
    case embeddedPlaintext(Data)
    /// Encrypted policy embedded in the header
    case embeddedEncrypted(Data)
    /// Encrypted policy with separate key access
    case embeddedEncryptedWithKeyAccess(Data, PolicyKeyAccess)
}

// MARK: - Builder

/// Fluent builder for constructing NanoTDFCollection instances.
///
/// Performs single ECDH + HKDF derivation per collection for efficiency.
///
/// - Important: NanoTDF is deprecated. Use ``TDFCBORBuilder`` instead.
///   See the migration guide at `docs/NANOTDF_MIGRATION.md` for details.
///
/// ## Example Usage
/// ```swift
/// let collection = try await NanoTDFCollectionBuilder()
///     .kasMetadata(kasMetadata)
///     .policy(.embeddedPlaintext(policyData))
///     .configuration(.default)
///     .build()
/// ```
@available(*, deprecated, message: "NanoTDF is deprecated. Use TDFCBORBuilder instead. See docs/NANOTDF_MIGRATION.md")
public struct NanoTDFCollectionBuilder: Sendable {
    private var kasMetadata: KasMetadata?
    private var policyConfig: CollectionPolicyConfiguration?
    private var configuration: CollectionConfiguration = .default

    public init() {}

    // MARK: - Fluent API

    /// Sets the KAS metadata for key derivation
    /// - Parameter metadata: The KAS metadata containing public key and endpoint
    /// - Returns: Self for method chaining
    public func kasMetadata(_ metadata: KasMetadata) -> NanoTDFCollectionBuilder {
        var copy = self
        copy.kasMetadata = metadata
        return copy
    }

    /// Configures the policy for this collection
    /// - Parameter policy: The policy configuration
    /// - Returns: Self for method chaining
    public func policy(_ policy: CollectionPolicyConfiguration) -> NanoTDFCollectionBuilder {
        var copy = self
        copy.policyConfig = policy
        return copy
    }

    /// Sets the collection configuration
    /// - Parameter config: The collection configuration
    /// - Returns: Self for method chaining
    public func configuration(_ config: CollectionConfiguration) -> NanoTDFCollectionBuilder {
        var copy = self
        copy.configuration = config
        return copy
    }

    /// Sets a custom rotation threshold
    /// - Parameter threshold: The IV count at which rotation is recommended
    /// - Returns: Self for method chaining
    public func rotationThreshold(_ threshold: UInt32) -> NanoTDFCollectionBuilder {
        var copy = self
        copy.configuration = CollectionConfiguration(
            rotationThreshold: threshold,
            wireFormat: configuration.wireFormat,
            cipher: configuration.cipher,
        )
        return copy
    }

    /// Sets the wire format for serialization
    /// - Parameter format: The wire format to use
    /// - Returns: Self for method chaining
    public func wireFormat(_ format: CollectionWireFormat) -> NanoTDFCollectionBuilder {
        var copy = self
        copy.configuration = CollectionConfiguration(
            rotationThreshold: configuration.rotationThreshold,
            wireFormat: format,
            cipher: configuration.cipher,
        )
        return copy
    }

    /// Sets the cipher for payload encryption
    /// - Parameter cipher: The cipher to use
    /// - Returns: Self for method chaining
    public func cipher(_ cipher: Cipher) -> NanoTDFCollectionBuilder {
        var copy = self
        copy.configuration = CollectionConfiguration(
            rotationThreshold: configuration.rotationThreshold,
            wireFormat: configuration.wireFormat,
            cipher: cipher,
        )
        return copy
    }

    // MARK: - Build

    /// Builds the NanoTDFCollection with configured options.
    /// Performs single ECDH + HKDF derivation for the collection.
    ///
    /// - Returns: A configured NanoTDFCollection ready for encryption
    /// - Throws: `NanoTDFCollectionError` if required configuration is missing or key derivation fails
    public func build() async throws -> NanoTDFCollection {
        // Validate required configuration
        guard let kas = kasMetadata else {
            throw NanoTDFCollectionError.missingKASMetadata
        }
        guard let policyConfig else {
            throw NanoTDFCollectionError.missingPolicy
        }

        let cryptoHelper = NanoTDF.sharedCryptoHelper

        // Step 1: Generate ephemeral key pair (expensive - ~50us)
        guard let keyPair = cryptoHelper.generateEphemeralKeyPair(curveType: kas.curve) else {
            throw NanoTDFCollectionError.keyDerivationFailed("Failed to generate ephemeral key pair")
        }

        // Step 2: Derive shared secret via ECDH (expensive - ~100us)
        let kasPublicKey = try kas.getPublicKey()
        guard let sharedSecret = try cryptoHelper.deriveSharedSecret(
            keyPair: keyPair,
            recipientPublicKey: kasPublicKey,
        ) else {
            throw NanoTDFCollectionError.keyDerivationFailed("Failed to derive shared secret")
        }

        // Step 3: Derive symmetric key via HKDF (moderate - ~10us)
        // Use v12 salt for KAS compatibility (L1L format)
        let salt = CryptoHelper.computeHKDFSalt(version: Header.versionV12)
        let symmetricKey = cryptoHelper.deriveSymmetricKey(
            sharedSecret: sharedSecret,
            salt: salt,
            info: Data(),
            outputByteCount: 32,
        )

        // Step 4: Build policy (encrypting embedded encrypted policies) and compute binding
        // over the serialized policy body (matching createNanoTDF and Header.verifyPolicyBinding).
        var (policy, policyBody) = try buildPolicy(
            from: policyConfig,
            kas: kas,
            kasPublicKey: kasPublicKey,
            symmetricKey: symmetricKey,
            salt: salt,
            cryptoHelper: cryptoHelper,
        )

        // Create GMAC policy binding
        let binding = try cryptoHelper.createGMACBinding(
            policyBody: policyBody,
            symmetricKey: symmetricKey,
        )
        policy.binding = binding

        // Step 5: Build header with KAS public key for KeyStore-based decryption
        let payloadKeyAccess = PayloadKeyAccess(
            kasEndpointLocator: kas.resourceLocator,
            kasPublicKey: kasPublicKey, // Include KAS public key for KeyStore lookup
        )

        let header = Header(
            payloadKeyAccess: payloadKeyAccess,
            policyBindingConfig: PolicyBindingConfig(
                ecdsaBinding: false,
                curve: kas.curve,
            ),
            payloadSignatureConfig: SignatureAndPayloadConfig(
                signed: false,
                signatureCurve: kas.curve,
                payloadCipher: configuration.cipher,
            ),
            policy: policy,
            ephemeralPublicKey: keyPair.publicKey,
        )

        // Step 6: Create and return the collection
        return NanoTDFCollection(
            header: header,
            symmetricKey: symmetricKey,
            configuration: configuration,
        )
    }

    // MARK: - Private Helpers

    private func buildPolicy(
        from config: CollectionPolicyConfiguration,
        kas: KasMetadata,
        kasPublicKey: Data,
        symmetricKey: SymmetricKey,
        salt: Data,
        cryptoHelper: CryptoHelper,
    ) throws -> (policy: Policy, serializedBody: Data) {
        switch config {
        case let .remote(locator):
            let policy = Policy(
                type: .remote,
                body: nil,
                remote: locator,
                binding: nil,
            )
            return (policy, locator.toData())

        case let .embeddedPlaintext(data):
            let body = EmbeddedPolicyBody(body: data, keyAccess: nil)
            let serialized = try body.serializedData()
            let policy = Policy(
                type: .embeddedPlaintext,
                body: body,
                remote: nil,
                binding: nil,
            )
            return (policy, serialized)

        case let .embeddedEncrypted(data):
            // Encrypt policy using domain-separated key derived from symmetricKey and append 16-byte GCM tag.
            let encryptedData = try CryptoHelper.encryptEmbeddedPolicy(
                plaintext: data,
                using: symmetricKey,
            )
            let body = EmbeddedPolicyBody(body: encryptedData, keyAccess: nil)
            let serialized = try body.serializedData()
            let policy = Policy(
                type: .embeddedEncrypted,
                body: body,
                remote: nil,
                binding: nil,
            )
            return (policy, serialized)

        case let .embeddedEncryptedWithKeyAccess(data, keyAccess):
            guard let policyEphemeralKeyPair = cryptoHelper.generateEphemeralKeyPair(curveType: kas.curve) else {
                throw NanoTDFCollectionError.keyDerivationFailed("Failed to generate policy ephemeral key pair")
            }
            guard let policySharedSecret = try cryptoHelper.deriveSharedSecret(
                keyPair: policyEphemeralKeyPair,
                recipientPublicKey: kasPublicKey,
            ) else {
                throw NanoTDFCollectionError.keyDerivationFailed("Failed to derive policy shared secret")
            }
            let policySymmetricKey = cryptoHelper.deriveSymmetricKey(
                sharedSecret: policySharedSecret,
                salt: salt,
                info: Data(),
                outputByteCount: 32,
            )
            let adjustedIV = cryptoHelper.adjustNonce(Data([0, 0, 0]), to: 12)
            let (ciphertext, tag) = try cryptoHelper.encryptPayload(
                plaintext: data,
                symmetricKey: policySymmetricKey,
                nonce: adjustedIV,
            )
            var authenticatedCiphertext = Data(capacity: ciphertext.count + tag.count)
            authenticatedCiphertext.append(ciphertext)
            authenticatedCiphertext.append(tag)

            let updatedKeyAccess = PolicyKeyAccess(
                resourceLocator: keyAccess.resourceLocator,
                ephemeralPublicKey: policyEphemeralKeyPair.publicKey,
            )
            let body = EmbeddedPolicyBody(body: authenticatedCiphertext, keyAccess: updatedKeyAccess)
            let serialized = try body.serializedData()
            let policy = Policy(
                type: .embeddedEncryptedWithPolicyKeyAccess,
                body: body,
                remote: nil,
                binding: nil,
            )
            return (policy, serialized)
        }
    }
}
