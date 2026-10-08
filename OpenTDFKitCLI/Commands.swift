import CryptoKit
import Darwin
import Foundation
import OpenTDFKit

extension Data {
    func hexEncodedString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}

struct CLIConfig {
    let kasURL: String
    let platformURL: String
    /// Optional: NanoTDF commands authenticate with a bearer token
    /// (`TDF_OAUTH_TOKEN` / `OAUTH_TOKEN` / token file), so client credentials
    /// are only needed by callers that run a client-credentials grant.
    let clientID: String?
    let clientSecret: String?
    let withECDSABinding: Bool
    let withPlaintextPolicy: Bool

    static func fromEnvironment() throws -> CLIConfig {
        let env = ProcessInfo.processInfo.environment
        guard let kasURL = env["KASURL"] else {
            throw CLIConfigError.missingEnvironmentVariable("KASURL")
        }
        guard let platformURL = env["PLATFORMURL"] else {
            throw CLIConfigError.missingEnvironmentVariable("PLATFORMURL")
        }

        return CLIConfig(
            kasURL: kasURL,
            platformURL: platformURL,
            clientID: env["CLIENTID"],
            clientSecret: env["CLIENTSECRET"],
            withECDSABinding: env["XT_WITH_ECDSA_BINDING"] == "true",
            withPlaintextPolicy: env["XT_WITH_PLAINTEXT_POLICY"] == "true",
        )
    }
}

enum CLIConfigError: Error, CustomStringConvertible {
    case missingEnvironmentVariable(String)

    var description: String {
        switch self {
        case let .missingEnvironmentVariable(name):
            "Required environment variable '\(name)' is not set. Please export it before running."
        }
    }
}

enum Commands {
    /// Quick signature check to route files to the appropriate parser.
    static func isLikelyArchiveTDF(data: Data) -> Bool {
        data.starts(with: [0x50, 0x4B])
    }

    static func resolveOAuthToken(providedToken: String?, tokenPath: String) throws -> String {
        if let providedToken, !providedToken.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return providedToken.trimmingCharacters(in: .whitespacesAndNewlines)
        }

        let tokenURL = URL(fileURLWithPath: tokenPath)
        guard FileManager.default.fileExists(atPath: tokenURL.path) else {
            throw DecryptError.missingOAuthToken
        }

        let tokenData = try Data(contentsOf: tokenURL)
        let oauthToken = String(data: tokenData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        guard !oauthToken.isEmpty else {
            throw DecryptError.missingOAuthToken
        }

        return oauthToken
    }

    /// Resolve the bearer token for NanoTDF commands from the environment.
    ///
    /// Token: `providedToken`, else `TDF_OAUTH_TOKEN`, else `OAUTH_TOKEN`.
    /// File (when no token value is set): `tokenPath`, else `TDF_OAUTH_TOKEN_PATH`,
    /// else `OAUTH_TOKEN_PATH`, else `fresh_token.txt`. Mirrors the Standard TDF
    /// decrypt token lookup; the token is treated as opaque (JWT or CWT).
    static func resolveEnvironmentOAuthToken(providedToken: String? = nil, tokenPath: String? = nil) throws -> String {
        let env = ProcessInfo.processInfo.environment
        func nonEmpty(_ value: String?) -> String? {
            guard let value, !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                return nil
            }
            return value
        }
        let token = nonEmpty(providedToken) ?? nonEmpty(env["TDF_OAUTH_TOKEN"]) ?? nonEmpty(env["OAUTH_TOKEN"])
        let path = nonEmpty(tokenPath)
            ?? nonEmpty(env["TDF_OAUTH_TOKEN_PATH"])
            ?? nonEmpty(env["OAUTH_TOKEN_PATH"])
            ?? "fresh_token.txt"
        return try resolveOAuthToken(providedToken: token, tokenPath: path)
    }

    /// Build the NanoTDF KAS resource-locator body (`host[:port]`) from `KASURL`.
    /// The port is included only when `KASURL` names one explicitly, so
    /// `http://localhost:8080/kas` → `localhost:8080` and
    /// `https://platform.example.com/kas` → `platform.example.com`.
    static func nanoKasLocatorBody(kasURL: URL) -> String? {
        guard let host = kasURL.host, !host.isEmpty else {
            return nil
        }
        if let port = kasURL.port {
            return "\(host):\(port)"
        }
        return host
    }

    /// NanoTDF resource-locator protocol for a KAS URL scheme (`https` or `http`).
    static func nanoProtocol(forScheme scheme: String?) -> ProtocolEnum {
        scheme?.lowercased() == "https" ? .https : .http
    }

    /// KAS key identifier for the NanoTDF locator: the KAS-reported `kid` when it
    /// fits a locator identifier (2, 8, or 32 bytes), else `nil`.
    static func nanoKasIdentifier(kid: String?) -> Data? {
        guard let kid else {
            return nil
        }
        let data = Data(kid.utf8)
        return [2, 8, 32].contains(data.count) ? data : nil
    }

    /// Rebuild the KAS URL (`scheme://body[/kas]`) from a NanoTDF header locator.
    /// The scheme follows the locator protocol; a body without a `/kas` path
    /// (this CLI's `host[:port]` form) gets `/kas` appended.
    static func nanoKasURL(from locator: ResourceLocator) -> URL? {
        let scheme = locator.protocolEnum == .https ? "https" : "http"
        let body = locator.body
        let urlString = body.contains("/kas") ? "\(scheme)://\(body)" : "\(scheme)://\(body)/kas"
        return URL(string: urlString)
    }

    /// Parse and report details about a ZIP-based TDF container.
    static func verifyTDF(data: Data, filename: String) throws {
        print("Standard TDF Verification Report")
        print("================================")
        print("File: \(filename)")
        print("Size: \(data.count) bytes\n")

        let loader = TDFLoader()
        let container = try loader.load(from: data)
        let manifest = container.manifest

        print("✓ Manifest parsed successfully")
        print("  Spec Version: \(manifest.effectiveSpecVersion ?? "unknown")")
        print("  Payload URL: \(manifest.payload.url)")
        print("  Payload Protocol: \(manifest.payload.protocolValue.rawValue)")
        print("  Encrypted: \(manifest.payload.isEncrypted)")

        let enc = manifest.encryptionInformation
        print("\nEncryption Information:")
        print("  Type: \(enc.type.rawValue)")
        print("  Key Access Objects: \(enc.keyAccess.count)")
        print("  Symmetric Algorithm: \(enc.method.algorithm)")

        if let integrity = enc.integrityInformation {
            print("\nIntegrity Information:")
            print("  Segment Hash Alg: \(integrity.segmentHashAlg)")
            print("  Default Segment Size: \(integrity.segmentSizeDefault)")
            print("  Segments: \(integrity.segments.count)")
        } else {
            print("\nIntegrity Information: None")
        }

        if let assertions = manifest.assertions {
            print("\nAssertions: \(assertions.count)")
        }

        print("\n✓ Standard TDF structure validated")
    }

    /// Load a ZIP-based TDF container and decrypt payload.
    ///
    /// Stage-1 KAS path (preferred when no offline symmetric key):
    /// 1. Client-credentials OAuth (caller supplies token)
    /// 2. `rewrapAndUnwrapTDF` per KAS: ephemeral P-256 session keypair, rewrap,
    ///    and EC session unwrap with the Standard TDF salt (`SHA256("TDF")`, not
    ///    the Nano default) — all owned by the library.
    ///
    /// Offline shortcuts: `symmetricKey`, or legacy RSA `privateKeyPEM` to unwrap
    /// the raw rewrap response (which therefore runs `rewrapTDF` directly).
    static func decryptTDF(
        data: Data,
        filename: String,
        symmetricKey: SymmetricKey?,
        privateKeyPEM: String?,
        oauthToken: String?,
    ) async throws -> Data {
        print("Standard TDF Decryption")
        print("========================")
        print("File: \(filename)")
        print("Size: \(data.count) bytes\n")

        let loader = TDFLoader()
        let container = try loader.load(from: data)

        print("✓ Manifest loaded")
        print("  Spec Version: \(container.manifest.effectiveSpecVersion ?? "unknown")")
        print("  Key Access Entries: \(container.manifest.encryptionInformation.keyAccess.count)")

        let decryptor = TDFDecryptor()

        if let symmetricKey {
            print("  Using provided symmetric key for decryption")
            return try decryptor.decrypt(container: container, symmetricKey: symmetricKey)
        }

        guard let oauthToken, !oauthToken.isEmpty else {
            throw DecryptError.missingOAuthToken
        }

        print("  Requesting rewrap from KAS (ephemeral P-256 session key)")

        // Shares tagged with their split ID; combined per OpenTDF split semantics
        // (same sid = alternatives, distinct sids XORed).
        var keyShares: [TDFKeyShare] = []
        let keyAccess = container.manifest.encryptionInformation.keyAccess
        var kasURLs: [String] = []
        for kao in keyAccess where !kasURLs.contains(kao.url) {
            kasURLs.append(kao.url)
        }

        for kasURLString in kasURLs {
            guard let kasURL = URL(string: kasURLString) else {
                continue
            }

            let configuration = await resolveConfiguration(kasURL: kasURL, token: oauthToken)
            let client = try KASRewrapClient(configuration: configuration, oauthToken: oauthToken)

            guard let privateKeyPEM else {
                // Stage-1 path: the library generates the ephemeral key, rewraps, and
                // unwraps with go `tdfSalt()` = SHA256("TDF").
                try await keyShares.append(contentsOf: client.rewrapAndUnwrapTDFShares(manifest: container.manifest))
                continue
            }

            // A legacy RSA client key needs the raw wrapped bytes, so run the rewrap
            // here; the EC session unwrap is still preferred when the KAS offers one.
            let entries = keyAccess.filter { $0.url == kasURLString }
            let ephemeralPrivateKey = P256.KeyAgreement.PrivateKey()
            let result = try await client.rewrapTDF(
                manifest: container.manifest,
                clientPrivateKey: ephemeralPrivateKey,
            )
            let sessionKey = try result.sessionPublicKeyPEM.flatMap { pem in
                pem.isEmpty ? nil : try KASRewrapClient.validateEcPublicKeyPEM(pem).0
            }
            if sessionKey == nil {
                print("  Falling back to RSA private-key unwrap of rewrap response")
            }

            for (objectID, wrappedKeyData) in result.wrappedKeys.sorted(by: { $0.key < $1.key }) {
                // Request ids are `kao-<index into this KAS's entries>`.
                let index = Int(objectID.dropFirst("kao-".count))
                let sid = index.flatMap { entries.indices.contains($0) ? entries[$0].sid : nil }
                let share: SymmetricKey = if let sessionKey {
                    try KASRewrapClient.unwrapKey(
                        wrappedKey: wrappedKeyData,
                        sessionPublicKey: sessionKey,
                        clientPrivateKey: ephemeralPrivateKey.rawRepresentation,
                        salt: KASRewrapClient.standardTDFSessionSalt,
                    )
                } else {
                    try TDFCrypto.unwrapSymmetricKeyWithRSA(
                        privateKeyPEM: privateKeyPEM,
                        wrappedKey: wrappedKeyData.base64EncodedString(),
                    )
                }
                keyShares.append(TDFKeyShare(sid: sid, key: share))
            }
        }

        guard !keyShares.isEmpty else {
            throw DecryptError.missingWrappedKey
        }

        let dek = try TDFDecryptor.combineKeyShares(keyShares.map { share in
            (sid: share.sid, unwrap: { TDFCrypto.data(from: share.key) })
        })
        return try decryptor.decrypt(container: container, symmetricKey: SymmetricKey(data: dek))
    }

    /// Acquire an OAuth access token via client_credentials.
    ///
    /// Resolution order for token URL:
    /// 1. `TOKENENDPOINT` env
    /// 2. `KCFULLURL` + `/protocol/openid-connect/token`
    /// 3. `platformURL` + `/token` (local platform convenience)
    ///
    /// Loopback hosts are normalized to `127.0.0.1` so the JWT `iss` claim
    /// matches platform `server.auth.issuer` (CI often sets issuer to
    /// `http://127.0.0.1:8888/...` while test.env still says `localhost`).
    static func getOAuthToken(
        platformURL: String,
        clientID: String,
        clientSecret: String,
    ) async throws -> String {
        let env = ProcessInfo.processInfo.environment
        let rawTokenURL: String = if let explicit = env["TOKENENDPOINT"], !explicit.isEmpty {
            explicit
        } else if let kc = env["KCFULLURL"], !kc.isEmpty {
            kc.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                + "/protocol/openid-connect/token"
        } else {
            platformURL.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + "/token"
        }
        let tokenURLString = normalizeLoopbackHost(rawTokenURL)

        guard let tokenURL = URL(string: tokenURLString) else {
            throw DecryptError.missingOAuthToken
        }

        var request = URLRequest(url: tokenURL)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        // application/x-www-form-urlencoded: encode as form fields (not query allow-list).
        let body =
            "grant_type=client_credentials&client_id=\(formURLEncode(clientID))&client_secret=\(formURLEncode(clientSecret))"
        request.httpBody = body.data(using: .utf8)

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            let status = (response as? HTTPURLResponse)?.statusCode ?? -1
            let detail = String(data: data, encoding: .utf8) ?? ""
            throw NSError(
                domain: "OpenTDFKitCLI",
                code: status,
                userInfo: [NSLocalizedDescriptionKey:
                    "OAuth token request failed (HTTP \(status)) at \(tokenURLString): \(detail)"],
            )
        }
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        guard let token = json?["access_token"] as? String, !token.isEmpty else {
            throw DecryptError.missingOAuthToken
        }
        return token
    }

    /// Rewrite `localhost` → `127.0.0.1` in URLs so OIDC `iss` matches platform issuer.
    static func normalizeLoopbackHost(_ urlString: String) -> String {
        var s = urlString
        s = s.replacingOccurrences(of: "://localhost:", with: "://127.0.0.1:")
        s = s.replacingOccurrences(of: "://localhost/", with: "://127.0.0.1/")
        if s.hasSuffix("://localhost") {
            s = s.replacingOccurrences(of: "://localhost", with: "://127.0.0.1")
        }
        return s
    }

    /// Form-urlencoded encoding for OAuth token POST bodies.
    private static func formURLEncode(_ value: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }

    /// Fetch RSA public key PEM (+ optional kid) from KAS for Standard TDF wrap.
    static func fetchKASRSAPublicKey(
        kasURL: URL,
        platformURL: String?,
        token: String,
    ) async throws -> (pem: String, kid: String?) {
        // Prefer Connect PublicKey on platform root (strip trailing /kas).
        let base: URL = {
            if let platformURL, let u = URL(string: platformURL) {
                return u
            }
            var s = kasURL.absoluteString
            if s.hasSuffix("/kas") {
                s = String(s.dropLast(4))
            }
            return URL(string: s) ?? kasURL
        }()

        // Try Connect first: POST {base}/kas.AccessService/PublicKey
        if let connectURL = URL(string: base.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            + "/kas.AccessService/PublicKey")
        {
            var request = URLRequest(url: connectURL)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.setValue("1", forHTTPHeaderField: "Connect-Protocol-Version")
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            request.httpBody = try JSONSerialization.data(withJSONObject: ["algorithm": "rsa:2048"])
            if let (data, response) = try? await URLSession.shared.data(for: request),
               let http = response as? HTTPURLResponse,
               http.statusCode == 200,
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let pem = json["publicKey"] as? String ?? json["public_key"] as? String
            {
                let kid = json["kid"] as? String
                return (pem, kid)
            }
        }

        // Legacy REST: GET {platform}/kas/v2/kas_public_key
        let restBase = base.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        if let restURL = URL(string: restBase + "/kas/v2/kas_public_key") {
            var request = URLRequest(url: restURL)
            request.httpMethod = "GET"
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                throw NSError(
                    domain: "OpenTDFKitCLI",
                    code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Failed to fetch KAS RSA public key"],
                )
            }
            // try? so non-JSON bodies fall through to the raw-PEM fallback below.
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let pem = json["publicKey"] as? String ?? json["public_key"] as? String
            {
                return (pem, json["kid"] as? String)
            }
            // Some deployments return raw PEM
            if let pem = String(data: data, encoding: .utf8), pem.contains("BEGIN PUBLIC KEY") {
                return (pem, nil)
            }
        }

        throw NSError(
            domain: "OpenTDFKitCLI",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "Unable to fetch KAS RSA public key via Connect or REST"],
        )
    }

    /// Encrypt plaintext to NanoTDF v1.2 format (L1L) using OpenTDFKit's NanoTDF API
    static func encryptNanoTDF(plaintext: Data, useECDSA: Bool) async throws -> Data {
        print("NanoTDF Encryption")
        print("==================")
        print("Plaintext size: \(plaintext.count) bytes")
        print("ECDSA binding: \(useECDSA)")

        // Get configuration from environment
        let config = try CLIConfig.fromEnvironment()

        // Parse KAS URL. The NanoTDF ResourceLocator carries host[:port] only
        // (no path); the port is kept only when KASURL names one explicitly.
        guard let kasURL = URL(string: config.kasURL),
              let kasBody = nanoKasLocatorBody(kasURL: kasURL)
        else {
            throw EncryptError.invalidKASURL
        }

        // Bearer token for fetching the KAS public key (env or token file)
        let oauthToken = try resolveEnvironmentOAuthToken()

        // Fetch KAS public key (endpoints resolved from PLATFORMURL / KASURL)
        let kasKey = try await fetchKASPublicKey(kasURL: kasURL, token: oauthToken)
        print("✓ Retrieved KAS public key\(kasKey.kid.map { " (kid: \($0))" } ?? "")")

        // Create resource locator for KAS, matching the configured scheme. The
        // identifier is the KAS key id ("e1" when the KAS does not report one).
        guard let kasLocator = ResourceLocator(
            protocolEnum: nanoProtocol(forScheme: kasURL.scheme),
            body: kasBody,
            identifier: nanoKasIdentifier(kid: kasKey.kid ?? "e1"),
        ) else {
            throw EncryptError.invalidKASURL
        }

        // Convert compressed key data to CryptoKit public key
        let kasPublicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: kasKey.compressedKey)

        // Create KAS metadata with the public key
        let kasMetadata = try KasMetadata(
            resourceLocator: kasLocator,
            publicKey: kasPublicKey,
            curve: .secp256r1,
        )

        // Create policy with actual attributes
        var policy: Policy

        // Create a valid policy with no attributes (open access)
        let policyUUID = UUID().uuidString.lowercased()
        let policyJSON = """
        {
            "uuid": "\(policyUUID)",
            "body": {
                "dataAttributes": [],
                "dissem": []
            }
        }
        """
        let policyData = policyJSON.data(using: .utf8)!

        if config.withPlaintextPolicy {
            policy = Policy(
                type: .embeddedPlaintext,
                body: EmbeddedPolicyBody(body: policyData),
                remote: nil,
                binding: nil,
            )
        } else {
            policy = Policy(
                type: .embeddedEncrypted,
                body: EmbeddedPolicyBody(body: policyData),
                remote: nil,
                binding: nil,
            )
        }

        // Create v1.2 NanoTDF for otdfctl compatibility
        let nanoTDF = try await createNanoTDFv12(
            kas: kasMetadata,
            policy: &policy,
            plaintext: plaintext,
        )

        // Get the binary data
        let nanoTDFData = nanoTDF.toData()

        // Add ECDSA signature if requested
        // Note: This would require additional implementation

        print("✓ Created NanoTDF (\(nanoTDFData.count) bytes)")
        return nanoTDFData
    }

    /// Encrypt plaintext to Standard TDF using local configuration.
    static func encryptTDF(
        plaintext: Data,
        configuration: TDFEncryptionConfiguration,
    ) throws -> (result: TDFEncryptionResult, archiveData: Data) {
        print("Standard TDF Encryption")
        print("=======================")
        print("Plaintext size: \(plaintext.count) bytes")
        print("KAS URL: \(configuration.kas.url.absoluteString)")

        let encryptor = TDFEncryptor()
        let result = try encryptor.encrypt(
            plaintext: plaintext,
            configuration: configuration,
            segmentSize: StreamingTDFCrypto.defaultChunkSize,
        )
        let archiveData = try result.container.serializedData()

        print("✓ Created Standard TDF archive (\(archiveData.count) bytes)")
        print("  Key Access entries: \(result.container.manifest.encryptionInformation.keyAccess.count)")

        return (result, archiveData)
    }

    /// Resolve an OpenTDFConfiguration for the platform hosting `kasURL`.
    /// Tries well-known discovery at the platform root (PLATFORMURL env, else
    /// the scheme/host/port of `kasURL`). If well-known is missing **or**
    /// present without a usable `kas` block, fall back to synthesized Connect
    /// endpoints at the default KAS base. Connect paths live at the platform
    /// root, not under the KAS `/kas` identity path.
    static func resolveConfiguration(kasURL: URL, token _: String) async -> OpenTDFConfiguration {
        let platformBase: String
        if let env = ProcessInfo.processInfo.environment["PLATFORMURL"], !env.isEmpty {
            platformBase = env
        } else {
            var comps = URLComponents()
            comps.scheme = kasURL.scheme
            comps.host = kasURL.host
            comps.port = kasURL.port
            platformBase = comps.string ?? kasURL.absoluteString
        }
        let fallbackBase = defaultKasConnectBase(kasURL: kasURL, platformBase: platformBase)
        if let cfg = try? await fetchWellKnown(platformURL: platformBase) {
            // Incomplete well-known (e.g. IdP only, no kas) → keep IdP, fill kas.
            return cfg.withKasFallback(baseURL: fallbackBase)
        }
        return OpenTDFConfiguration.forKasConnect(fallbackBase)
    }

    /// Connect endpoints attach to the platform root. Prefer `PLATFORMURL`,
    /// then `KASURL`/`TDF_KAS_URL` with a trailing `/kas` stripped, then the
    /// scheme/host/port derived from the manifest `kasURL`.
    static func defaultKasConnectBase(kasURL: URL, platformBase: String) -> String {
        func stripKasPath(_ raw: String) -> String {
            var s = raw
            while s.hasSuffix("/") {
                s.removeLast()
            }
            if s.hasSuffix("/kas") {
                s = String(s.dropLast(4))
            }
            while s.hasSuffix("/") {
                s.removeLast()
            }
            return s
        }
        let env = ProcessInfo.processInfo.environment
        if let platform = env["PLATFORMURL"], !platform.isEmpty {
            return stripKasPath(platform)
        }
        if let kas = env["KASURL"] ?? env["TDF_KAS_URL"], !kas.isEmpty {
            return stripKasPath(kas)
        }
        return stripKasPath(platformBase.isEmpty ? kasURL.absoluteString : platformBase)
    }

    /// Fetch the KAS EC (P-256) public key and its key id, if the KAS reports one.
    static func fetchKASPublicKey(kasURL: URL, token: String) async throws -> (compressedKey: Data, kid: String?) {
        let configuration = await resolveConfiguration(kasURL: kasURL, token: token)
        let client = try KASRewrapClient(configuration: configuration, oauthToken: token)
        let result = try await client.fetchKasEcPublicKey(algorithm: .ecP256)
        return (result.compressedKey, result.kid)
    }

    /// Verify and parse a NanoTDF file using OpenTDFKit's parser
    static func verifyNanoTDF(data: Data, filename: String) throws {
        print("NanoTDF Verification Report")
        print("============================")
        print("File: \(filename)")
        print("Size: \(data.count) bytes\n")

        // Use OpenTDFKit's BinaryParser
        let parser = BinaryParser(data: data)

        // Parse the header
        let header: Header
        do {
            header = try parser.parseHeader()
            print("✓ Header parsed successfully")
        } catch {
            print("❌ Failed to parse header: \(error)")
            throw error
        }

        // Determine version from raw data
        let versionByte = data[2]
        let versionString = versionByte == 0x4C ? "1.2 (L1L)" : "1.3 (L1M)"
        print("  Version: \(versionString)")

        // Display what we can access
        print("\nKAS Information:")
        print("  URL: \(header.payloadKeyAccess.kasLocator.body)")
        if let identifier = header.payloadKeyAccess.kasLocator.identifier {
            print("  Identifier: \(String(data: identifier, encoding: .utf8) ?? identifier.hexEncodedString())")
        }
        if header.payloadKeyAccess.kasPublicKey.count > 0 {
            print("  KAS Public Key: \(header.payloadKeyAccess.kasPublicKey.count) bytes")
        }

        print("\nEphemeral Key:")
        print("  Length: \(header.ephemeralPublicKey.count) bytes")

        // Check for otdfctl's wrapped format
        if header.ephemeralPublicKey.count == 101 {
            print("  Format: otdfctl wrapped (68 bytes metadata + 33 bytes P-256 key)")
            print("  Note: otdfctl only supports secp256r1")
        } else {
            let curveName = switch header.ephemeralPublicKey.count {
            case 33: "secp256r1 (P-256)"
            case 49: "secp384r1 (P-384)"
            case 67: "secp521r1 (P-521)"
            default: "unknown"
            }
            print("  Detected curve: \(curveName)")
        }

        print("\nPolicy:")
        print("  Type: \(header.policy.type)")
        if let policyBody = header.policy.body {
            print("  Body size: \(policyBody.body.count) bytes")
        }

        // Try to parse payload
        print("\nPayload:")
        do {
            let payload = try parser.parsePayload(config: header.payloadSignatureConfig)
            print("  ✓ Parsed successfully")
            print("  Length: \(payload.length) bytes")
            print("  Ciphertext: \(payload.ciphertext.count) bytes")
            print("  MAC: \(payload.mac.count) bytes")
        } catch {
            print("  ⚠️  Could not parse payload: \(error)")
        }

        // Summary
        print("\n✓ NanoTDF structure validated using OpenTDFKit parser")
    }

    /// Decrypt a NanoTDF file and return plaintext
    static func decryptNanoTDFWithOutput(data: Data, filename _: String) async throws -> Data {
        try await performDecryption(data: data, verbose: false)
    }

    /// Decrypt a NanoTDF file with verbose console output
    static func decryptNanoTDF(data: Data, filename: String, token: String? = nil, tokenPath: String? = nil) async throws {
        print("NanoTDF Decryption")
        print("==================")
        print("File: \(filename)")
        print("Size: \(data.count) bytes\n")

        let decryptedData = try await performDecryption(data: data, verbose: true, token: token, tokenPath: tokenPath)
        let plaintext = String(data: decryptedData, encoding: .utf8) ?? "<binary data>"

        print("\n✓ Decryption successful!")
        print("\nPlaintext:")
        print("----------")
        print(plaintext)
    }

    /// Core decryption logic shared between verbose and silent modes
    private static func performDecryption(
        data: Data,
        verbose: Bool,
        token: String? = nil,
        tokenPath: String? = nil,
    ) async throws -> Data {
        let parser = BinaryParser(data: data)
        let header: Header
        do {
            header = try parser.parseHeader()
            if verbose {
                print("✓ Header parsed successfully")
            }
        } catch {
            if verbose {
                print("❌ Failed to parse header: \(error)")
            }
            throw DecryptError.invalidFormat
        }

        // Extract KAS URL - handle both formats: host[:port] and host[:port]/kas;
        // the scheme follows the header locator protocol (http / https).
        let kasLocator = header.payloadKeyAccess.kasLocator
        guard let kasURL = nanoKasURL(from: kasLocator) else {
            if verbose {
                print("❌ Invalid KAS URL: \(kasLocator.body)")
            }
            throw DecryptError.invalidKASURL
        }
        if verbose {
            print("KAS URL: \(kasURL)")
        }

        // Get OAuth token (parameter, TDF_OAUTH_TOKEN / OAUTH_TOKEN, or token file)
        let oauthToken = try resolveEnvironmentOAuthToken(providedToken: token, tokenPath: tokenPath)
        if verbose {
            print("✓ OAuth token loaded")
        }

        // Generate client ephemeral key pair. KASRewrapClient expects the
        // compressed public key and builds the request PEM itself.
        let privateKey = P256.KeyAgreement.PrivateKey()
        let clientKeyPair = EphemeralKeyPair(
            privateKey: privateKey.rawRepresentation,
            publicKey: privateKey.publicKey.compressedRepresentation,
            curve: .secp256r1,
        )
        if verbose {
            print("✓ Generated client ephemeral key pair")
        }

        // Find header boundary
        let headerSize = calculateHeaderSize(from: data, parsedHeader: header, verbose: verbose)
        let rawHeader = data.prefix(headerSize)

        // Call KAS rewrap endpoint
        if verbose {
            print("\nCalling KAS rewrap endpoint...")
        }
        let configuration = await resolveConfiguration(kasURL: kasURL, token: oauthToken)
        let kasClient = try KASRewrapClient(configuration: configuration, oauthToken: oauthToken)

        let (wrappedKey, sessionPublicKey): (Data, Data)
        do {
            (wrappedKey, sessionPublicKey) = try await kasClient.rewrapNanoTDF(
                header: rawHeader,
                parsedHeader: header,
                clientKeyPair: clientKeyPair,
            )
            if verbose {
                print("✓ KAS rewrap successful")
            }
        } catch {
            if verbose {
                print("❌ KAS rewrap failed: \(error)")
            }
            throw error
        }

        // Unwrap the key
        let payloadKey: SymmetricKey
        do {
            payloadKey = try KASRewrapClient.unwrapKey(
                wrappedKey: wrappedKey,
                sessionPublicKey: sessionPublicKey,
                clientPrivateKey: clientKeyPair.privateKey,
            )
            if verbose {
                print("✓ Key unwrapped successfully")
            }
        } catch {
            if verbose {
                print("❌ Key unwrap failed: \(error)")
            }
            throw error
        }

        // Parse and decrypt the payload
        let payload = try parser.parsePayload(config: header.payloadSignatureConfig)
        if verbose {
            print("\nPayload:")
            print("  Length: \(payload.length) bytes")
            print("  IV: \(payload.iv.hexEncodedString())")
            print("  Ciphertext: \(payload.ciphertext.count) bytes")
            print("  MAC: \(payload.mac.count) bytes")
            print("\n✓ Using \(payload.mac.count)-byte MAC tag")
        }

        // Construct nonce: 9 bytes zeros + 3-byte payload IV
        var adjustedIV = Data(count: 9)
        adjustedIV.append(payload.iv)

        // Decrypt using GCM
        guard let cipher = header.payloadSignatureConfig.payloadCipher else {
            throw DecryptError.decryptionFailed
        }

        do {
            return try OpenTDFKit.CryptoHelper.decryptNanoTDF(
                cipher: cipher,
                key: payloadKey,
                iv: adjustedIV,
                ciphertext: payload.ciphertext,
                tag: payload.mac,
            )
        } catch {
            if verbose {
                print("\n✗ GCM decryption failed: \(error)")
                let keyData = payloadKey.withUnsafeBytes { Data($0) }
                print("  Payload key: \(keyData.hexEncodedString())")
                print("  IV (adjusted): \(adjustedIV.hexEncodedString())")
            }
            throw error
        }
    }

    /// Calculate the header size from raw NanoTDF data
    private static func calculateHeaderSize(from data: Data, parsedHeader: Header, verbose: Bool) -> Int {
        // Try to find payload marker
        for i in NanoTDFConstants.headerSearchStart ..< min(data.count - 2, NanoTDFConstants.headerSearchEnd) {
            if data[i] == 0x00, data[i + 1] == 0x00 {
                if i + 2 < data.count {
                    let potentialLength = Int(data[i + 2])
                    if potentialLength > 0, potentialLength < 100, (i + 3 + potentialLength) <= data.count {
                        if verbose {
                            print("Found payload at offset \(i)")
                        }
                        return i
                    }
                }
            }
        }

        // Fallback to reconstructed header size
        let reconstructed = parsedHeader.toData().count
        if verbose {
            print("Using reconstructed header size: \(reconstructed) bytes")
        }
        return reconstructed
    }
}

enum NanoTDFConstants {
    static let headerSearchStart = 100
    static let headerSearchEnd = 300
    static let nonceZeroPadding = 9
}

enum DecryptError: Error, CustomStringConvertible {
    case invalidKASURL
    case missingOAuthToken
    case decryptionFailed
    case keyFormatError
    case invalidFormat
    case missingSymmetricMaterial
    case missingWrappedKey
    case invalidWrappedKeyFormat

    var description: String {
        switch self {
        case .invalidKASURL: "Invalid KAS URL format"
        case .missingOAuthToken: "OAuth token not found"
        case .decryptionFailed: "Payload decryption failed"
        case .keyFormatError: "Invalid key format"
        case .invalidFormat: "Invalid NanoTDF format"
        case .missingSymmetricMaterial: "Provide TDF_SYMMETRIC_KEY_PATH or TDF_PRIVATE_KEY_PATH to decrypt standard TDF files"
        case .missingWrappedKey: "KAS response missing wrapped key"
        case .invalidWrappedKeyFormat: "Key share length mismatch in multi-share TDF"
        }
    }
}

enum EncryptError: Error, CustomStringConvertible {
    case invalidKASURL
    case kasRequestFailed
    case invalidKASPublicKey
    case encryptionFailed
    case missingConfiguration(String)

    var description: String {
        switch self {
        case .invalidKASURL: "Invalid KAS URL format"
        case .kasRequestFailed: "KAS public key request failed"
        case .invalidKASPublicKey: "Invalid KAS public key format"
        case .encryptionFailed: "Encryption operation failed"
        case let .missingConfiguration(message): message
        }
    }
}

extension String {
    func chunked(into size: Int) -> [String] {
        stride(from: 0, to: count, by: size).map {
            let start = index(startIndex, offsetBy: $0)
            let end = index(start, offsetBy: min(size, count - $0))
            return String(self[start ..< end])
        }
    }
}

// MARK: - NanoTDF Collection Commands

extension Commands {
    /// Encrypt multiple plaintexts to a NanoTDF Collection file
    static func encryptNanoTDFCollection(
        plaintexts: [Data],
        outputURL: URL,
    ) async throws {
        print("NanoTDF Collection Encryption")
        print("==============================")
        print("Items to encrypt: \(plaintexts.count)")

        // Get configuration from environment
        let config = try CLIConfig.fromEnvironment()

        // Parse KAS URL (locator body is host[:port]; port only when explicit)
        guard let kasURL = URL(string: config.kasURL),
              let kasBody = nanoKasLocatorBody(kasURL: kasURL)
        else {
            throw EncryptError.invalidKASURL
        }

        // Get OAuth token (env or token file)
        let oauthToken = try resolveEnvironmentOAuthToken()

        // Fetch KAS public key (endpoints resolved from PLATFORMURL / KASURL)
        let kasKey = try await fetchKASPublicKey(kasURL: kasURL, token: oauthToken)
        print("✓ Retrieved KAS public key\(kasKey.kid.map { " (kid: \($0))" } ?? "")")

        // Create resource locator for KAS, matching the configured scheme
        guard let kasLocator = ResourceLocator(
            protocolEnum: nanoProtocol(forScheme: kasURL.scheme),
            body: kasBody,
            identifier: nanoKasIdentifier(kid: kasKey.kid ?? "e1"),
        ) else {
            throw EncryptError.invalidKASURL
        }

        // Convert compressed key data to CryptoKit public key
        let kasPublicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: kasKey.compressedKey)

        // Create KAS metadata
        let kasMetadata = try KasMetadata(
            resourceLocator: kasLocator,
            publicKey: kasPublicKey,
            curve: .secp256r1,
        )

        // Create policy locator
        guard let policyLocator = ResourceLocator(
            protocolEnum: .https,
            body: "\(kasBody)/policy",
        ) else {
            throw EncryptError.invalidKASURL
        }

        // Build collection
        let collection = try await NanoTDFCollectionBuilder()
            .kasMetadata(kasMetadata)
            .policy(.remote(policyLocator))
            .build()

        print("✓ Collection initialized (single key derivation)")

        // Encrypt all items
        var serializedData = Data()
        for (index, plaintext) in plaintexts.enumerated() {
            let item = try await collection.encryptItem(plaintext: plaintext)
            let serialized = await collection.serialize(item: item)
            serializedData.append(serialized)

            if (index + 1) % 100 == 0 || index == plaintexts.count - 1 {
                print("  Encrypted \(index + 1)/\(plaintexts.count) items")
            }
        }

        // Create collection file
        let headerBytes = await collection.getHeaderBytes()
        let itemCount = await collection.itemCount
        let fileData = NanoTDFCollectionFile.serialize(
            header: headerBytes,
            items: serializedData,
            itemCount: itemCount,
        )

        // Write to output
        try fileData.write(to: outputURL)

        print("✓ Created NanoTDF Collection")
        print("  Total size: \(fileData.count) bytes")
        print("  Items: \(itemCount)")
        print("  Header: \(headerBytes.count) bytes")
    }

    /// Decrypt a NanoTDF Collection file
    static func decryptNanoTDFCollection(
        data: Data,
        filename: String,
        token: String? = nil,
        tokenPath: String? = nil,
    ) async throws -> [Data] {
        print("NanoTDF Collection Decryption")
        print("==============================")
        print("File: \(filename)")
        print("Size: \(data.count) bytes\n")

        // Parse collection file
        let (headerBytes, itemsData, itemCount) = try NanoTDFCollectionFile.parse(from: data)
        print("✓ Parsed collection file")
        print("  Header: \(headerBytes.count) bytes")
        print("  Items: \(itemCount)")

        // Parse header
        let parser = BinaryParser(data: headerBytes)
        let header = try parser.parseHeader()
        print("✓ Parsed NanoTDF header")

        // Get KAS URL (scheme from the header locator protocol)
        guard let kasURL = nanoKasURL(from: header.payloadKeyAccess.kasLocator) else {
            throw DecryptError.invalidKASURL
        }
        print("  KAS URL: \(kasURL)")

        // Get OAuth token (parameter, TDF_OAUTH_TOKEN / OAUTH_TOKEN, or token file)
        let oauthToken = try resolveEnvironmentOAuthToken(providedToken: token, tokenPath: tokenPath)
        print("✓ OAuth token loaded")

        // Generate client ephemeral key pair (compressed public key; the rewrap
        // client builds the request PEM itself)
        let privateKey = P256.KeyAgreement.PrivateKey()
        let clientKeyPair = EphemeralKeyPair(
            privateKey: privateKey.rawRepresentation,
            publicKey: privateKey.publicKey.compressedRepresentation,
            curve: .secp256r1,
        )
        print("✓ Generated client ephemeral key pair")

        // Call KAS rewrap endpoint (single rewrap for entire collection)
        print("\nCalling KAS rewrap endpoint...")
        let configuration = await resolveConfiguration(kasURL: kasURL, token: oauthToken)
        let kasClient = try KASRewrapClient(configuration: configuration, oauthToken: oauthToken)

        let (wrappedKey, sessionPublicKey) = try await kasClient.rewrapNanoTDF(
            header: headerBytes,
            parsedHeader: header,
            clientKeyPair: clientKeyPair,
        )
        print("✓ KAS rewrap successful (single key for all items)")

        // Unwrap the key
        let payloadKey = try KASRewrapClient.unwrapKey(
            wrappedKey: wrappedKey,
            sessionPublicKey: sessionPublicKey,
            clientPrivateKey: clientKeyPair.privateKey,
        )
        print("✓ Key unwrapped successfully")

        // Create decryptor with the unwrapped key
        let cipher = header.payloadSignatureConfig.payloadCipher ?? .aes256GCM128
        let decryptor = NanoTDFCollectionDecryptor.withUnwrappedKey(
            symmetricKey: payloadKey,
            cipher: cipher,
        )

        // Parse and decrypt all items
        let items = try NanoTDFCollectionParser.parseStream(
            from: itemsData,
            format: .containerFraming,
            tagSize: cipher.tagSize,
        )
        print("\n✓ Parsed \(items.count) items from stream")

        var decryptedItems = [Data]()
        decryptedItems.reserveCapacity(items.count)

        for (index, item) in items.enumerated() {
            let plaintext = try await decryptor.decryptItem(item)
            decryptedItems.append(plaintext)

            if (index + 1) % 100 == 0 || index == items.count - 1 {
                print("  Decrypted \(index + 1)/\(items.count) items")
            }
        }

        print("\n✓ Decryption complete!")
        return decryptedItems
    }

    /// Encrypt a single file to NanoTDF Collection format (for CLI convenience)
    static func encryptFileToCollection(inputURL: URL, outputURL: URL) async throws {
        let inputData = try Data(contentsOf: inputURL)
        // For single file, we just encrypt it as a single-item collection
        try await encryptNanoTDFCollection(plaintexts: [inputData], outputURL: outputURL)
    }

    /// Decrypt a NanoTDF Collection file and return the first item (for CLI single-file mode)
    static func decryptCollectionToFile(
        inputURL: URL,
        outputURL: URL,
        token: String? = nil,
        tokenPath: String? = nil,
    ) async throws {
        let data = try Data(contentsOf: inputURL)
        let decryptedItems = try await decryptNanoTDFCollection(
            data: data,
            filename: inputURL.lastPathComponent,
            token: token,
            tokenPath: tokenPath,
        )

        guard let firstItem = decryptedItems.first else {
            throw CollectionCLIError.emptyCollection
        }

        // For single output file, concatenate all items or just use first
        if decryptedItems.count == 1 {
            try firstItem.write(to: outputURL)
        } else {
            // For multiple items, concatenate them with newlines if they're text
            var combined = Data()
            for item in decryptedItems {
                combined.append(item)
            }
            try combined.write(to: outputURL)
        }
    }
}

enum CollectionCLIError: Error, CustomStringConvertible {
    case emptyCollection

    var description: String {
        switch self {
        case .emptyCollection:
            "Collection contains no items"
        }
    }
}

// MARK: - TDF-JSON and TDF-CBOR Commands

/// Result type for TDF-JSON/CBOR encryption
struct TDFInlineEncryptionResult {
    let data: Data
    let symmetricKey: SymmetricKey
}

extension Commands {
    /// Encrypt plaintext to TDF-JSON format
    static func encryptTDFJSON(
        plaintext: Data,
        inputURL _: URL,
    ) throws -> TDFInlineEncryptionResult {
        print("TDF-JSON Encryption")
        print("===================")
        print("Plaintext size: \(plaintext.count) bytes")

        let env = ProcessInfo.processInfo.environment
        guard let kasURLString = env["TDF_KAS_URL"] ?? env["KASURL"],
              let kasURL = URL(string: kasURLString)
        else {
            throw EncryptError.missingConfiguration("TDF_KAS_URL or KASURL environment variable required")
        }

        let publicKeyPEM = try loadKASPublicKeyPEM()
        let policy = try loadPolicy()

        let builder = TDFJSONBuilder()
            .kasURL(kasURL)
            .kasPublicKey(publicKeyPEM)

        let builderWithKid: TDFJSONBuilder = if let kid = env["TDF_KAS_KID"] {
            builder.kasKid(kid)
        } else {
            builder
        }

        let builderWithMime: TDFJSONBuilder = if let mimeType = env["TDF_MIME_TYPE"] {
            builderWithKid.mimeType(mimeType)
        } else {
            builderWithKid
        }

        let result = try builderWithMime
            .policy(policy)
            .encrypt(plaintext: plaintext)

        let jsonData = try result.container.serializedData()

        print("✓ Created TDF-JSON (\(jsonData.count) bytes)")

        return TDFInlineEncryptionResult(
            data: jsonData,
            symmetricKey: result.symmetricKey,
        )
    }

    /// Encrypt plaintext to TDF-CBOR format
    static func encryptTDFCBOR(
        plaintext: Data,
        inputURL _: URL,
    ) throws -> TDFInlineEncryptionResult {
        print("TDF-CBOR Encryption")
        print("===================")
        print("Plaintext size: \(plaintext.count) bytes")

        let env = ProcessInfo.processInfo.environment
        guard let kasURLString = env["TDF_KAS_URL"] ?? env["KASURL"],
              let kasURL = URL(string: kasURLString)
        else {
            throw EncryptError.missingConfiguration("TDF_KAS_URL or KASURL environment variable required")
        }

        let publicKeyPEM = try loadKASPublicKeyPEM()
        let policy = try loadPolicy()

        let builder = TDFCBORBuilder()
            .kasURL(kasURL)
            .kasPublicKey(publicKeyPEM)

        let builderWithKid: TDFCBORBuilder = if let kid = env["TDF_KAS_KID"] {
            builder.kasKid(kid)
        } else {
            builder
        }

        let builderWithMime: TDFCBORBuilder = if let mimeType = env["TDF_MIME_TYPE"] {
            builderWithKid.mimeType(mimeType)
        } else {
            builderWithKid
        }

        let result = try builderWithMime
            .policy(policy)
            .encrypt(plaintext: plaintext)

        let cborData = try result.container.serializedData()

        print("✓ Created TDF-CBOR (\(cborData.count) bytes)")

        return TDFInlineEncryptionResult(
            data: cborData,
            symmetricKey: result.symmetricKey,
        )
    }

    /// Decrypt TDF-JSON format
    static func decryptTDFJSON(
        data: Data,
        filename: String,
        symmetricKey: SymmetricKey?,
        privateKeyPEM: String?,
    ) throws -> Data {
        print("TDF-JSON Decryption")
        print("===================")
        print("File: \(filename)")
        print("Size: \(data.count) bytes\n")

        let loader = TDFJSONLoader()
        let container = try loader.load(from: data)

        print("✓ TDF-JSON loaded")
        print("  Version: \(container.envelope.version)")

        let decryptor = TDFJSONDecryptor()

        if let symmetricKey {
            print("  Using provided symmetric key for decryption")
            return try decryptor.decrypt(container: container, symmetricKey: symmetricKey)
        }

        guard let privateKeyPEM else {
            throw DecryptError.missingSymmetricMaterial
        }

        print("  Using private key for decryption")
        return try decryptor.decrypt(container: container, privateKeyPEM: privateKeyPEM)
    }

    /// Decrypt TDF-CBOR format
    static func decryptTDFCBOR(
        data: Data,
        filename: String,
        symmetricKey: SymmetricKey?,
        privateKeyPEM: String?,
    ) throws -> Data {
        print("TDF-CBOR Decryption")
        print("===================")
        print("File: \(filename)")
        print("Size: \(data.count) bytes\n")

        let loader = TDFCBORLoader()
        let container = try loader.load(from: data)

        print("✓ TDF-CBOR loaded")
        print("  Version: \(container.envelope.version.map { String($0) }.joined(separator: "."))")

        let decryptor = TDFCBORDecryptor()

        if let symmetricKey {
            print("  Using provided symmetric key for decryption")
            return try decryptor.decrypt(container: container, symmetricKey: symmetricKey)
        }

        guard let privateKeyPEM else {
            throw DecryptError.missingSymmetricMaterial
        }

        print("  Using private key for decryption")
        return try decryptor.decrypt(container: container, privateKeyPEM: privateKeyPEM)
    }

    /// Verify TDF-JSON structure
    static func verifyTDFJSON(data: Data, filename: String) throws {
        print("TDF-JSON Verification Report")
        print("============================")
        print("File: \(filename)")
        print("Size: \(data.count) bytes\n")

        let loader = TDFJSONLoader()
        let container = try loader.load(from: data)

        print("✓ TDF-JSON parsed successfully")
        print("  TDF Type: \(container.envelope.tdf)")
        print("  Version: \(container.envelope.version)")
        if let created = container.envelope.created {
            print("  Created: \(created)")
        }

        let enc = container.encryptionInformation
        print("\nEncryption Information:")
        print("  Type: \(enc.type.rawValue)")
        print("  Key Access Objects: \(enc.keyAccess.count)")
        print("  Algorithm: \(enc.method.algorithm)")

        print("\nPayload:")
        print("  Type: \(container.envelope.payload.type)")
        print("  Protocol: \(container.envelope.payload.protocol)")
        print("  Encrypted: \(container.envelope.payload.isEncrypted)")
        if let mimeType = container.envelope.payload.mimeType {
            print("  MIME Type: \(mimeType)")
        }

        print("\n✓ TDF-JSON structure validated")
    }

    /// Verify TDF-CBOR structure
    static func verifyTDFCBOR(data: Data, filename: String) throws {
        print("TDF-CBOR Verification Report")
        print("============================")
        print("File: \(filename)")
        print("Size: \(data.count) bytes\n")

        // Check magic bytes
        guard TDFCBOREnvelope.hasMagicBytes(data) else {
            throw TDFCBORError.invalidMagicBytes
        }
        print("✓ CBOR magic bytes verified")

        let loader = TDFCBORLoader()
        let container = try loader.load(from: data)

        print("✓ TDF-CBOR parsed successfully")
        print("  TDF Type: \(container.envelope.tdf)")
        print("  Version: \(container.envelope.version.map { String($0) }.joined(separator: "."))")
        if let created = container.envelope.created {
            print("  Created: \(created)")
        }

        let enc = container.encryptionInformation
        print("\nEncryption Information:")
        print("  Type: \(enc.type.rawValue)")
        print("  Key Access Objects: \(enc.keyAccess.count)")
        print("  Algorithm: \(enc.method.algorithm)")

        print("\nPayload:")
        print("  Type: \(container.envelope.payload.type)")
        print("  Protocol: \(container.envelope.payload.protocol)")
        print("  Encrypted: \(container.envelope.payload.isEncrypted)")
        print("  Size: \(container.envelope.payload.value.count) bytes")
        if let mimeType = container.envelope.payload.mimeType {
            print("  MIME Type: \(mimeType)")
        }

        print("\n✓ TDF-CBOR structure validated")
    }

    // MARK: - Private Helpers

    private static func loadKASPublicKeyPEM() throws -> String {
        let env = ProcessInfo.processInfo.environment
        if let inline = env["TDF_KAS_PUBLIC_KEY"],
           !inline.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        {
            return inline
        }

        if let path = env["TDF_KAS_PUBLIC_KEY_PATH"] {
            let url = URL(fileURLWithPath: path)
            return try String(contentsOf: url, encoding: .utf8)
        }

        throw EncryptError.missingConfiguration("TDF_KAS_PUBLIC_KEY or TDF_KAS_PUBLIC_KEY_PATH required")
    }

    private static func loadPolicy() throws -> TDFPolicy {
        let env = ProcessInfo.processInfo.environment

        if let policyPath = env["TDF_POLICY_PATH"] {
            let url = URL(fileURLWithPath: policyPath)
            let data = try Data(contentsOf: url)
            return try TDFPolicy(json: data)
        }

        if let policyBase64 = env["TDF_POLICY_BASE64"],
           let data = Data(base64Encoded: policyBase64)
        {
            return try TDFPolicy(json: data)
        }

        if let inlineJSON = env["TDF_POLICY_JSON"],
           let data = inlineJSON.data(using: .utf8)
        {
            return try TDFPolicy(json: data)
        }

        do {
            return try TDFPolicy(json: Config.defaultPolicyData(env: env))
        } catch {
            throw EncryptError.missingConfiguration("Unable to create default policy")
        }
    }
}
