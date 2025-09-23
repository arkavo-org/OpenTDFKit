import Foundation
import CryptoKit

/// Helper for creating and signing JWT tokens for KAS requests
public struct JWTHelper {

    /// JWT Header structure
    private struct Header: Codable {
        let alg: String
        let typ: String = "JWT"
    }

    /// JWT Claims structure for KAS rewrap request
    public struct RewrapClaims: Codable {
        let requestBody: String  // JSON-encoded UnsignedRewrapRequest
        let iss: String?
        let sub: String?
        let aud: String?
        let exp: Int?
        let iat: Int
        let jti: String?
    }

    /// Create a signed JWT for KAS rewrap request
    /// For now, we'll use HS256 with a shared secret (simplified for initial implementation)
    /// In production, this should use RS256 or ES256 with proper key management
    public static func createSignedRequestToken(requestBody: Data, secret: Data) throws -> String {
        // Create header
        let header = Header(alg: "HS256")
        let headerJSON = try JSONEncoder().encode(header)
        let headerBase64 = headerJSON.base64UrlEncodedString()

        // Create claims
        let claims = RewrapClaims(
            requestBody: String(data: requestBody, encoding: .utf8) ?? "",
            iss: "OpenTDFKit",
            sub: "opentdf-client",
            aud: "kas",
            exp: Int(Date().timeIntervalSince1970) + 3600, // 1 hour from now
            iat: Int(Date().timeIntervalSince1970),
            jti: UUID().uuidString
        )
        let claimsJSON = try JSONEncoder().encode(claims)
        let claimsBase64 = claimsJSON.base64UrlEncodedString()

        // Create signature
        let message = "\(headerBase64).\(claimsBase64)"
        let signature = try createHMACSignature(message: message, secret: secret)
        let signatureBase64 = signature.base64UrlEncodedString()

        // Combine to create JWT
        return "\(headerBase64).\(claimsBase64).\(signatureBase64)"
    }

    /// Create HMAC-SHA256 signature
    private static func createHMACSignature(message: String, secret: Data) throws -> Data {
        guard let messageData = message.data(using: .utf8) else {
            throw JWTError.invalidInput
        }

        let key = SymmetricKey(data: secret)
        let signature = HMAC<SHA256>.authenticationCode(for: messageData, using: key)
        return Data(signature)
    }
}

/// JWT-specific errors
public enum JWTError: Error {
    case invalidInput
    case signingFailed
}

// Extension for base64url encoding (no padding, URL-safe characters)
extension Data {
    func base64UrlEncodedString() -> String {
        return base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}