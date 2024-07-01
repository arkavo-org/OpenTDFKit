import CryptoKit
import Foundation

struct KASKeyMessage {
    let messageType: Data = Data([0x02])
    
    func toData() -> Data {
        return messageType
    }
}

struct PublicKeyMessage {
    let messageType: Data = Data([0x01])
    let publicKey: Data
    
    func toData() -> Data {
        var data = Data()
        data.append(messageType)
        data.append(publicKey)
        return data
    }
}

struct RewrapMessage {
    let messageType: Data = Data([0x03])
    let header: Header
    
    func toData() -> Data {
        var data = Data()
        data.append(messageType)
        data.append(header.toData())
        return data
    }
}

struct RewrappedKeyMessage {
    let messageType: Data = Data([0x04])
    let rewrappedKey: Data
    
    func toData() -> Data {
        var data = Data()
        data.append(messageType)
        data.append(rewrappedKey)
        return data
    }
}

class KASWebSocket {
    private var webSocketTask: URLSessionWebSocketTask?
    private let urlSession: URLSession
    private let myPrivateKey: P256.KeyAgreement.PrivateKey!
    private var sharedSecret: SharedSecret?
    private var salt: Data?
    private var rewrapCallback: ((Data, SymmetricKey?) -> Void)?
    private var kasPublicKeyCallback: ((P256.KeyAgreement.PublicKey) -> Void)?

    init() {
        // create key
        myPrivateKey = P256.KeyAgreement.PrivateKey()
        // Initialize a URLSession with a default configuration
        urlSession = URLSession(configuration: .default)
    }

    func setRewrapCallback(_ callback: @escaping (Data, SymmetricKey?) -> Void) {
        rewrapCallback = callback
    }
    func setKASPublicKeyCallback(_ callback: @escaping (P256.KeyAgreement.PublicKey) -> Void) {
        kasPublicKeyCallback = callback
    }
    
    func connect() {
        // Create the WebSocket task with the specified URL
        let url = URL(string: "ws://localhost:8080")!
        webSocketTask = urlSession.webSocketTask(with: url)
        webSocketTask?.resume()
        // Start receiving messages
        receiveMessage()
    }

    private func receiveMessage() {
        webSocketTask?.receive { [weak self] result in
            switch result {
            case let .failure(error):
                print("Failed to receive message: \(error)")
            case let .success(message):
                switch message {
                case let .string(text):
                    print("Received string: \(text)")
                case let .data(data):
                    self?.handleMessage(data: data)
                @unknown default:
                    fatalError()
                }

                // Continue receiving messages
                self?.receiveMessage()
            }
        }
    }
    
    private func handleMessage(data: Data) {
        let messageType = data.prefix(1)
        print("Received message with type: \(messageType as NSData)")
        switch messageType {
        case Data([0x01]):
            handlePublicKeyMessage(data: data.suffix(from: 1))
        case Data([0x02]):
            handleKASKeyMessage(data: data.suffix(from: 1))
        case Data([0x04]):
            handleRewrappedKeyMessage(data: data.suffix(from: 1))
        default:
            print("Unknown message type")
        }
    }
    
    private func handlePublicKeyMessage(data: Data) {
        guard data.count == 65 else {
            print("Error: PublicKey data + salt is not 33 + 32 bytes long")
            return
        }
        do {
            // set session salt
            salt = data.suffix(32)
            let publicKeyData = data.prefix(33)
            let receivedPublicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: publicKeyData)
            print("Server PublicKey: \(receivedPublicKey.compressedRepresentation.hexEncodedString())")
            sharedSecret = try myPrivateKey.sharedSecretFromKeyAgreement(with: receivedPublicKey)
            // Convert the symmetric key to a hex string
            let sharedSecretHex = sharedSecret!.withUnsafeBytes { buffer in
                buffer.map { String(format: "%02x", $0) }.joined()
            }
            print("Shared Secret +++++++++++++")
            print("Shared Secret: \(sharedSecretHex)")
            print("Shared Secret +++++++++++++")
            // Convert the symmetric key to a hex string
            let saltHex = salt!.withUnsafeBytes { buffer in
                buffer.map { String(format: "%02x", $0) }.joined()
            }
            print("Session Salt: \(saltHex)")
        } catch {
            print("Error handling PublicKeyMessage: \(error) \(data)")
            let dataHex = data.withUnsafeBytes { buffer in
                buffer.map { String(format: "%02x", $0) }.joined()
            }
            print("Bad PublicKeyMessage: \(dataHex)")
        }
    }

    private func handleKASKeyMessage(data: Data) {
        print("KAS Public Key Size: \(data)")
        guard data.count == 33 else {
            print("Error: KAS PublicKey data is not 33 bytes long (expected for compressed key)")
            return
        }
        print("KAS Public Key Hex: \(data.hexEncodedString())")
        do {
            let kasPublicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: data)
            // Call the callback with the parsed KAS public key
            kasPublicKeyCallback?(kasPublicKey)
        } catch {
            print("Error parsing KAS PublicKey: \(error)")
        }
    }
    
    private func handleRewrappedKeyMessage(data: Data) {
        defer {
            print("END handleRewrappedKeyMessage")
        }
        print("BEGIN handleRewrappedKeyMessage")
        print("wrapped_dek_shared_secret \(data.hexEncodedString())")
        guard data.count == 93 else {
            print("Received data is not the expected 93 bytes (33 for identifier + 60 for key)")
            return
        }
        let identifier = data.prefix(33)
        let keyData = data.suffix(60)
        // Parse key data components
        let nonce = keyData.prefix(12)
        let encryptedKeyLength = keyData.count - 12 - 16 // Total - nonce - tag
        print("encryptedKeyLength \(encryptedKeyLength)")
        guard encryptedKeyLength >= 0 else {
             print("Invalid encrypted key length: \(encryptedKeyLength)")
             return
         }
        let rewrappedKey = keyData.prefix(keyData.count - 16).suffix(encryptedKeyLength)
        let authTag = keyData.suffix(16)
        print("Identifier (bytes): \(identifier.hexEncodedString())")
        print("Nonce (12 bytes): \(nonce.hexEncodedString())")
        print("Rewrapped Key (\(encryptedKeyLength) bytes): \(rewrappedKey.hexEncodedString())")
        print("Authentication Tag (16 bytes): \(authTag.hexEncodedString())")
        // Decrypt the message using AES-GCM
        do {
            // Derive a symmetric key from the session shared secret
            let sessionSymmetricKey = CryptoHelper.deriveSymmetricKey(sharedSecret: sharedSecret!, salt: salt!, info: Data("rewrappedKey".utf8), outputByteCount: 32)
            print("Derived Session Key: \(sessionSymmetricKey.withUnsafeBytes { Data($0).hexEncodedString() })")
            let sealedBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: rewrappedKey, tag: authTag)
            let decryptedDataSharedSecret = try AES.GCM.open(sealedBox, using: sessionSymmetricKey)
            print("Decrypted shared secret: \(decryptedDataSharedSecret.hexEncodedString())")
            let sharedSecretKey = SymmetricKey(data: decryptedDataSharedSecret)
            // Derive a symmetric key from the TDF shared secret (DEK)
            let tdfSymmetricKey = CryptoHelper.deriveSymmetricKey(
                sharedSecretKey: sharedSecretKey,
                salt: Data("L1L".utf8),
                info: Data("encryption".utf8),
                outputByteCount: 32
            )
            // Notify the app with the identifier and derived symmetric key
            rewrapCallback?(identifier, tdfSymmetricKey)
        } catch {
            print("Decryption failed handleRewrappedKeyMessage: \(error)")
        }
    }
       
    func sendPublicKey() {
        let myPublicKey = myPrivateKey.publicKey
        let hexData = myPublicKey.compressedRepresentation.map { String(format: "%02x", $0) }.joined()
        print("Client Public Key: \(hexData)")
        let publicKeyMessage = PublicKeyMessage(publicKey: myPublicKey.compressedRepresentation)
                let data = URLSessionWebSocketTask.Message.data(publicKeyMessage.toData())
        print("Sending data: \(data)")
        webSocketTask?.send(data) { error in
            if let error = error {
                print("WebSocket sending error: \(error)")
            }
        }
    }
    
    func sendKASKeyMessage() {
        let kasKeyMessage = KASKeyMessage()
        let data = URLSessionWebSocketTask.Message.data(kasKeyMessage.toData())
        print("Sending data: \(data)")
        webSocketTask?.send(data) { error in
            if let error = error {
                print("WebSocket sending error: \(error)")
            }
        }
    }

    func sendRewrapMessage(header: Header) {
        let rewrapMessage = RewrapMessage(header: header)
        let data = URLSessionWebSocketTask.Message.data(rewrapMessage.toData())
        print("Sending data: \(data)")
        webSocketTask?.send(data) { error in
            if let error = error {
                print("WebSocket sending error: \(error)")
            }
        }
    }
    
    func disconnect() {
        // Close the WebSocket connection
        webSocketTask?.cancel(with: .goingAway, reason: nil)
    }
}

// Add this extension to Data for convenient hex string representation
extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}
