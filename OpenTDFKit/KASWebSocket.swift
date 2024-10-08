import Combine
import CryptoKit
import Foundation

public enum WebSocketConnectionState {
    case disconnected
    case connecting
    case connected
}

extension WebSocketConnectionState: CustomStringConvertible {
    public var description: String {
        switch self {
        case .disconnected: "Disconnected"
        case .connecting: "Connecting"
        case .connected: "Connected"
        }
    }
}

public class KASWebSocket {
    private var webSocketTask: URLSessionWebSocketTask?
    private var urlSession: URLSession?
    private let myPrivateKey: P256.KeyAgreement.PrivateKey!
    private var sharedSecret: SharedSecret?
    private var salt: Data?
    private var rewrapCallback: ((Data, SymmetricKey?) -> Void)?
    private var kasPublicKeyCallback: ((P256.KeyAgreement.PublicKey) -> Void)?
    private var customMessageCallback: ((Data) -> Void)?
    private let kasUrl: URL
    private let token: String

    private let connectionStateSubject = CurrentValueSubject<WebSocketConnectionState, Never>(.disconnected)
    public var connectionStatePublisher: AnyPublisher<WebSocketConnectionState, Never> {
        connectionStateSubject.eraseToAnyPublisher()
    }

    public init(kasUrl: URL, token: String) {
        // create key
        myPrivateKey = P256.KeyAgreement.PrivateKey()
        self.kasUrl = kasUrl
        self.token = token
    }

    public func setRewrapCallback(_ callback: @escaping (Data, SymmetricKey?) -> Void) {
        rewrapCallback = callback
    }

    public func setKASPublicKeyCallback(_ callback: @escaping (P256.KeyAgreement.PublicKey) -> Void) {
        kasPublicKeyCallback = callback
    }

    public func setCustomMessageCallback(_ callback: @escaping (Data) -> Void) {
        customMessageCallback = callback
    }

    public func sendCustomMessage(_ message: Data, completion: @escaping (Error?) -> Void) {
        let task = URLSessionWebSocketTask.Message.data(message)
        webSocketTask?.send(task) { error in
            if let error {
                print("Error sending custom message: \(error)")
            }
            completion(error)
        }
    }

    public func connect() {
        connectionStateSubject.send(.connecting)
        // Create a URLRequest object with the WebSocket URL
        var request = URLRequest(url: kasUrl)
        // Add the Authorization header to the request
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        // Initialize a URLSession with a default configuration
        urlSession = URLSession(configuration: .default)
        webSocketTask = urlSession!.webSocketTask(with: request)
        webSocketTask?.resume()
        let tokenMessage = URLSessionWebSocketTask.Message.string(token)
        webSocketTask?.send(tokenMessage) { error in
            if let error {
                print("token sending error: \(error)")
            }
        }
        // Start receiving messages
        receiveMessage()
        pingPeriodically()
    }

    private func pingPeriodically() {
        webSocketTask?.sendPing { [weak self] error in
            if let error {
                print("Error sending ping: \(error)")
                self?.connectionStateSubject.send(.disconnected)
            } else {
                self?.connectionStateSubject.send(.connected)
            }
            // Schedule next ping
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
                self?.pingPeriodically()
            }
        }
    }

    private func receiveMessage() {
        webSocketTask?.receive { [weak self] result in
            switch result {
            case let .failure(error):
                print("Failed to receive message: \(error)")
                self?.connectionStateSubject.send(.disconnected)
            case let .success(message):
                self?.connectionStateSubject.send(.connected)
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
        // print("Received message with type: \(messageType as NSData)")
        switch messageType {
        case Data([0x01]):
            handlePublicKeyMessage(data: data.suffix(from: 1))
        case Data([0x02]):
            handleKASKeyMessage(data: data.suffix(from: 1))
        case Data([0x04]):
            handleRewrappedKeyMessage(data: data.suffix(from: 1))
        default:
            customMessageCallback?(data)
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
            // print("Server PublicKey: \(receivedPublicKey.compressedRepresentation.hexEncodedString())")
            sharedSecret = try myPrivateKey.sharedSecretFromKeyAgreement(with: receivedPublicKey)
            // Convert the symmetric key to a hex string
//            let sharedSecretHex = sharedSecret!.withUnsafeBytes { buffer in
//                buffer.map { String(format: "%02x", $0) }.joined()
//            }
            // print("Shared Secret +++++++++++++")
            // print("Shared Secret: \(sharedSecretHex)")
            // print("Shared Secret +++++++++++++")
            // Convert the symmetric key to a hex string
//            let saltHex = salt!.withUnsafeBytes { buffer in
//                buffer.map { String(format: "%02x", $0) }.joined()
//            }
            // print("Session Salt: \(saltHex)")
        } catch {
            print("Error handling PublicKeyMessage: \(error) \(data)")
            let dataHex = data.withUnsafeBytes { buffer in
                buffer.map { String(format: "%02x", $0) }.joined()
            }
            print("Bad PublicKeyMessage: \(dataHex)")
        }
    }

    private func handleKASKeyMessage(data: Data) {
        // print("KAS Public Key Size: \(data)")
        guard data.count == 33 else {
            print("Error: KAS PublicKey data is not 33 bytes long (expected for compressed key)")
            return
        }
        // print("KAS Public Key Hex: \(data.hexEncodedString())")
        do {
            let kasPublicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: data)
            // Call the callback with the parsed KAS public key
            kasPublicKeyCallback?(kasPublicKey)
        } catch {
            print("Error parsing KAS PublicKey: \(error)")
        }
    }

    private func handleRewrappedKeyMessage(data: Data) {
//        defer {
//            print("END handleRewrappedKeyMessage")
//        }
//        print("BEGIN handleRewrappedKeyMessage")
        // print("wrapped_dek_shared_secret \(data.hexEncodedString())")
        guard data.count == 93 else {
            if data.count == 33 {
                // DENY -- Notify the app with the identifier
                rewrapCallback?(data, nil)
                return
            }
            print("RewrappedKeyMessage not the expected 93 bytes (33 for identifier + 60 for key): \(data.count)")
            return
        }
        let identifier = data.prefix(33)
        let keyData = data.suffix(60)
        // Parse key data components
        let nonce = keyData.prefix(12)
        let encryptedKeyLength = keyData.count - 12 - 16 // Total - nonce - tag
        // print("encryptedKeyLength \(encryptedKeyLength)")
        guard encryptedKeyLength >= 0 else {
            print("Invalid encrypted key length: \(encryptedKeyLength)")
            return
        }
        let rewrappedKey = keyData.prefix(keyData.count - 16).suffix(encryptedKeyLength)
        let authTag = keyData.suffix(16)
        // print("Identifier (bytes): \(identifier.hexEncodedString())")
        // print("Nonce (12 bytes): \(nonce.hexEncodedString())")
        // print("Rewrapped Key (\(encryptedKeyLength) bytes): \(rewrappedKey.hexEncodedString())")
        // print("Authentication Tag (16 bytes): \(authTag.hexEncodedString())")
        // Decrypt the message using AES-GCM
        do {
            // Derive a symmetric key from the session shared secret
            let sessionSymmetricKey = CryptoHelper.deriveSymmetricKey(sharedSecret: sharedSecret!, salt: salt!, info: Data("rewrappedKey".utf8), outputByteCount: 32)
            // print("Derived Session Key: \(sessionSymmetricKey.withUnsafeBytes { Data($0).hexEncodedString() })")
            let sealedBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: rewrappedKey, tag: authTag)
            let decryptedDataSharedSecret = try AES.GCM.open(sealedBox, using: sessionSymmetricKey)
            // print("Decrypted shared secret: \(decryptedDataSharedSecret.hexEncodedString())")
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

    public func sendPublicKey() {
        let myPublicKey = myPrivateKey.publicKey
//        let hexData = myPublicKey.compressedRepresentation.map { String(format: "%02x", $0) }.joined()
        // print("Client Public Key: \(hexData)")
        let publicKeyMessage = PublicKeyMessage(publicKey: myPublicKey.compressedRepresentation)
        let data = URLSessionWebSocketTask.Message.data(publicKeyMessage.toData())
        // print("Sending data: \(data)")
        webSocketTask?.send(data) { error in
            if let error {
                print("WebSocket sending error: \(error)")
            }
        }
    }

    public func sendKASKeyMessage() {
        let kasKeyMessage = KASKeyMessage()
        let data = URLSessionWebSocketTask.Message.data(kasKeyMessage.toData())
        // print("Sending data: \(data)")
        webSocketTask?.send(data) { error in
            if let error {
                print("WebSocket sending error: \(error)")
            }
        }
    }

    public func sendRewrapMessage(header: Header) {
        let rewrapMessage = RewrapMessage(header: header)
        let data = URLSessionWebSocketTask.Message.data(rewrapMessage.toData())
        // print("Sending data: \(data)")
        webSocketTask?.send(data) { error in
            if let error {
                print("WebSocket sending error: \(error)")
            }
        }
    }

    public func sendPing(completionHandler: @escaping (Error?) -> Void) {
        webSocketTask?.sendPing { error in
            if let error {
                print("Error sending ping: \(error)")
            }
            completionHandler(error)
        }
    }

    public func disconnect() {
        webSocketTask?.cancel(with: .goingAway, reason: nil)
        connectionStateSubject.send(.disconnected)
    }
}

// Add this extension to Data for convenient hex string representation
extension Data {
    func hexEncodedString() -> String {
        map { String(format: "%02hhx", $0) }.joined()
    }
}

struct KASKeyMessage {
    let messageType: Data = .init([0x02])

    func toData() -> Data {
        messageType
    }
}

struct PublicKeyMessage {
    let messageType: Data = .init([0x01])
    let publicKey: Data

    func toData() -> Data {
        var data = Data()
        data.append(messageType)
        data.append(publicKey)
        return data
    }
}

struct RewrapMessage {
    let messageType: Data = .init([0x03])
    let header: Header

    func toData() -> Data {
        var data = Data()
        data.append(messageType)
        data.append(header.toData())
        return data
    }
}

struct RewrappedKeyMessage {
    let messageType: Data = .init([0x04])
    let rewrappedKey: Data

    func toData() -> Data {
        var data = Data()
        data.append(messageType)
        data.append(rewrappedKey)
        return data
    }
}
