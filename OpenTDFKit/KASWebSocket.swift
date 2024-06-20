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
    private var myPrivateKey: Curve25519.KeyAgreement.PrivateKey!

    init() {
        // create key
        myPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        // Initialize a URLSession with a default configuration
        urlSession = URLSession(configuration: .default)
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
        print("Compressed Server PublicKey bytes: \(data)")
        let dataHex = data.withUnsafeBytes { buffer in
            buffer.map { String(format: "%02x", $0) }.joined()
        }
        print("Compressed Server PublicKey: \(dataHex)")
        guard data.count == 32 else {
            print("Error: PublicKey data is not 32 bytes long")
            return
        }
        do {
            // FIXME update to Curve25519 instead of P256
            let receivedPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: data)
            let sharedSecret = try myPrivateKey.sharedSecretFromKeyAgreement(with: receivedPublicKey)
            // Convert the symmetric key to a hex string
            let sharedSecretHex = sharedSecret.withUnsafeBytes { buffer in
                buffer.map { String(format: "%02x", $0) }.joined()
            }
            print("Shared Secret +++++++++++++")
            print("Shared Secret: \(sharedSecretHex)")
            print("Shared Secret +++++++++++++")
            // Derive a symmetric key from the shared secret
            let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data(),
                sharedInfo: Data(),
                outputByteCount: 32
            )
            // Convert the symmetric key to a hex string
            let symmetricKeyHex = symmetricKey.withUnsafeBytes { buffer in
                buffer.map { String(format: "%02x", $0) }.joined()
            }
            print("Symmetric Key: \(symmetricKeyHex)")
        } catch {
            print("Error handling PublicKeyMessage: \(error) \(data)")
            let dataHex = data.withUnsafeBytes { buffer in
                buffer.map { String(format: "%02x", $0) }.joined()
            }
            print("Bad PublicKeyMessage: \(dataHex)")
        }
    }

    private func handleKASKeyMessage(data: Data) {
        print("KAS key bytes: \(data)")
        // TODO parse into public key
        // add member and getter for KAS public key
    }
    
    private func handleRewrappedKeyMessage(data: Data) {
        print("Rewrapped key bytes: \(data)")
        // Implement the specific logic for handling the rewrapped key here
        
        // Example: Log or process the rewrapped key as needed
        // In a real scenario, you would likely take further action based on the message content
    }
    
    func sendPublicKey() {
        let myPublicKey = myPrivateKey.publicKey
        let hexData = myPublicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
        print("Client Public Key: \(hexData)")
        let publicKeyMessage = PublicKeyMessage(publicKey: myPublicKey.rawRepresentation)
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
