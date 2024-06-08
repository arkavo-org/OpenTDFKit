//
//  WebSocketManager.swift
//  Tests
//
//  Created by Paul Flynn on 5/10/24.
//

import Foundation
import CryptoKit

struct PublicKeyMessage: Codable {
    // TODO add Message type, value 0x01 
    let publicKey: Data
}

class WebSocketManager {
    private var webSocketTask: URLSessionWebSocketTask?
    private let urlSession: URLSession
    private var myPrivateKey: P256.KeyAgreement.PrivateKey!
    var myPublicKey: P256.KeyAgreement.PublicKey!

    init() {
        // create key
        myPrivateKey = P256.KeyAgreement.PrivateKey()
        myPublicKey = myPrivateKey.publicKey
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
            case .failure(let error):
                print("Failed to receive message: \(error)")
            case .success(let message):
                switch message {
                case .string(let text):
                    print("Received string: \(text)")
                case .data(let data):
                    print("Received data: \(data)")
                @unknown default:
                    fatalError()
                }

                // Continue receiving messages
                self?.receiveMessage()
            }
        }
    }

    func sendMessage(_ message: String) {
        let message = URLSessionWebSocketTask.Message.string(message)
        webSocketTask?.send(message) { error in
            if let error = error {
                print("Failed to send message: \(error)")
            }
        }
    }

    func sendPublicKey() {
        let publicKeyMessage = PublicKeyMessage(publicKey: myPublicKey.rawRepresentation)
//        let data : Data = publicKeyMessage.public_key
        let data = URLSessionWebSocketTask.Message.data(publicKeyMessage.publicKey)
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

