//
//  WebSocketManager.swift
//  Tests
//
//  Created by Paul Flynn on 5/10/24.
//

import CryptoKit
import Foundation

struct PublicKeyMessage: Codable {
    let messageType: Data
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
            case let .failure(error):
                print("Failed to receive message: \(error)")
            case let .success(message):
                switch message {
                case let .string(text):
                    print("Received string: \(text)")
                case let .data(data):
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
        let publicKeyMessage = PublicKeyMessage(messageType: Data(), publicKey: myPublicKey.rawRepresentation)
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
