#!/usr/bin/env python3
import socket
import sys
import threading

def handle_client(client_socket):
    try:
        # Connect to the real OIDC server
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect(('10.0.0.138', 8888))

        # Start threads to relay data in both directions
        threading.Thread(target=relay_data, args=(client_socket, remote_socket)).start()
        threading.Thread(target=relay_data, args=(remote_socket, client_socket)).start()
    except Exception as e:
        print(f"Error: {e}")
        client_socket.close()

def relay_data(source, destination):
    try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            destination.send(data)
    except:
        pass
    finally:
        source.close()
        destination.close()

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('127.0.0.1', 8888))
    server_socket.listen(5)

    print("Proxy listening on localhost:8888, forwarding to 10.0.0.138:8888")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(client_socket,)).start()
    except KeyboardInterrupt:
        print("\nShutting down proxy...")
        server_socket.close()

if __name__ == "__main__":
    main()