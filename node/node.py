import socket
import threading


class Node:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    def handle_client(self, client_socket: socket.socket, clients_list: list) -> None:
        while True:
            message = client_socket.recv(1024).decode()
            print(f"Reçu: {message} par {client_socket.getpeername()[0]}")
            for client in clients_list:
                if client != client_socket and "register;" not in message:
                    client.send(message.encode())
            if 'quit' in message.lower():
                client_socket.close()
                break

    def start(self) -> None:
        host = self.host
        port = self.port
        clients_list = []

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Écoute sur {host}:{port}")

        while True:
            client_socket, _ = server_socket.accept()
            clients_list.append(client_socket)
            thread = threading.Thread(
                target=self.handle_client,
                args=(client_socket, clients_list)
            )
            thread.daemon = True
            thread.start()


if __name__ == "__main__":
    node = Node('0.0.0.0', 8001)
    node.start()