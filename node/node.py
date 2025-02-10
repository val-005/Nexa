import socket
import threading
import time

class Node:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.client_list = []
        self.nodeSocket_list = []
        self.nodeIpPort_list = []

    def handle_client(self, client_socket: socket.socket, clients_list: list) -> None:
        while True:
            message = client_socket.recv(1024).decode()

            if message.split(';')[0] == 'register' and message.split(';')[1] == 'client':
                self.client_list.append(client_socket)

            print(f"Reçu: {message} par {client_socket.getpeername()[0]}")

            for client in clients_list:
                if client != client_socket and "register;" not in message:
                    client.send(message.encode())

            if 'quit' in message.lower():
                client_socket.close()
                break
    
    def connect_node(self, ip, port, etat) -> None:
        with threading.Lock():
            deSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            deSocket.settimeout(5)  # Ajout d'un timeout de 5 secondes
            try:
                if etat == 0:
                    print(f"tentative de connexion à {ip}:{port}")
                    deSocket.connect((ip, port))
            except socket.error as e:
                print(f"Erreur de connexion au serveur: {e}")
                deSocket.close()
                return
            print(f"Connecté à {ip}")
            
            try:
                deSocket.send(f"register;node;{self.host};{self.port}".encode())
            except socket.error as e:
                print(f"Erreur lors de l'envoi du message: {e}")

        self.nodeSocket_list.append(deSocket)
        for i in self.nodeIpPort_list:
            if i[0] == ip and i[1] == port:
                i[2] = 1
        
        

    def start(self) -> None:
        host = self.host
        port = self.port

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Écoute sur {host}:{port}")

        while True:
            client_socket, _ = server_socket.accept()
            thread = threading.Thread(
                target=self.handle_client,
                args=(client_socket, self.client_list)
            )
            thread.daemon = True
            thread.start()

    def connect_nodesList(self):
        while True:
            for node in self.nodeIpPort_list:
                if node[2] == 0:
                    t = threading.Thread(target=self.connect_node, args=(node[0], node[1], node[2])) 
                    t.start()
                    t.join()
            time.sleep(2)

if __name__ == "__main__":
    node = Node('0.0.0.0', 9102)
    t = threading.Thread(target=node.start)
    t.start()
    time.sleep(1)
    node.nodeIpPort_list.append(["192.168.194.126", 9102, 0])
    t2 = threading.Thread(target=node.connect_nodesList)
    t2.start()