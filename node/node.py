import socket
import threading


class Node:
    def __init__(self, host, port):
        """Création de l'objet Node avec l'hôte, le port et les pairs."""
        self.host = host
        self.port = port
        self.peers = []         # Connexions sortantes initiées par ce nœud
        self.connections = {}   # Connexions entrantes avec leurs adresses
        self.data = ""

    def start_server(self):
        """Démarrage du serveur."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        print(f"Écoute sur {self.host}:{self.port}")

        while True:
            conn, addr = server.accept()
            print(f"Connexion acceptée de {addr}")

            # Vérification pour éviter les connexions en double
            if addr not in self.connections and not self.is_peer(conn, addr):
                self.connections[addr] = conn
                threading.Thread(target=self.handle_client, args=(conn, addr)).start()

    def handle_client(self, conn, addr):
        '''Gestion des messages entrants et réponse.'''
        try:
            while True:
                data = conn.recv(1024)
                if not data:  # Si message vide, sortir de la boucle
                    break
                self.data = data.decode("utf-8")
                print(self.data)
        except Exception as e:
            print(f"Erreur avec {addr}: {e}")
        finally:
            conn.close()
            if addr in self.connections:
                del self.connections[addr]
            print(f"Connexion fermée avec {addr}")

    def connect_node(self, ip, port):
        """Connexion à un autre nœud."""
        peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if not self.is_peer(ip, port):
            peer.connect((ip, port))
            self.peers.append(peer)
            peer.send(f"node!{self.host}!{self.port}".encode())

    def is_peer(self, ip_or_conn, port=None):
        """
        Vérifie si le couple (hôte, port) est déjà un pair.
        Peut accepter soit une connexion et son adresse (tuple) soit directement (ip, port).
        """
        if port is None:
            # Cas où ip_or_conn est une connexion et port est en fait une adresse tuple
            addr = ip_or_conn.getpeername()
        else:
            addr = (ip_or_conn, port)

        for peer in self.peers:
            if peer.getpeername() == addr:
                return True
        return False


if __name__ == "__main__":
    node = Node("0.0.0.0", 8000)
    node.start_server()