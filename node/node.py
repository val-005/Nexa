import socket, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer

class Node:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.client_list = []
        self.nodeSocket_list = []
        self.nodeIpPort_list = []
        self.lock = threading.Lock()  # Ajout d'un verrou partagé

    def handleClient(self, client_socket: socket.socket) -> None:
        try:
            while True:
                try:
                    message = client_socket.recv(1024).decode()
                    
                    if not message:  # Connexion fermée
                        break
                        
                    # Format standardisé des messages
                    if not any(message.strip().endswith(f";{i}") for i in range(len(self.nodeIpPort_list))):
                        message += ";0"

                    print(f"Reçu: {message} par {client_socket.getpeername()[0]}")

                    # Enregistrement des clients
                    if "register;client;" in message:
                        with self.lock:
                            self.client_list.append(client_socket)
                    
                    # Enregistrement des nœuds et récupération de leur liste de clients
                    elif "register;node;" in message:
                        # Optionnel: extraire IP et port du nœud qui se connecte
                        parts = message.split(';')
                        if len(parts) >= 4:
                            node_ip = parts[2]
                            node_port = int(parts[3])
                            with self.lock:
                                # Vérifier s'il n'est pas déjà dans la liste
                                exists = False
                                for node in self.nodeIpPort_list:
                                    if node[0] == node_ip and node[1] == node_port:
                                        node[2] = 1  # Marquer comme connecté
                                        exists = True
                                if not exists:
                                    self.nodeIpPort_list.append([node_ip, node_port, 1])
                    
                    # Gestion des messages ordinaires
                    elif message != "register;":
                        # Permettre le relais même s'il n'y a aucun autre nœud connu ou si le compteur de sauts est valide
                        if len(self.nodeIpPort_list) == 0 or int(message.split(";")[3]) < len(self.nodeIpPort_list):
                            # Formattage du message et incrémentation du compteur de sauts
                            next_message = message.split(';')[0] + ";" + message.split(';')[1] + ";" + message.split(';')[2] + ';' + str(int(message.split(";")[3]) + 1)
                            
                            # Envoi aux clients locaux
                            self.removeClosedClients()
                            clients_copy = list(self.client_list)
                            for client in clients_copy:
                                if client != client_socket:  # Éviter de renvoyer au client d'origine
                                    try:
                                        client.send(next_message.encode())
                                    except (BrokenPipeError, ConnectionResetError):
                                        print(f"Le client s'est déconnecté.")
                                        if client in self.client_list:
                                            self.client_list.remove(client)
                            
                            # Envoi aux autres nœuds (une seule fois)
                            self.sendMessageNode(next_message)

                    if 'quit' in message.lower():
                        break
                        
                except (ConnectionResetError, BrokenPipeError) as e:
                    print(f"Erreur de connexion: {e}")
                    break
                    
        finally:
            # Nettoyage lorsque la connexion est fermée
            try:
                if client_socket in self.client_list:
                    self.client_list.remove(client_socket)
                client_socket.close()
            except:
                pass
    
    def removeClosedClients(self):
        """Supprime les clients déconnectés"""
        with self.lock:
            for client in list(self.client_list):
                try:
                    # Sauvegarde du timeout original
                    original_timeout = client.gettimeout()
                    # Test non bloquant
                    client.settimeout(0.1)
                    client.send(b'')  # Message vide pour tester la connexion
                    # Restauration du timeout original
                    client.settimeout(original_timeout)
                except:
                    if client in self.client_list:
                        self.client_list.remove(client)
    
    def removeClosedNodes(self):
        """Supprime les nœuds déconnectés"""
        with self.lock:
            for sock in list(self.nodeSocket_list):
                try:
                    # Sauvegarde du timeout original
                    original_timeout = sock.gettimeout()
                    # Test non bloquant
                    sock.settimeout(0.1)
                    sock.send(b'')  # Message vide pour tester la connexion
                    # Restauration du timeout original
                    sock.settimeout(original_timeout)
                except:
                    print(f"Suppression d'un nœud déconnecté")
                    if sock in self.nodeSocket_list:
                        self.nodeSocket_list.remove(sock)
                    # Mise à jour de l'état du nœud dans la liste
                    try:
                        for node in self.nodeIpPort_list:
                            if node[0] == sock.getpeername()[0]:
                                node[2] = 0  # Marquer comme déconnecté
                    except:
                        pass
    
    def connectNode(self, ip, port, etat) -> None:
        with self.lock:  # Utilisation du verrou partagé
            deSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            deSocket.settimeout(5)
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
                self.nodeSocket_list.append(deSocket)
                for i in self.nodeIpPort_list:
                    if i[0] == ip and i[1] == port:
                        i[2] = 1
            except socket.error as e:
                print(f"Erreur lors de l'envoi du message: {e}")
                deSocket.close()

    def connectNodesList(self):
        while True:
            self.removeClosedNodes()  # Nettoyer avant de tenter de nouvelles connexions
            for node in self.nodeIpPort_list:
                if node[2] == 0:
                    t = threading.Thread(target=self.connectNode, args=(node[0], node[1], node[2])) 
                    t.daemon = True  # Marquer comme daemon pour éviter de bloquer à la sortie
                    t.start()
                    t.join()
            time.sleep(2)

    def sendMessageNode(self, message: str) -> None:
        self.removeClosedNodes()  # Nettoyer avant d'envoyer
        nodes_copy = list(self.nodeSocket_list)  # Copie pour itération sécurisée
        for node in nodes_copy:
            try:
                node.send(message.encode())
            except socket.error as e:
                print(f"Erreur lors de l'envoi du message: {e}")
                if node in self.nodeSocket_list:
                    self.nodeSocket_list.remove(node)

    def start(self) -> None:
        host = self.host
        port = self.port

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Permet la réutilisation d'adresse
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Écoute sur {host} : {port}")

        while True:
            client_socket, _ = server_socket.accept()
            thread = threading.Thread(
                target=self.handleClient,
                args=(client_socket,)
            )
            thread.daemon = True
            thread.start()

class StatusHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/status':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'OK')
        else:
            self.send_error(404)

    # Désactiver les logs pour éviter la sortie standard inutile
    def log_message(self, format, *args):
        return

def run_http_server():
    httpd = HTTPServer(('0.0.0.0', 8080), StatusHTTPRequestHandler)
    print("Serveur HTTP (endpoint /status) démarré sur le port 8080")
    httpd.serve_forever()

if __name__ == "__main__":
    http_thread = threading.Thread(target=run_http_server)
    http_thread.daemon = True
    http_thread.start()
    node = Node('0.0.0.0', 9102)
    t = threading.Thread(target=node.start)
    t.start()
    time.sleep(1)
    node.nodeIpPort_list.append(["10.66.66.5", 9102, 0])
    #node.nodeIpPort_list.append(["10.66.66.2", 9102, 0])
    t2 = threading.Thread(target=node.connectNodesList)
    t2.start()