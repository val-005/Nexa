import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

class Node:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.client_list = []
        self.nodeSocket_list = []
        self.nodeIpPort_list = []

    def handleClient(self, client_socket: socket.socket) -> None:
        while True:
            message = client_socket.recv(1024).decode()
            message += ";0"

            print(f"Reçu: {message} par {client_socket.getpeername()[0]}")

            if "register;client;" in message:
                self.client_list.append(client_socket)

            if message != "register;" and message.split(";")[2] == "0":
                self.sendMessageNode(message.split(';')[0] + ";" + message.split(';')[1] + ";" + str(int(message.split(';')[2]) + 1))
            
            elif message != "register;" and message.split(";")[2] == "1":
                for client in self.client_list:
                    client.send(message.encode())


            if 'quit' in message.lower():
                client_socket.close()
                break
    
    def connectNode(self, ip, port, etat) -> None:
        with threading.Lock():
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
            except socket.error as e:
                print(f"Erreur lors de l'envoi du message: {e}")

        self.nodeSocket_list.append(deSocket)
        for i in self.nodeIpPort_list:
            if i[0] == ip and i[1] == port:
                i[2] = 1

    def connectNodesList(self):
        while True:
            for node in self.nodeIpPort_list:
                if node[2] == 0:
                    t = threading.Thread(target=self.connectNode, args=(node[0], node[1], node[2])) 
                    t.start()
                    t.join()
            time.sleep(2)

    def sendMessageNode(self, message: str) -> None:
        for node in self.nodeSocket_list:
            try:
                node.send(message.encode())
            except socket.error as e:
                print(f"Erreur lors de l'envoi du message: {e}")


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
    httpd = HTTPServer(('0.0.0.0', 80), StatusHTTPRequestHandler)
    print("Serveur HTTP (endpoint /status) démarré sur le port 80")
    httpd.serve_forever()

if __name__ == "__main__":
    http_thread = threading.Thread(target=run_http_server)
    http_thread.daemon = True
    http_thread.start()
    node = Node('0.0.0.0', 9102)
    t = threading.Thread(target=node.start)
    t.start()
    time.sleep(1)
    node.nodeIpPort_list.append(["192.168.194.126", 9102, 0])
    t2 = threading.Thread(target=node.connectNodesList)
    t2.start()