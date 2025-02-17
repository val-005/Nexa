import socket, threading

from ecies import encrypt, decrypt
from ecies.utils import generate_eth_key

class Client:

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.keys = generate_eth_key()
        self.privKey = self.keys.to_hex()
        self.pubKey = self.keys.public_key.to_compressed_bytes().hex()

    def receive_message(self, client_socket: socket.socket) -> None:
        #gère la réception des messages
        while True:
            reponse = client_socket.recv(1024).decode()
            print(f"{reponse.split(';')[0]}: {reponse.split(';')[1]}")

    def start(self) -> None:
        #démarre le client
        host = self.host        # Adresse du serveur
        port = self.port        # Port du serveur

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            client_socket.connect((host, port))
        except socket.error as e:
            print(f"Erreur de connexion au serveur: {e}")
            return

        pseudo = input("Entrez votre pseudo : ")
        registration_msg = f"register;client;{pseudo}"
        client_socket.send(registration_msg.encode())
        print("Connecté au serveur !")
        print("===========================================\n")
        print(f"clé publique : {self.pubKey}")

        #crée un processus pour recevoir les messages
        threadMsg = threading.Thread(target=self.receive_message, args=(client_socket,))
        threadMsg.start()

        while True:
            msg = input("")
            if msg.lower() == 'quit':
                break

            to = input("To: ")

            msgEncrypt = encrypt(to, msg.encode())

            msg_formaté = f"{pseudo};{msgEncrypt};{to}"
            client_socket.send(msg_formaté.encode())
        
        client_socket.close()

if __name__ == "__main__":
    cli = Client('127.0.0.1', 9102) #adresse du serveur
    cli.start()