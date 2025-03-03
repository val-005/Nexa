import socket, threading
import ast

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
            if "register;" not in reponse:
                try:
                    msg = decrypt(self.privKey, bytes.fromhex(reponse.split(';')[1]))
                    if str(msg).startswith("b'") and str(msg).endswith("'"):
                        msg = ast.literal_eval(str(msg)).decode()
                        print(f"{reponse.split(';')[0]}: {msg}")
                except Exception as e:
                    print(f"Erreur lors du déchiffrement: {e}")

    def start(self) -> None:
        #démarre le client
        host = self.host        # Adresse du serveur
        port = self.port        # Port du serveur

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            client_socket.connect((host, port))
        except socket.error as e:
            print(f"Erreur de connexion au serveur: {e}")

        pseudo = input("Entrez votre pseudo : ")
        registration_msg = f"register;client;{pseudo}"
        client_socket.send(registration_msg.encode())
        print("\n===================== Connecté au serveur ======================\n")
        print(f"ta clé publique : {self.pubKey}")

        #crée un processus pour recevoir les messages
        threadMsg = threading.Thread(target=self.receive_message, args=(client_socket,))
        threadMsg.start()

        while True:
            msg = input("")
            if msg == 'quit':
                break
            for lettre in msg:
                if lettre == " ' ":
                    print("APPOSTROPHE DETECTEE")

            to = input("To: ")
            
            try:
                msgEncrypt = encrypt(to, msg.encode())
            except Exception as e:
                print(f"Erreur lors du chiffrement: {e}")
                continue

            msg_formaté = f"{pseudo};{msgEncrypt.hex()};{to}"
            client_socket.send(msg_formaté.encode())
        
        client_socket.close()

if __name__ == "__main__":
    cli = Client('127.0.0.1', 9102) #adresse du serveur
    cli.start()