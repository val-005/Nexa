import socket, threading, ast, uuid

from ecies import encrypt, decrypt
from ecies.utils import generate_eth_key


class Client:

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.keys = generate_eth_key()
        self.privKey = self.keys.to_hex()
        self.pubKey = self.keys.public_key.to_compressed_bytes().hex()
        # Cache pour éviter d'afficher les messages dupliqués
        self.seen_messages = set()
        self.quitting = False               # Permettra de fermer la connexion avec 'quit'


    def receive_message(self, client_socket: socket.socket) -> None:
        # Gère la réception des messages
        while True:
            reponse = ""
            try:
                reponse = client_socket.recv(1024).decode()
                if not reponse:
                    print("Déconnecté du serveur.")
                    break
                    
                if "register;" not in reponse:
                    try:
                        parts = reponse.split(';')
                        sender = parts[0]
                        content = parts[1]
                        recipient = parts[2]
                        msg_id = parts[3] if len(parts) > 3 else None
                        
                        # Si on a déjà vu ce message (par son ID), on l'ignore
                        if msg_id and msg_id in self.seen_messages:
                            continue
                            
                        # Ajouter à la liste des messages vus
                        if msg_id:
                            self.seen_messages.add(msg_id)
                            
                            # Limiter la taille du cache
                            if len(self.seen_messages) > 1000:
                                self.seen_messages.pop()
                        
                        # Déchiffrement du message
                        msg = decrypt(self.privKey, bytes.fromhex(content))
                        if str(msg).startswith("b'") and str(msg).endswith("'"):
                            msg = ast.literal_eval(str(msg)).decode()
                            print(f"{sender}: {msg}")
                    except Exception as e:
                        pass
            except Exception as e:
                if not self.quitting:
                    print(f"Erreur lors de la réception : {e}")
                break

    def start(self) -> None:
        #démarre le client
        host = self.host        # Adresse du serveur
        port = self.port        # Port du serveur

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            client_socket.connect((host, port))
        except socket.error as e:
            print(f"Erreur de connexion au serveur : {e}")
            return

        pseudo = input("Entrez votre pseudo : ")
        registration_msg = f"register;client;{pseudo}"
        client_socket.send(registration_msg.encode())
        print("\n========================== Connecté au serveur ============================")
        print(f"\nTa clé publique : {self.pubKey}")

        # Crée un processus pour recevoir les messages
        threadMsg = threading.Thread(target=self.receive_message, args=(client_socket,))
        threadMsg.daemon = True  # Pour que le thread se termine avec le programme
        threadMsg.start()

        while True:
            msg = input("")

            if msg == 'quit':               # Si l'utilisateur souhaite fermer la connexion avec les noeuds.
                #print("\nTentative de déconnexion du serveur...")
                self.quitting = True

                try:
                    client_socket.close()   # Ferme proprement le socket
                except Exception as e:
                    print(f"Erreur lors de la déconnexion : {e}")

                threadMsg.join()            # Attend la fin du thread de réception
                print("\nVous vous êtes déconnecté.")
                break                       # Sort de la boucle après que tout soit bien fermé
            
            to = input("Clé du destinataire : ")
            
            # Générer un identifiant unique pour ce message
            msg_id = str(uuid.uuid4())
            
            try:
                msgEncrypt = encrypt(to, msg.encode())
            except Exception as e:
                print(f"Erreur lors du chiffrement : {e}")
                continue

            # Format: émetteur;message_chiffré;destinataire;ID_unique;TTL
            msg_formaté = f"{pseudo};{msgEncrypt.hex()};{to};{msg_id};5"
            try:
                client_socket.send(msg_formaté.encode())
            except Exception as e:
                print(f"Erreur lors de l'envoi : {e}")
                break
        
        client_socket.close()

if __name__ == "__main__":
    cli = Client('217.154.11.237', 9102)                 # Adresse du noeud
    #cli = Client('bootstrap.nexachat.tech', 9102)   # Adresse du bootstrap
    cli.start()