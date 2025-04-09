import asyncio, websockets, threading, ast, uuid, requests, pyperclip, random, sys, os, platform, signal

from ecies import encrypt, decrypt
from ecies.utils import generate_eth_key

# Créer une liste globale pour stocker les nœuds disponibles
available_nodes = []
node_detection_callback = None  # Callback pour notifier l'interface de la mise à jour des nœuds

# Fonction asynchrone pour récupérer les nœuds disponibles
def async_getnodes():
    """Lance la recherche de nœuds disponibles en arrière-plan"""
    global available_nodes
    
    def worker():
        global available_nodes
        try:
            # Récupérer les nœuds avec un timeout plus court
            nodes = Client.getnodes(timeout=0.5)
            # Mettre à jour la liste globale
            available_nodes = nodes
            #print(f"Nœuds détectés: {len(nodes)}")
            
            # Notifier l'interface utilisateur si un callback est défini
            if node_detection_callback:
                node_detection_callback(nodes)
        except Exception as e:
            print(f"Erreur lors de la recherche des nœuds: {e}")
    
    # Lancer dans un thread pour ne pas bloquer l'interface
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    
    # Planifier la prochaine actualisation
    if threading.current_thread() is threading.main_thread():
        # Si on est dans le thread principal, on peut utiliser after
        import tkinter as tk
        if tk._default_root:
            tk._default_root.after(10000, async_getnodes)  # Actualiser toutes les 10 secondes
    
    return available_nodes

def verify_key(key):
    """Vérifie si une clé publique ETH est valide
    
    Args:
        key (str): La clé publique à vérifier
        
    Returns:
        bool: True si la clé est valide, False sinon
    """
    # Vérifier si la clé est vide
    if not key or len(key.strip()) == 0:
        return False
    
    # Vérifier la longueur de la clé ETH (généralement 64 ou 66 caractères hexadécimaux)
    # Une clé ETH compressée est généralement de 66 caractères (avec 0x préfixe) 
    # ou 64 caractères (sans préfixe)
    if len(key) < 40:  # Longueur minimale pour une clé ETH
        return False
    
    # Vérifier que la clé contient uniquement des caractères hexadécimaux
    # On accepte aussi le préfixe '0x' optionnel
    valid_key = key
    if key.startswith('0x'):
        valid_key = key[2:]  # Enlever le préfixe 0x
        
    try:
        # Tenter de convertir en hexadécimal pour validation
        int(valid_key, 16)
        return True
    except ValueError:
        return False

class Client:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        try:
            with open("privkey.key", "r") as f:
                content = f.read().strip()
                if not content:											# Si le fichier ne contient aucune clé
                    self.keys = generate_eth_key()
                    self.privKey = self.keys.to_hex()
                    self.pubKey = self.keys.public_key.to_compressed_bytes().hex()
                    with open("privkey.key", "w") as f2:
                        f2.write(self.privKey + "\n" + self.pubKey)
                else:
                    lines = content.splitlines()
                    if len(lines) == 2:
                        self.privKey = lines[0]
                        self.pubKey = lines[1]
                    else:												# Si le fichier n'a qu'une seule clé'
                        print("Format de fichier de clés incorrect, régénération...")
                        self.keys = generate_eth_key()
                        self.privKey = self.keys.to_hex()
                        self.pubKey = self.keys.public_key.to_compressed_bytes().hex()
                        with open("privkey.key", "w") as f2:
                            f2.write(self.privKey + "\n" + self.pubKey)
        except FileNotFoundError:										# Si le fichier n'existe pas
            self.keys = generate_eth_key()
            self.privKey = self.keys.to_hex()
            self.pubKey = self.keys.public_key.to_compressed_bytes().hex()
            with open("privkey.key", "w") as f:
                f.write(self.privKey + "\n" + self.pubKey)
        
        self.seen_messages = set()	# Cache pour éviter d'afficher les messages dupliqués
        self.quitting = False 		# Permet de fermer la connexion avec 'quit'
        
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.websocket = None
        
    @staticmethod
    def getnodes(timeout=60):
        url = "https://bootstrap.nexachat.tech/upNodes"
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        nodes = response.json()
        return nodes
        
    async def receive_messages(self):
        """Gère la réception des messages en continu"""
        try:
            async for message in self.websocket:
                if not message:
                    print("Déconnecté du serveur.")
                    break
                
                if "register;" not in message:
                    try:
                        parts = message.split(';')
                        sender = parts[0]
                        content = parts[1]
                        msg_id = parts[3] if len(parts) > 3 else None
                        
                        if msg_id and msg_id in self.seen_messages:
                            continue  # Ignore les messages déjà vus
                        
                        if msg_id:
                            self.seen_messages.add(msg_id)
                            
                            if len(self.seen_messages) > 1000:
                                self.seen_messages.pop()  # Limite la taille du cache
                        
                        msg = decrypt(self.privKey, bytes.fromhex(content))  # Déchiffrement du message
                        if str(msg).startswith("b'") and str(msg).endswith("'"):
                            msg = ast.literal_eval(str(msg)).decode()
                            new_msg = ""  # Message avec des "'" au lieu des "¤"
                            for lettre in msg:
                                if lettre == "¤":
                                    new_msg += "'"
                                else:
                                    new_msg += lettre
                            print(f"{sender}: {new_msg}")
                    except Exception as e:
                        pass
        except websockets.exceptions.ConnectionClosed:
            if not self.quitting:
                print("Connexion au serveur perdue.")
        except Exception as e:
            if not self.quitting:
                print(f'Erreur lors de la réception du message. ("{e}")')
    
    async def connect_and_send(self):
        """Établit une connexion WebSocket et gère l'envoi de messages"""
        host = self.host
        port = self.port
        
        # Variable pour contrôler la boucle de demande de clé
        self.key_requested = False
        self.msg_to_send = None
        
        if host == "auto" and available_nodes:
            node = random.choice(available_nodes)
            node_parts = node.split(":")
            host = node_parts[0]
            port = int(node_parts[1])
            #print(f"Connexion automatique au noeud : {host}:{port}")
        
        uri = f"ws://{host}:{port}"
        try:
            async with websockets.connect(uri) as websocket:
                self.websocket = websocket
        
                pseudo = ""
                while not pseudo.strip():
                    pseudo = input("Entrez votre pseudo : ")
                    if not pseudo.strip():
                        print("\nTu ne peux pas avoir un pseudo vide.")
                    elif pseudo == 'quit':
                        self.quitting = True
                        print("Fermeture du programme...\n")
                        
                        # Détermine l'OS et ferme le programme
                        if platform.system() == "Windows":
                            os.system("taskkill /F /PID " + str(os.getppid()))
                        else:  														# Systèmes Linux/Unix
                            os.kill(os.getpid(), signal.SIGTERM)
                            sys.exit(0)
                        
                registration_msg = f"register;client;{pseudo}"
                await websocket.send(registration_msg)
                
                #print("\n=========================={ Connecté au serveur }============================")
                #print(f"\nTa clé publique : {self.pubKey}")
                
                # Démarrer une tâche pour recevoir les messages
                receive_task = asyncio.create_task(self.receive_messages())
                
                # Boucle pour envoyer des messages
                while True:
                    if self.key_requested and self.msg_to_send:
                        # Demander la clé du destinataire
                        key = input("Clé du destinataire : ")
                        
                        # Si la clé est vide, on attend un peu et on réessaie
                        if not key or key.strip() == "":
                            await asyncio.sleep(0.5)
                            continue
                            
                        # Si l'utilisateur demande de quitter
                        if key == 'quit':
                            self.quitting = True
                            print("Fermeture du programme...\n")
                            receive_task.cancel()
                            if platform.system() == "Windows":
                                os.system("taskkill /F /PID " + str(os.getppid()))
                            else:
                                os.kill(os.getpid(), signal.SIGTERM)
                                sys.exit(0)
                        
                        # Essayer d'envoyer le message avec cette clé
                        try:
                            msg_id = str(uuid.uuid4())
                            msgEncrypt = encrypt(key, self.msg_to_send.encode())
                            await websocket.send(f"{pseudo};{msgEncrypt.hex()};{key};{msg_id}")
                            # Réinitialiser pour permettre un nouveau message
                            self.key_requested = False
                            self.msg_to_send = None
                            continue
                        except Exception as e:
                            print(f'Erreur : tu as mal entré la clé publique. ("{e}")')
                            # On ne réinitialise pas key_requested pour redemander la clé
                            continue
                    else:
                        # Attendre un nouveau message
                        msg = await asyncio.to_thread(input, "")
                        
                        if msg == 'quit':
                            self.quitting = True
                            print("Fermeture du programme...\n")
                            receive_task.cancel()
                            if platform.system() == "Windows":
                                os.system("taskkill /F /PID " + str(os.getppid()))
                            else:
                                os.kill(os.getpid(), signal.SIGTERM)
                                sys.exit(0)
                        elif msg == 'copy':
                            pyperclip.copy(self.pubKey)
                            print("Ta clé publique a bien été copiée.")
                        elif msg.strip():
                            # Préparer le message pour l'envoi (remplacer les apostrophes)
                            new_msg = ""
                            for lettre in msg:
                                if lettre == "'":
                                    new_msg += "¤"
                                else:
                                    new_msg += lettre
                            
                            # Stocker le message et demander la clé
                            self.msg_to_send = new_msg
                            self.key_requested = True
                            print("Clé du destinataire : ")
        
        except websockets.exceptions.ConnectionClosed:
            print("Connexion fermée par le serveur.")
        except Exception as e:
            print(f'Erreur de connexion au serveur. ("{e}")')
            
            # Déterminer l'OS et fermer le programme si nécessaire
            if platform.system() == "Windows":
                os.system("taskkill /F /PID " + str(os.getppid()))
            else:
                os.kill(os.getpid(), signal.SIGTERM)
                sys.exit(0)
    
    def start(self):
        """Démarre le client"""
        try:
            self.loop.run_until_complete(self.connect_and_send())
        except KeyboardInterrupt:
            self.quitting = True
            print("\nFermeture du programme...\n")

            # Détermine l'OS et ferme le programme
            if platform.system() == "Windows":
                os.system("taskkill /F /PID " + str(os.getppid()))
            else:  														# Systèmes Linux/Unix
                os.kill(os.getpid(), signal.SIGTERM)
            sys.exit(0)
        finally:
            self.loop.close()

if __name__ == "__main__":
    async_getnodes()  						# Tests en localhost
    #cli = Client('10.66.66.5', 9102)		# Tests en localhost
    cli = Client('auto', 9102)				# "auto" pour se connecter aléatoirement à un noeud
    cli.start()