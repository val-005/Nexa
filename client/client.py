import socket, threading, ast, uuid, requests

from ecies import encrypt, decrypt
from ecies.utils import generate_eth_key

available_nodes = []

def get_nodes():
	url = "https://bootstrap.nexachat.tech/upNodes"
	response = requests.get(url)
	response.raise_for_status()
	nodes = response.json()
	return nodes


def async_getnodes(interval=60):
	global available_nodes
	print("Tentative de connection aux nœuds...")
	available_nodes = get_nodes()
	if len(available_nodes) == 0:
		print("Aucun noeud en ligne.")
	else:
		print("Mise à jour des noeuds :", available_nodes)
	threading.Timer(interval, async_getnodes, [interval]).start()

class Client:

	def __init__(self, host: str, port: int):
		self.host = host
		self.port = port
		self.keys = generate_eth_key()
		self.privKey = self.keys.to_hex()
		self.pubKey = self.keys.public_key.to_compressed_bytes().hex()
		
		self.seen_messages = set()																	# Cache pour éviter d'afficher les messages dupliqués
		self.quitting = False																	# Permet de fermer la connexion avec 'quit'


	def receive_message(self, client_socket: socket.socket) -> None:						# Gère la réception des messages
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
						#recipient = parts[2]
						msg_id = parts[3] if len(parts) > 3 else None
						
						if msg_id and msg_id in self.seen_messages:									# Si on a déjà vu ce message (par son ID), on l'ignore
							continue

						if msg_id:																# Ajouter à la liste des messages vus
							self.seen_messages.add(msg_id)
							
							if len(self.seen_messages) > 1000:								# Limiter la taille du cache
								self.seen_messages.pop()

						msg = decrypt(self.privKey, bytes.fromhex(content))					# Déchiffrement du message
						if str(msg).startswith("b'") and str(msg).endswith("'"):
							msg = ast.literal_eval(str(msg)).decode()
							new_msg = ""													# Message avec des "¤" au lieu des apostrophes
							for lettre in msg:
								if lettre == "¤":
									new_msg += "'"
								else:
									new_msg += lettre
							print(f"{sender}: {new_msg}")
					except Exception as e:
						pass
			except Exception as e:
				if not self.quitting:
					print(f"Erreur lors de la réception : {e}")
				break

	def start(self) -> None:										# Démarre le client, et permet d'envoyer des messages
		host = self.host							# Adresse du serveur
		port = self.port							# Port du serveur
		
		if host == "auto" and available_nodes:								# Si la var host est sur auto, on utilise un noeud disponible aléatoirement
			import random
			node = random.choice(available_nodes)
			node_parts = node.split(":")								# Séparation de la chaîne "host:port"
			host = node_parts[0]
			port = int(node_parts[1])
			print(f"Connexion automatique au noeud : {host}:{port}")

		client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		try:
			client_socket.connect((host, port))
		except socket.error as e:
			print(f"Erreur de connexion au serveur : {e}")
			return

		pseudo = input("Entrez votre pseudo : ")
		registration_msg = f"register;client;{pseudo}"
		client_socket.send(registration_msg.encode())
		print("\n=========================={ Connecté au serveur }============================")
		print(f"\nTa clé publique : {self.pubKey}")

		threadMsg = threading.Thread(target=self.receive_message, args=(client_socket,))			# Crée un processus pour recevoir les messages
		threadMsg.daemon = True
		threadMsg.start()

		while True:
			msg = input("")
			new_msg = ""													# Message avec des "¤" au lieu des apostrophes
			for lettre in msg:
				if lettre == "'":
					new_msg += "¤"
				else:
					new_msg += lettre
			
			if msg == 'quit':
				self.quitting = True
				client_socket.close()
				threadMsg.join()
				print("\nVous vous êtes déconnecté.")
				break
			
			to = input("Clé du destinataire : ")
			msg_id = str(uuid.uuid4())
			msgEncrypt = encrypt(to, new_msg.encode())
			msg_formaté = f"{pseudo};{msgEncrypt.hex()};{to};{msg_id};5"
			client_socket.send(msg_formaté.encode())

if __name__ == "__main__":
	cli = Client('127.0.0.1', 9102)
	cli.start()