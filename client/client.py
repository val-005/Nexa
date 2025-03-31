import asyncio, websockets, threading, ast, uuid, requests, pyperclip, random

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
		
		self.seen_messages = set()  # Cache pour éviter d'afficher les messages dupliqués
		self.quitting = False  # Permet de fermer la connexion avec 'quit'
		
		# Créer un event loop pour les opérations asynchrones
		self.loop = asyncio.new_event_loop()
		asyncio.set_event_loop(self.loop)
		self.websocket = None
		
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
							continue  # Ignorer les messages déjà vus
						
						if msg_id:
							self.seen_messages.add(msg_id)
							
							if len(self.seen_messages) > 1000:
								self.seen_messages.pop()  # Limiter la taille du cache
						
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
				print(f"Erreur lors de la réception : {e}")
	
	async def connect_and_send(self):
		"""Établit une connexion WebSocket et gère l'envoi de messages"""
		host = self.host
		port = self.port
		
		if host == "auto" and available_nodes:
			node = random.choice(available_nodes)
			node_parts = node.split(":")
			host = node_parts[0]
			port = int(node_parts[1])
			print(f"Connexion automatique au noeud : {host}:{port}")
		
		uri = f"ws://{host}:{port}"
		try:
			async with websockets.connect(uri) as websocket:
				self.websocket = websocket
				
				# Envoyer le message d'enregistrement
				pseudo = ""
				while not pseudo.strip():
					pseudo = input("Entrez votre pseudo : ")
					if not pseudo.strip():
						print("\nTu ne peux pas avoir un pseudo vide.")
				registration_msg = f"register;client;{pseudo}"
				await websocket.send(registration_msg)
				
				print("\n=========================={ Connecté au serveur }============================")
				print(f"\nTa clé publique : {self.pubKey}")
				
				# Démarrer une tâche pour recevoir les messages
				receive_task = asyncio.create_task(self.receive_messages())
				
				# Boucle pour envoyer des messages
				while True:
					# Utiliser asyncio.to_thread pour les opérations bloquantes comme input()
					msg = await asyncio.to_thread(input, "")
					
					new_msg = ""  # Message avec des "¤" au lieu des apostrophes
					for lettre in msg:
						if lettre == "'":
							new_msg += "¤"
						else:
							new_msg += lettre
					
					if msg == 'quit':
						self.quitting = True
						break

					elif msg == 'copy':
						pyperclip.copy(self.pubKey)
						print("Ta clé publique a bien été copiée.")
						continue
					
					to = await asyncio.to_thread(input, "Clé du destinataire : ")
					msg_id = str(uuid.uuid4())
					try:
						msgEncrypt = encrypt(to, new_msg.encode())
					except Exception as e:
						print(f"Erreur lors du chiffrement avec la clé du destinataire: {e}")
						continue
					msg_formaté = f"{pseudo};{msgEncrypt.hex()};{to};{msg_id};5"
					await websocket.send(msg_formaté)
				
				# Annuler la tâche de réception des messages
				receive_task.cancel()
				print("\nVous vous êtes déconnecté.")
		
		except websockets.exceptions.ConnectionClosed:
			print("Connexion fermée par le serveur.")
		except Exception as e:
			print(f"Erreur de connexion : {e}")
	
	def start(self):
		"""Démarre le client"""
		try:
			self.loop.run_until_complete(self.connect_and_send())
		except KeyboardInterrupt:
			print("\nClient arrêté par l'utilisateur.")
		finally:
			self.loop.close()

if __name__ == "__main__":
	async_getnodes()  # A mettre en commentaire pour se connecter en localhost
	cli = Client('auto', 9102)  # "auto" pour se connecter aléatoirement à un noeud
	# cli = Client('217.154.11.237', 9102)
	cli.start()