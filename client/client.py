import asyncio, websockets, threading, ast, uuid, requests, pyperclip, random, sys, os, platform, signal, sqlite3

from ecies import encrypt, decrypt
from ecies.utils import generate_eth_key

# Chemin du répertoire du script actuel
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

available_nodes = []

def get_nodes():
	'''
	Récupère la liste des noeuds sur le bootstrap
	'''
	url = "https://bootstrap.nexachat.tech/upNodes"
	response = requests.get(url)
	response.raise_for_status()
	nodes = response.json()
	return nodes

def async_getnodes(interval=60):
	'''
	Exécute la fonction get_nodes toutes les 60 secondes
	'''
	global available_nodes
	available_nodes = get_nodes()
	if len(available_nodes) == 0:
		print("Aucun noeud en ligne.")
	threading.Timer(interval, async_getnodes, [interval]).start()

class Client:
	def __init__(self, host: str, port: int = 0):
		'''
		initialise le client, stock dans ses attributs :
		- le port du noeud auquel on veut se connecter
		- l'ip du noeud auquel on veut se connecter

		- notre clé privée
		- notre clé publique

		enregistre dans le fichier privkey.key nos clés
		'''
		self.host = host
		self.port = port
		
		# Chemin absolu pour privkey.key
		privkey_path = os.path.join(SCRIPT_DIR, "privkey.key")
		
		try:
			with open(privkey_path, "r") as f:
				content = f.read().strip()
				if not content:
					self.keys = generate_eth_key()
					self.privKey = self.keys.to_hex()
					self.pubKey = self.keys.public_key.to_compressed_bytes().hex()
					with open(privkey_path, "w") as f2:
						f2.write(self.privKey + "\n" + self.pubKey)
				else:
					lines = content.splitlines()
					if len(lines) == 2:
						self.privKey = lines[0]
						self.pubKey = lines[1]
					else:
						print("Format de fichier de clés incorrect, régénération...")
						self.keys = generate_eth_key()
						self.privKey = self.keys.to_hex()
						self.pubKey = self.keys.public_key.to_compressed_bytes().hex()
						with open(privkey_path, "w") as f2:
							f2.write(self.privKey + "\n" + self.pubKey)
		except FileNotFoundError:
			self.keys = generate_eth_key()
			self.privKey = self.keys.to_hex()
			self.pubKey = self.keys.public_key.to_compressed_bytes().hex()
			with open(privkey_path, "w") as f:
				f.write(self.privKey + "\n" + self.pubKey)
        
		self.seen_messages = set()
		self.quitting = False
        
		self.loop = asyncio.new_event_loop()
		asyncio.set_event_loop(self.loop)
		self.websocket = None

		# Chemin absolu pour contacts.db
		contacts_db_path = os.path.join(SCRIPT_DIR, "contacts.db")
		self.db = sqlite3.connect(contacts_db_path)
		self.cursor = self.db.cursor()
		self.cursor.execute("CREATE TABLE IF NOT EXISTS contacts (pseudo TEXT PRIMARY KEY, pubkey TEXT)")
		self.db.commit()
		
	async def receive_messages(self):
		'''
		gère la réception des messages en continu,
		essaie de les déchiffrer, s'il y arrive, affiche le message, sinon, ne fait rien
		'''
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
							continue
						
						if msg_id:
							self.seen_messages.add(msg_id)
							if len(self.seen_messages) > 1000:
								self.seen_messages.pop()
						
						msg = decrypt(self.privKey, bytes.fromhex(content))
						if str(msg).startswith("b'") and str(msg).endswith("'"):
							msg = ast.literal_eval(str(msg)).decode()
							new_msg = ""
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
		'''
		établit une connection websocket avec le noeud et envoie les messages

		plusieurs fonctionnalités disponibles :
		- quit : ferme l'application
		- copy : copie la clé publique

		chiffre les messages avant de les envoyer
		'''
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
		
				pseudo = ""
				while not pseudo.strip():
					pseudo = input("Entrez votre pseudo : ")
					if not pseudo.strip():
						print("\nTu ne peux pas avoir un pseudo vide.")
					elif pseudo == 'quit':
						self.quitting = True
						print("\nTentative de fermeture du programme...")
						
						if platform.system() == "Windows":
							os.system("taskkill /F /PID " + str(os.getppid()) + " >nul 2>&1")
						else:
							os.kill(os.getpid(), signal.SIGTERM)
							sys.exit(0)
						
				registration_msg = f"register;client;{pseudo};{self.pubKey}"
				await websocket.send(registration_msg)
				
				print("\n=========================={ Connecté au serveur }============================")
				print(f"\nTa clé publique : {self.pubKey}")

				def list_contacts():
					self.cursor.execute("SELECT pseudo, pubkey FROM contacts")
					rows = self.cursor.fetchall()
					if not rows:
						print("Aucun contact enregistré.")
					else:
						print("\n{ Contacts enregistrés }")
						for pseudo, pubkey in rows:
							print(f"{pseudo} : {pubkey}")
						print()

				def add_contact():
					pseudo = input("Entrer un pseudo : ").strip()
					pubkey = input("Entrer la clé publique : ").strip()
					if not pseudo or not pubkey:
						print("Pseudo ou clé publique manquant.")
						return
					try:
						self.cursor.execute("INSERT INTO contacts (pseudo, pubkey) VALUES (?, ?)", (pseudo, pubkey))
						self.db.commit()
						print("Contact ajouté.")
					except sqlite3.IntegrityError:
						print("Ce pseudo existe déjà.")
				
				receive_task = asyncio.create_task(self.receive_messages())
				
				while True:
					msg = await asyncio.to_thread(input, "")
					if msg == "contacts":
						while True:
							cmd = await asyncio.to_thread(input, "voir / ajouter / retour : ")
							if cmd == "voir":
								list_contacts()
							elif cmd == "ajouter":
								add_contact()
							elif cmd == "retour":
								break
							else:
								print("Commande inconnue.")
						continue
					
					new_msg = ""
					for lettre in msg:
						if lettre == "'":
							new_msg += "¤"
						else:
							new_msg += lettre
					
					if msg == 'quit':
						self.quitting = True
						print("\nTentative de fermeture du programme...")
						receive_task.cancel()
						if platform.system() == "Windows":
							os.system("taskkill /F /PID " + str(os.getppid()) + " >nul 2>&1")
						else:
							os.kill(os.getpid(), signal.SIGTERM)
							sys.exit(0)

					elif msg == 'copy':
						pyperclip.copy(self.pubKey)
						print("Ta clé publique a bien été copiée.")
						continue

					to = await asyncio.to_thread(input, "Clé du destinataire ou pseudo : ")
					self.cursor.execute("SELECT pubkey FROM contacts WHERE pseudo = ?", (to,))
					result = self.cursor.fetchone()
					if result:
						to = result[0]
					elif not (len(to) == 66 and to.startswith("0")):
						print("Aucun contact trouvé et ce n’est pas une clé publique valide.")
						continue

					msg_id = str(uuid.uuid4())
					try:
						msgEncrypt = encrypt(to, new_msg.encode())
						await websocket.send(f"{pseudo};{msgEncrypt.hex()};{to};{msg_id}")
					except Exception as e:
						print(f"Erreur de chiffrement/envoi : {e}")
		
		except websockets.exceptions.ConnectionClosed:
			print("Connexion fermée par le serveur.")
		except Exception as e:
			print(f'Erreur de connexion au serveur. ("{e}")')
	
	def start(self):
		'''
		démarre le client
		'''
		try:
			self.loop.run_until_complete(self.connect_and_send())
		except KeyboardInterrupt:
			self.quitting = True
			print("\nTentative de fermeture du programme...")
			if platform.system() == "Windows":
				os.system("taskkill /F /PID " + str(os.getppid()) + " >nul 2>&1")
			else:
				os.kill(os.getpid(), signal.SIGTERM)
			sys.exit(0)
		finally:
			self.db.close()
			self.loop.close()

if __name__ == "__main__":
	async_getnodes()
	cli = Client('auto')				# "auto" pour se connecter aléatoirement à un noeud
	cli.start()