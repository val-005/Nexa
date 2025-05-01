import os, sys, threading, time, asyncio, random, sqlite3, configparser, re, queue, concurrent.futures, platform, signal, requests, pyperclip, websockets, ast, locale, uuid, tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, StringVar
from datetime import datetime, timedelta
from ecies import encrypt, decrypt
from ecies.utils import generate_eth_key
from PIL import Image, ImageTk

if getattr(sys, 'frozen', False):
    SCRIPT_DIR = sys._MEIPASS
else:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Définir le dossier des données (AppData\Roaming\NexaChat)
appdata = os.getenv('APPDATA') or os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming')
DATA_DIR = os.path.join(appdata, 'NexaChat')
os.makedirs(DATA_DIR, exist_ok=True)

# Chemin pour lecture et écriture
SETTINGS_BUNDLE_PATH = os.path.join(SCRIPT_DIR, "settings.ini")
SETTINGS_USER_PATH = os.path.join(DATA_DIR, "settings.ini")

try:
	locale.setlocale(locale.LC_TIME, 'fr_FR.UTF-8')
except:
	try:
		locale.setlocale(locale.LC_TIME, 'fr_FR')
	except:
		try:
			locale.setlocale(locale.LC_TIME, 'fra_fra')
		except:
			pass

# Variable globales
available_nodes = []
node_detection_callback = None
app = None
stop_async_getnodes = False

# Fonction utilitaire pour assombrir une couleur hexadécimale
def darken(hex_color, factor=0.8):
    r = int(hex_color[1:3], 16)
    g = int(hex_color[3:5], 16)
    b = int(hex_color[5:7], 16)
    return f"#{int(r*factor):02x}{int(g*factor):02x}{int(b*factor):02x}"

# Fonction calculant la luminosité d'une couleur hexadécimale
def luminosite(hex_color):
    r = int(hex_color[1:3], 16)
    g = int(hex_color[3:5], 16)
    b = int(hex_color[5:7], 16)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b

# Fonction utilitaire pour afficher les erreurs de façon uniforme
def show_error(message, **kwargs):
    messagebox.showerror("Erreur", message, **kwargs)

# Choix de couleur de base et alias pour éviter doublons
base_colors = {
    'dark grey': ('#424242', '#212121'),		'dark blue': ('#1565c0', '#0d47a1'),
    'light green': ('#7ED957', '#388E3C'),		'light blue': ('#339CFF', '#1976D2'),
    'purple': ('#8e24aa', '#512da8'),			'red': ('#D50000', '#B71C1C'),
    'yellow': ('#FFEB3B', '#FBC02D'),			'green': ('#388E3C', '#1B5E20'),
    'pink': ('#FF69B4', '#C2185B'),				'black': ('#212121', '#000000'),
    'blue': ('#1976d2', '#0d47a1'),				'orange': ('#FF9800', '#F57C00'),
}
COLOR_CHOICES = dict(base_colors)
aliases = {
    'gris foncé': 'dark grey',				'bleu foncé': 'dark blue',
    'vert clair': 'light green',			'bleu clair': 'light blue',
	'bleu ciel': 'light blue',				'reset': 'light blue',
    'violet': 'purple', 'rouge':			'red', 'jaune': 'yellow',
    'vert': 'green',						'rose': 'pink',
	'noir': 'black', 						'bleu': 'blue',
}
for alias_name, ref in aliases.items():
    COLOR_CHOICES[alias_name] = base_colors[ref]

def parse_color_input(color_input):
	"""
	Permet d'utiliser /color #hex ou /color rgb(r,g,b) pour choisir la couleur principale.
	Retourne primary, secondary ou None si invalide.
	"""
	color_input = color_input.strip()
	# Format hexadécimal : #RRGGBB ou RRGGBB
	hex_match = re.fullmatch(r'#([0-9a-fA-F]{6})', color_input)
	if hex_match:
		primary = f"#{hex_match.group(1)}"
		# Génère une couleur secondaire plus foncée
		secondary = darken(primary)
		return (primary, secondary)
	# Format RGB : rgb(r,g,b) ou r,g,b
	rgb_match = re.fullmatch(r'rgb\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)', color_input, re.IGNORECASE)
	if rgb_match:
		r, g, b = map(int, rgb_match.groups())
		if all(0 <= v <= 255 for v in (r, g, b)):
			primary = f"#{r:02x}{g:02x}{b:02x}"
			secondary = darken(primary)
			return (primary, secondary)
	return None

def load_color_settings():
    config = configparser.ConfigParser()

    if os.path.exists(SETTINGS_USER_PATH):
        config.read(SETTINGS_USER_PATH)
    elif os.path.exists(SETTINGS_BUNDLE_PATH):
        config.read(SETTINGS_BUNDLE_PATH)

        os.makedirs(os.path.dirname(SETTINGS_USER_PATH), exist_ok=True)
        with open(SETTINGS_USER_PATH, 'w') as configfile:
            config.write(configfile)
    else:
        config['Colors'] = {'primary': '#339CFF', 'secondary': '#1976D2'}
        os.makedirs(os.path.dirname(SETTINGS_USER_PATH), exist_ok=True)
        with open(SETTINGS_USER_PATH, 'w') as configfile:
            config.write(configfile)
    if 'Colors' not in config:
        config['Colors'] = {'primary': '#339CFF', 'secondary': '#1976D2'}
    return config['Colors'].get('primary', '#339CFF'), config['Colors'].get('secondary', '#1976D2')

def save_color_settings(primary, secondary):
    config = configparser.ConfigParser()
    config['Colors'] = {'primary': primary, 'secondary': secondary}
    os.makedirs(os.path.dirname(SETTINGS_USER_PATH), exist_ok=True)
    with open(SETTINGS_USER_PATH, 'w') as configfile:
        config.write(configfile)

def signal_handler(sig, frame):					# sig, frame inutilisées mais nécessaires
	'''
	Ferme le programme quand Crtl+C est saisi.
	'''
	global app
	try:
		if app and hasattr(app, 'destroy'):
			app.destroy()
	except Exception:
		pass
	os._exit(0)

signal.signal(signal.SIGINT, signal_handler)

def get_nodes():
	'''
	Récupère la liste des noeuds sur le bootstrap.
	'''
	try:
		url = "https://bootstrap.nexachat.tech/upNodes"
		response = requests.get(url)
		response.raise_for_status()
		nodes = response.json()
		if node_detection_callback:
			node_detection_callback(nodes)
		return nodes
	except Exception as e:
		show_error(f"Erreur lors de la recherche des nœuds. ({e})")
		if node_detection_callback:
			node_detection_callback([])
		return []

def async_getnodes(interval=60):
	'''
	Exécute la fonction get_nodes toutes les 60 secondes.
	'''
	global available_nodes, stop_async_getnodes
	if stop_async_getnodes:
		return
	available_nodes = get_nodes()
	if not stop_async_getnodes:											# Ne relance le timer que si l'app n'est pas en train de fermer
		threading.Timer(interval, async_getnodes, [interval]).start()

class Client:
	def __init__(self, host: str, port: int = 0):
		'''
        Initialise le client, et stocke dans ses attributs :
        - le port du noeud auquel on veut se connecter
        - l'ip du noeud auquel on veut se connecter.
		Stocke la clé publique et la clé privée de l'utilisateur dans le fichier privkey.key.
        '''
		self.host = host
		self.port = port
		
		privkey_path = os.path.join(DATA_DIR, "privkey.key")			# Chemin clé publique et privée
		# Génère les clés
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
		self.seen_db = sqlite3.connect(os.path.join(DATA_DIR, "seen_messages.db"), check_same_thread=False)
		self.seen_cursor = self.seen_db.cursor()
		self.seen_cursor.execute('''CREATE TABLE IF NOT EXISTS seen_messages (msg_id TEXT PRIMARY KEY)''')
		self.seen_db.commit()
		for row in self.seen_cursor.execute('SELECT msg_id FROM seen_messages'):
			self.seen_messages.add(row[0])

		self.quitting = False
		self.key_requested = False		# Indique si le client attend une clé
		self.message_to_send = None		# Stocke temporairement le message à envoyer
		self.recipient_key = None		# Stocke temporairement la clé destinataire
		
		self.loop = asyncio.new_event_loop()
		asyncio.set_event_loop(self.loop)
		self.websocket = None

		db_path = os.path.join(DATA_DIR, "messagesUI.db")
		self.msg_db = sqlite3.connect(db_path, check_same_thread=False)

		self.contacts_db = sqlite3.connect(os.path.join(DATA_DIR, "contacts.db"), check_same_thread=False)
		self.contacts_cursor = self.contacts_db.cursor()
		self.contacts_cursor.execute('''CREATE TABLE IF NOT EXISTS contacts (
			pseudo TEXT NOT NULL UNIQUE,
			pubkey TEXT NOT NULL UNIQUE
		)''')
		self.contacts_db.commit()
		self.current_contact_pubkey = None

	@staticmethod
	def verify_key(key):
		'''
		Vérifie si une clé publique est au bon format hexadécimal compressé (66 hex).
		'''
		if isinstance(key, str) and key.strip() and len(key) == 66:
			try:
				bytes.fromhex(key)
				return True
			except ValueError:
				return False
		return None

	async def receive_messages(self):
		"""
		Gère la réception des messages en continu, essaie de les déchiffrer,
		s'il y arrive, affiche le message, sinon ne fait rien.
		"""
		try:
			async for message in self.websocket:
				if self.quitting or not self.websocket:
					return
				if not message:
					show_error("Déconnecté du serveur.")
					break
				if "register;" not in message:
					try:
						parts = message.split(';')
						sender = parts[0]
						content = parts[1]
						msg_id = parts[3] if len(parts) > 3 else None
						# Vérification persistante pour éviter la réception de messages déjà vus
						if msg_id and msg_id in self.seen_messages:
							continue
						if msg_id:
							self.seen_messages.add(msg_id)
							try:
								self.seen_cursor.execute('INSERT OR IGNORE INTO seen_messages (msg_id) VALUES (?)', (msg_id,))
								self.seen_db.commit()
							except Exception:
								pass
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
				show_error("Connexion au serveur perdue.")
		except Exception as e:
			if not self.quitting:
				show_error(f"Erreur lors de la réception du message. ({e})")

	async def send_message_with_key(self, message, recipient_key, pseudo):
		'''
		Méthode pour envoyer un message directement avec une clé (spécifiquement pour l'interface).
		'''
		if not self.websocket:
			show_error("Tu n'es pas connecté au serveur.")
			return False
		try:
			new_msg = ""
			for lettre in message:
				if lettre == "'":
					new_msg += "¤"
				else:
					new_msg += lettre

			if not Client.verify_key(recipient_key):
				show_error("Assure-toi d’avoir correctement saisi la clé publique !")
				return False
			msg_id = str(uuid.uuid4())
			msgEncrypt = encrypt(recipient_key, new_msg.encode())
			await self.websocket.send(f"{pseudo};{msgEncrypt.hex()};{recipient_key};{msg_id}")

			print(f"Toi: {message}")			# Affiche le message envoyé
			return True
		except Exception as e:
			show_error(f"Erreur lors de l'envoi du message. ({e})")
			return False

	async def connect_and_send(self):
		'''
        Etablit une connection websocket avec le noeud et envoie les messages.
        Chiffre les messages avant de les envoyer.
        '''
		host = self.host
		port = self.port
		if host == "auto" and available_nodes:
			node = random.choice(available_nodes)
			node_parts = node.split(":")
			host = node_parts[0]
			port = int(node_parts[1])
		uri = f"ws://{host}:{port}"
		try:
			async with websockets.connect(uri) as websocket:
				self.websocket = websocket
				asyncio.create_task(self.keep_connection_alive())
				pseudo = ""
				while not pseudo.strip():
					pseudo = input("Entrez votre pseudo : ")
					if not pseudo.strip():
						show_error("Tu ne peux pas avoir un pseudo vide.")
				registration_msg = f"register;client;{pseudo};{self.pubKey}"
				await websocket.send(registration_msg)
				asyncio.create_task(self.receive_messages())
				message_queue = asyncio.Queue()

				async def message_processor():
					while True:
						try:
							if self.quitting:
								break
							msg_data = await message_queue.get()
							message, recipient_key = msg_data
							new_msg = ""
							for lettre in message:
								if lettre == "'":		# Permet l'envoi d'appostrophes dans les messages
									new_msg += "¤"
								else:
									new_msg += lettre
							msg_id = str(uuid.uuid4())
							msgEncrypt = encrypt(recipient_key, new_msg.encode())	# Chiffre le message
							await websocket.send(f"{pseudo};{msgEncrypt.hex()};{recipient_key};{msg_id}")
							print(f"Toi: {message}")
							message_queue.task_done()
							await asyncio.sleep(0.01)		# Légère pause pour éviter de surcharger le serveur
						except asyncio.CancelledError:
							break
						except Exception as e:
							show_error("Assure-toi d'avoir correctement saisi la clé publique. Réessaie.")
							message_queue.task_done()
				
				processor_task = asyncio.create_task(message_processor())
				try:
					while True:
						if self.quitting:
							break
						if self.message_to_send and self.recipient_key:
							msg = self.message_to_send
							key = self.recipient_key
							self.message_to_send = None
							self.recipient_key = None
							if self.verify_key(key):
								await message_queue.put((msg, key))
							else:
								show_error("Clé du destinataire invalide.")
						try:
							await asyncio.sleep(0.05)
						except asyncio.CancelledError:
							break
				finally:
					processor_task.cancel()
					try:
						await processor_task
					except asyncio.CancelledError:
						pass
					
		except websockets.exceptions.ConnectionClosed:
			if not self.quitting:
				show_error("Connexion fermée par le serveur.")
		except asyncio.CancelledError:
			pass
		except Exception as e:
			if not self.quitting:
				show_error(f"Problème de connexion au serveur. ({e})")

	async def keep_connection_alive(self, interval=30):
		try:
			while True:
				await asyncio.sleep(interval)
				if self.websocket and not self.quitting:
					try:
						await self.websocket.ping()		# Ping envoyé pour maintenir la connexion active
					except Exception as e:
						await self.reconnect()			# Tentative de reconnexion si le ping échoue
		except Exception as e:
			if not self.quitting:
				show_error(f"Erreur inattendue dans le maintien de la connexion. ({e})")

	async def reconnect(self):
		'''
		Tente de se reconnecter au serveur en cas de déconnexion.
		'''
		try:
			await self.connect_and_send()
		except Exception as e:
			show_error(f"Échec de la reconnexion. ({e})")

	def start(self):
		'''
		Démarre le client.
		'''
		try:
			self.loop.run_until_complete(self.connect_and_send())
		except KeyboardInterrupt:
			self.quitting = True
			if platform.system() == "Windows":
				os.system("taskkill /F /PID " + str(os.getppid()))
			else:
				os.kill(os.getpid(), signal.SIGTERM)
			sys.exit(0)
		finally:
			self.loop.close()

class WrapperClient:
    def __init__(self):
        self.client = None
        self.client_thread = None
        self.quitting = False

    def start_client(self, host="auto", port=9102):
        if self.client_thread and self.client_thread.is_alive():
            return False
            
        self.client = Client(host, port)
        self.quitting = False
        self.client_thread = threading.Thread(target=self._run_client)
        self.client_thread.daemon = True
        self.client_thread.start()
        return True
        
    def _run_client(self):
        try:
            self.client.start()
        except Exception as e:
            if "Event loop stopped before Future completed" not in str(e):
                show_error(f"Erreur dans le client. ({e})")
        finally:
            self.client = None
        
    def stop_client(self):
        if not self.client:
            return
            
        self.quitting = True
        if self.client:
            self.client.quitting = True
            
        # Ferme la websocket et annuler toutes les tâches en cours ou en attente
        try:
            if hasattr(self.client, 'websocket') and self.client.websocket:
                loop = self.client.loop
                if loop and loop.is_running():
                    for task in asyncio.all_tasks(loop):
                        task.cancel()
                    coro = self.client.websocket.close()
                    future = asyncio.run_coroutine_threadsafe(coro, loop)
                    try:
                        future.result(timeout=1.0)			# Attend la fermeture avec timeout
                    except (asyncio.TimeoutError, concurrent.futures.TimeoutError, Exception):
                        pass
        except Exception as e:
            pass
            
        # Attend que le thread du client se termine
        max_wait = 2.0  # secondes
        start_time = time.time()
        while self.client_thread and self.client_thread.is_alive() and time.time() - start_time < max_wait:
            time.sleep(0.1)

        if self.client and hasattr(self.client, 'loop') and self.client.loop:
            try:
                loop = self.client.loop
                if loop.is_running():
                    for task in asyncio.all_tasks(loop):
                        if not task.done():
                            task.cancel()
                    loop.call_soon_threadsafe(loop.stop)
            except Exception:
                pass
                
        # Nettoyer le client
        self.client = None

# Interface graphique
class MessageRedirect:
	def __init__(self, text_widget, save_message_callback=None):
		self.text_widget = text_widget
		self.queue = queue.Queue()
		self.original_stdout = sys.stdout
		self.updating = True
		self.save_message_callback = save_message_callback
		threading.Thread(target=self.update_loop, daemon=True).start()

	def write(self, string):
		if "Erreur" in string or "erreur" in string:
			# remonte uniquement via la boucle d'erreur
			self.queue.put(("error", string))
		else:
			# Empêche l'affichage des messages reçus si aucun contact n'est sélectionné
			if ": " in string and not any(x in string for x in ("===", "Ta clé", "Connexion")):
				try:
					parent = self.text_widget.master
					while parent and not hasattr(parent, 'current_contact_pubkey'):
						parent = getattr(parent, 'master', None)
					if parent and getattr(parent, 'current_contact_pubkey', None) is None:
						return
					parts = string.split(": ", 1)
					if len(parts) >= 2:
						sender, message = parts[0], parts[1].strip()

						display_sender = sender
						to_pubkey = None

						if hasattr(parent, 'current_contact_pubkey') and hasattr(parent, 'contacts'):
							to_pubkey = getattr(parent, 'key_var', None)
							contact_pseudo = None
							for p, pk in parent.contacts:
								if pk == parent.current_contact_pubkey:
									contact_pseudo = p
									break

							if sender.strip().lower() not in ("toi", "vous") and contact_pseudo:
								display_sender = contact_pseudo
							elif sender.strip().lower() in ("toi", "vous"):
								display_sender = "Toi"
								
							timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
						if self.save_message_callback:
							self.save_message_callback(display_sender, message, timestamp, to=to_pubkey)
				except Exception as e:
					pass
			self.queue.put(("message", string))

	def flush(self): pass

	def update_loop(self):
		'''
		Boucle de mise à jour qui affiche :
		- les messages,
		- l'heure à laquelle ils ont été reçus,
		- les messages d'erreur.
		'''
		while self.updating:
			try:
				while True:
					item = self.queue.get_nowait()
					item_type, string = item
					if item_type == "error":
						if self.text_widget.winfo_toplevel():
							self.text_widget.winfo_toplevel().after(0, lambda s=string: show_error(s.strip()))
					else:
						self.text_widget.config(state=tk.NORMAL)
						string = string.rstrip()
						if ": " in string and not any(x in string for x in ("Ta clé", "Connexion")):
							try:
								parts = string.split(": ", 1)
								if len(parts) >= 2:
									sender, message = parts[0], parts[1]
									time_str = datetime.now().strftime("%H:%M")

									parent = self.text_widget.master
									while parent and not hasattr(parent, 'current_contact_pubkey'):
										parent = getattr(parent, 'master', None)

									display = sender
									tag = 'message_received'

									if sender.strip().lower() in ("toi", "vous"):
										display = 'Toi'
										tag = 'message_sent'
									else:
										# Si un contact est sélectionné, utiliser son pseudo pour l'affichage # MODIFIED
										if parent and hasattr(parent, 'current_contact_pubkey') and parent.current_contact_pubkey and hasattr(parent, 'contacts'): # MODIFIED
											contact_pseudo = None # MODIFIED
											for p, pk in parent.contacts: # MODIFIED
												if pk == parent.current_contact_pubkey: # MODIFIED
													contact_pseudo = p # MODIFIED
													break # MODIFIED
											if contact_pseudo: # MODIFIED
												display = contact_pseudo # MODIFIED
											# Si pas de pseudo trouvé (ne devrait pas arriver), on garde le 'sender' original comme fallback # MODIFIED
										# Le tag reste 'message_received' # MODIFIED

									self.text_widget.insert(tk.END, f"[{time_str}] {display}: ", "sender_name")
									self.text_widget.insert(tk.END, message.strip(), tag)
									self.text_widget.insert(tk.END, "\n", "")

							except Exception as e:
								self.text_widget.insert(tk.END, string + "\n") # ADDED
						else:
							if not ("erreur" in string.lower() or "error" in string.lower()): # MODIFIED
								string = string.strip() # MODIFIED
								if string:
									self.text_widget.insert(tk.END, string, "system_message") # MODIFIED
									self.text_widget.insert(tk.END, "\n", "")

						self.text_widget.config(state=tk.DISABLED)
						self.text_widget.see(tk.END)
					self.queue.task_done()

			except queue.Empty:
				pass
			time.sleep(0.1)

	def stop(self):
		self.updating = False

class NexaInterface(tk.Tk):
	def __init__(self):
		super().__init__()
		self.withdraw()
		self.title("NexaChat")
		self.geometry("600x700")			# Taille de la fenêtre (largeur x hauteur)
		self.minsize(600, 600)				# Taille minimale

		self.center_window()
		self.deiconify()
		self.protocol("WM_DELETE_WINDOW", self.on_closing)

		self.is_mac = platform.system() == "Darwin"			# Adapte l'interface en fonction de l'OS utilisé
		
		if self.is_mac:
			# Force le mode clair sur macOS
			self.tk_setPalette(background="#FFFFFF",
							  foreground="#000000",
							  activeBackground="#EFEFEF",
							  activeForeground="#000000")
		
		self.style = ttk.Style()
		if self.is_mac:
			try:
				self.style.theme_use('default')  # Utiliser le thème par défaut au lieu de aqua
			except:
				self.style.theme_use('default')
		else:
			self.style.theme_use('clam')

		# Chargement des couleurs depuis les paramètres
		self.primary_color, self.secondary_color = load_color_settings()
		self.text_color = "#212121"

		self.style.configure('TFrame', background="#FFFFFF")
		self.style.configure('Header.TFrame', background=self.primary_color)

		# Définition des polices selon la plateforme
		if self.is_mac:
			self.default_font = 'Helvetica'
		else:
			self.default_font = 'Segoe UI'
		self.button_font = (self.default_font, 10)
		self.title_font = (self.default_font, 16, 'bold')
		self.subtitle_font = (self.default_font, 10)
		
		self.style.configure('TLabel', 
					   background="#FFFFFF",
					   foreground=self.text_color,
					   font=self.subtitle_font)
    		
		self.style.configure('Header.TLabel',
					   font=('Segoe UI', 16, 'bold'),
					   foreground='white',
					   background=self.primary_color)
		
		self.style.configure('Header.Subtitle.TLabel',
					   font=('Segoe UI', 10),
					   foreground='white',
					   background=self.primary_color)
		
		self.style.configure('Status.TLabel',
					   font=('Segoe UI', 10),
					   foreground=self.text_color,
					   background=self.primary_color)
		
		# Configuration des boutons adaptée à macOS
		if self.is_mac:
			self.style.configure('TButton',
						font=self.button_font,
						padding=6)
		else:
			self.style.configure('TButton',
						font=('Segoe UI', 10),
						borderwidth=0,
						relief="flat",
						padding=5)
		
		self.style.map('TButton', 
					foreground=[('pressed', 'white'), ('active', 'white')],	  
					background=[('pressed', self.secondary_color), ('active', self.secondary_color)])
		
		self.style.configure('Send.TButton',
					   	font=('Segoe UI', 12, 'bold'),
						background=self.primary_color, 
						foreground='white',
						borderwidth=0,
						padding=8)
		
		self.style.map('Send.TButton', 
					 foreground=[('pressed', 'white'), ('active', 'white')], 
					 background=[('pressed', self.secondary_color),
				  				('active', self.secondary_color)])
		
		self.style.configure('Key.TLabel',
					   font=('Segoe UI', 9),
					   background='#EEEEEE')
		
		self.message_to_send = StringVar()
		self.recipient_key = StringVar()
		self.status = StringVar(value="Déconnecté")
		self.key_var = StringVar(value="Non disponible")
		self.nodes_var = StringVar(value="Recherche de nœuds...")
		self.client = None
		self.connected = False
		self.message_queue = queue.Queue()
		self.key_queue = queue.Queue()
		self.client_wrapper = WrapperClient()

		if platform.system() == "Windows":
			icon_path = os.path.join(SCRIPT_DIR, "Nexa.ico")
			if os.path.exists(icon_path):
				try:
					self.iconbitmap(icon_path)
				except Exception as e:
					show_error(f"L'icône Nexa.ico n'a pas pu être chargée. ({e})")

		self.msg_db = sqlite3.connect(os.path.join(DATA_DIR, "messagesUI.db"), check_same_thread=False)

		self.msg_cursor = self.msg_db.cursor()
		self.msg_cursor.execute('''
			CREATE TABLE IF NOT EXISTS message (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				sender TEXT,
				"to" TEXT,
				message TEXT,
				timestamp TEXT
			)
		''')
		self.msg_db.commit()

		self.contacts_db = sqlite3.connect(os.path.join(DATA_DIR, "contacts.db"), check_same_thread=False)
		self.contacts_cursor = self.contacts_db.cursor()
		self.contacts_cursor.execute('''
			CREATE TABLE IF NOT EXISTS contacts (
				pseudo TEXT NOT NULL UNIQUE,
				pubkey TEXT NOT NULL UNIQUE
			)
		''')
		self.contacts_db.commit()
		self.current_contact_pubkey = None

		self.seen_db = sqlite3.connect(os.path.join(DATA_DIR, "seen_messages.db"), check_same_thread=False)

		self.create_widgets()
		self.delete_old_messages()  # Suppression des anciens messages au bout d'une semaine
		self.load_message_history()  # Charge l'historique des messages précédents
		self.load_contacts()  # Charge les contacts
		self.after(100, self.check_input_needed)
		self.setup_nodes_detection()

	def delete_old_messages(self):
		'''
		Supprime les messages datant de plus d'une semaine dans messagesUI.db
		'''
		try:
			one_week_ago = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
			self.msg_cursor.execute("DELETE FROM message WHERE timestamp < ?", (one_week_ago,))
			self.msg_db.commit()
		except Exception as e:
			show_error(f"Erreur lors du nettoyage des anciens messages. ({e})")

	def center_window(self):
		self.update_idletasks()
		screen_width = self.winfo_screenwidth()
		screen_height = self.winfo_screenheight()
		width = self.winfo_width()
		height = self.winfo_height()
		x = (screen_width - width) // 2
		y = (screen_height - height) // 2 - 50
		self.geometry(f"{width}x{height}+{x}+{y}")

	def setup_nodes_detection(self):
		'''
		Configure la détection des nœuds
		'''
		def update_nodes(nodes):
			if nodes:
				if len(nodes) == 1:
					self.nodes_var.set("1 nœud disponible")
				else:
					self.nodes_var.set(f"{len(nodes)} nœuds disponibles")
				self.connect_button.config(state=tk.NORMAL)
			else:
				self.nodes_var.set("Aucun nœud disponible")
				self.connect_button.config(state=tk.DISABLED)
		global node_detection_callback
		node_detection_callback = update_nodes
		async_getnodes()		# Lance la détection des nœuds

	def create_widgets(self):
		'''
		Crée les widgets de l'interface
		'''
		main_frame = ttk.Frame(self)
		main_frame.pack(fill=tk.BOTH, expand=True)
		
		# En-tête
		header_frame = ttk.Frame(main_frame, style='Header.TFrame')
		header_frame.pack(fill=tk.X)
		header_padding = ttk.Frame(header_frame, style='Header.TFrame')
		header_padding.pack(fill=tk.X, padx=15, pady=15)

		# Titre centré
		ttk.Label(header_padding, text="NexaChat", style='Header.TLabel').pack(anchor=tk.CENTER, expand=True)

		# Page de connexion
		self.login_frame = ttk.Frame(main_frame, padding=20)	
		self.login_frame.pack(fill=tk.BOTH, expand=True, pady=(80, 0))  # Ajout d'un padding vertical
		
		icon_path = os.path.join(SCRIPT_DIR, "Nexa.png")
		if os.path.exists(icon_path):
			try:
				pil_image = Image.open(icon_path)
				pil_image = pil_image.resize((128, 128), Image.LANCZOS if hasattr(Image, 'LANCZOS') else Image.ANTIALIAS)
				self.tk_logo = ImageTk.PhotoImage(pil_image)
				logo_label = ttk.Label(self.login_frame, image=self.tk_logo)
			except Exception as e:
				logo_label = ttk.Label(self.login_frame, text="📱", font=(self.default_font, 48))
		else:
			logo_label = ttk.Label(self.login_frame, text="📱", font=(self.default_font, 48))
		logo_label.pack(pady=(30, 20))

		ttk.Label(self.login_frame,
					text="Bienvenue sur NexaChat !",
					font=(self.default_font, 25, "bold")).pack(pady=(0, 20))
		
		# Formulaire de connexion
		form_frame = ttk.Frame(self.login_frame, padding=10)
		form_frame.pack(fill=tk.X)

		spacer = ttk.Frame(self.login_frame, height=100)
		spacer.pack(fill=tk.X)

		bottom_frame = ttk.Frame(self.login_frame)
		bottom_frame.pack(fill=tk.X, pady=(45, 0))

		# Style adapté selon la plateforme
		ttk.Label(bottom_frame,
				textvariable=self.nodes_var,
				font=(self.default_font, 13)
				).pack(anchor=tk.CENTER, pady=(0, 20))
		# Bouton de connexion
		if self.is_mac:
			self.connect_button = ttk.Button(bottom_frame, 
											text="Me connecter",
											command=self.connect,
											style='TButton')
			self.connect_button.pack(fill=tk.X, pady=10)
		else:
			self.connect_button = tk.Button(bottom_frame,
								text="Me connecter",
								command=self.connect,
								bg=self.primary_color,
								fg="white", 
								font=(self.default_font, 18, 'bold'),
								relief=tk.RAISED,
								borderwidth=0,
								padx=10, pady=15,
								cursor="hand2")
			self.connect_button.pack(fill=tk.X, ipady=8)
		self.connect_button.config(state=tk.DISABLED)  # Désactivé par défaut jusqu'à ce que des nœuds soient trouvés

		self.chat_frame = ttk.Frame(main_frame)		# Fenêtre de chat

		# En-tête avec clé publique de l'utilisateur
		key_frame = ttk.Frame(self.chat_frame, padding=(10, 2))
		key_frame.pack(fill=tk.X)
		ttk.Label(key_frame, text="Ta clé publique :", font=(self.default_font, 9, 'bold')).pack(side=tk.LEFT)
		
		key_display_frame = ttk.Frame(key_frame)
		key_display_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=2)

		self.key_label = ttk.Label(key_display_frame,
							 textvariable=self.key_var,
							 style='Key.TLabel',
							 wraplength=0,
							 anchor='center',
							 background='#EEEEEE')
		
		self.key_label.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=2, padx=5)
		
		# Bouton pour copier la clé (à droite du conteneur)
		if self.is_mac:
			copy_btn = ttk.Button(key_frame,
						   text="Copier",
						   command=self.copy_key,
						   style='TButton')
		else:
			copy_btn = tk.Button(key_frame,
						   text="Copier",
						   command=self.copy_key,
						   bg=self.primary_color,
						   fg="white",
						   font=(self.default_font, 9, 'bold'),
						   relief=tk.RAISED,
						   borderwidth=0,
						   padx=8, pady=2,
						   cursor="hand2")
		
		copy_btn.pack(side=tk.LEFT, padx=5, pady=2)
		ttk.Separator(self.chat_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=2)

		# clear separation: use PanedWindow horizontal
		paned = tk.PanedWindow(self.chat_frame, orient=tk.HORIZONTAL, sashwidth=6, sashrelief=tk.RAISED)
		paned.pack(fill=tk.BOTH, expand=True)

		# Contacts panel as pane
		contacts_frame = ttk.Frame(paned, padding=2, width=150, relief=tk.GROOVE, borderwidth=1)
		contacts_frame.pack(side=tk.LEFT, fill=tk.Y)
		paned.add(contacts_frame)
		paned.paneconfigure(contacts_frame, minsize=150)
		contacts_label = ttk.Label(contacts_frame, text="Contacts", font=(self.default_font, 12, 'bold'))
		contacts_label.pack(pady=(2, 2))
		self.contacts_listbox = tk.Listbox(contacts_frame, font=(self.default_font, 10, 'normal'), exportselection=False)
		self.contacts_listbox.pack(fill=tk.BOTH, expand=True, pady=(2, 2))
		self.contacts_listbox.config(selectbackground=self.primary_color, selectforeground='white')
		contacts_btn = tk.Button(contacts_frame, text="Ajouter", command=self.fenêtre_contacts,
									bg=self.primary_color, fg="white", font=(self.default_font, 9, 'bold'),
									relief=tk.RAISED, borderwidth=0, cursor="hand2")
		contacts_btn.pack(fill=tk.X, pady=(2, 2))

		# menu contextuel sur contacts
		self.contact_menu = tk.Menu(self, tearoff=0)
		self.contact_menu.add_command(label="Supprimer", command=self.delete_contact)
		# Correction : ne pas déselectionner le contact lors de la sélection de texte dans le chat
		self.contacts_listbox.bind("<ButtonRelease-1>", lambda e: self.on_contact_select())
		self.contacts_listbox.bind("<Button-3>", self.show_contact_menu)

		 # Chat area as pane
		chat_area_frame = ttk.Frame(paned)
		paned.add(chat_area_frame)
		paned.paneconfigure(chat_area_frame, minsize=300)

		# Zone d'affichage des messages
		self.chat_text = scrolledtext.ScrolledText(chat_area_frame,
												wrap=tk.WORD,
												height=15,
												font=(self.default_font, 11),
												bd=1 if self.is_mac else 0,  # Bordure légère sur Mac
												relief=tk.SUNKEN if self.is_mac else tk.FLAT
												)
		self.chat_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
		self.chat_text.config(state=tk.DISABLED)
		# Empêcher la déselection du contact lors d'un double-clic dans la zone de chat
		self.chat_text.bind('<Double-Button-1>', lambda e: 'break')

		# Configuration des tags pour le formatage du texte
		self.chat_text.tag_configure("message_sent",
									font=(self.default_font, 11),
									spacing1=0, spacing2=0, spacing3=0,
									lmargin1=5, lmargin2=5,
									foreground="black",
									wrap=tk.WORD)  # Ensure long messages wrap properly

		self.chat_text.tag_configure("system_message_center",
									foreground="#757575",
									font=(self.default_font, 9),
									justify='center',
									spacing1=2, spacing2=0, spacing3=2)
							
		self.chat_text.tag_configure("message_received",
									font=(self.default_font, 11),
									spacing1=0, spacing2=0, spacing3=0,
									lmargin1=5, lmargin2=5,
									foreground="black",
									wrap=tk.WORD)  # Ensure long messages wrap properly
		
		self.chat_text.tag_configure("sender_name",
									font=(self.default_font, 10, 'bold'),
									justify='left',
									lmargin1=5, lmargin2=5,
									foreground=self.primary_color)
		
		self.chat_text.tag_configure("system_message",
									foreground="#757575",
									font=(self.default_font, 9),
									justify='left',
									spacing1=1, spacing2=0, spacing3=1,
									lmargin1=5, lmargin2=5)
		
		# Zone de saisie
		msg_frame = ttk.Frame(chat_area_frame, padding=10)
		msg_frame.pack(fill=tk.X, side=tk.BOTTOM)
		# Suppression du label "Message :"
		# ttk.Label(msg_frame, text="Message :", font=(self.default_font, 9, 'bold')).pack(anchor=tk.W)

		input_frame = ttk.Frame(msg_frame)
		input_frame.pack(fill=tk.X, pady=5)

		self.msg_entry = ttk.Entry(input_frame, textvariable=self.message_to_send, font=(self.default_font, 10))
		self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
		self.msg_entry.bind("<Return>", lambda e: self.send_message())

		# Bouton d'envoi
		if self.is_mac:
			send_btn = ttk.Button(input_frame,
							text="Envoyer",
							command=self.send_message,
							style='TButton')
		else:
			send_btn = tk.Button(input_frame,
							text="Envoyer",
							command=self.send_message,
							bg=self.primary_color,
							fg="white",
							font=(self.default_font, 9, 'bold'),
							relief=tk.RAISED,
							borderwidth=0,
							padx=10, pady=4,
							cursor="hand2")
		
		send_btn.pack(side=tk.RIGHT)

		# Effets de survol des boutons seulement pour Windows
		if not self.is_mac:
			buttons = []
			if hasattr(self, 'connect_button') and isinstance(self.connect_button, tk.Button):
				buttons.append(self.connect_button)
			if isinstance(copy_btn, tk.Button):
				buttons.append(copy_btn)
			if isinstance(send_btn, tk.Button):
				buttons.append(send_btn)
			if isinstance(contacts_btn, tk.Button):
				buttons.append(contacts_btn)
				
			for btn in buttons:
				btn.bind("<Enter>", lambda e, b=btn: b.config(bg=self.secondary_color))
				btn.bind("<Leave>", lambda e, b=btn: b.config(bg=self.primary_color))

	def load_message_history(self):
		'''
		Charge l'historique des messages stockés dans messagesUI.db et les affiche.
		'''
		self.delete_old_messages()  # Nettoyage avant chargement
		try:
			self.msg_cursor.execute("SELECT sender, \"to\", message, timestamp FROM message ORDER BY id")
			rows = self.msg_cursor.fetchall()
			self.chat_text.config(state=tk.NORMAL)
			self.chat_text.delete(1.0, tk.END)
			for sender, to, message, timestamp in rows:
				time_str = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").strftime("%H:%M")
				self.chat_text.insert(tk.END, f"[{time_str}] {sender}: ", "sender_name")
				self.chat_text.insert(tk.END, f"{message}\n", "message_received")
			self.chat_text.config(state=tk.DISABLED)
			self.chat_text.see(tk.END)
		except Exception as e:
			show_error(f"Erreur lors du chargement de l'historique. ({e})")

	def save_message(self, sender, message, timestamp, to=None):
		'''
		Sauvegarde les messages dans messagesUI.db uniquement s'ils n'existent pas déjà.
		'''
		if sender.strip().lower() in ("vous", "toi"):
			sender = "Toi"
		if to is None:
			to = getattr(self, 'current_contact_pubkey', None)
		# Convert tkinter StringVar to raw string for SQLite
		if isinstance(to, StringVar):
			to = to.get()
		try:
			self.msg_cursor.execute("SELECT 1 FROM message WHERE sender=? AND \"to\"=? AND message=? AND timestamp=?", (sender, to, message, timestamp))
			if self.msg_cursor.fetchone():
				return
			self.msg_cursor.execute("INSERT INTO message (sender, \"to\", message, timestamp) VALUES (?, ?, ?, ?)", (sender, to, message, timestamp))
			self.msg_db.commit()
		except Exception as e:
			show_error(f"Erreur lors de la sauvegarde du message. ({e})")

	def load_contacts(self):
		'''
		Charge les contacts depuis contacts.db.
		'''
		self.contacts_cursor.execute("SELECT pseudo, pubkey FROM contacts ORDER BY pseudo")
		rows = self.contacts_cursor.fetchall()
		self.contacts = rows
		if hasattr(self, 'contacts_listbox'):
			self.contacts_listbox.delete(0, tk.END)
			for item in rows:
				pseudo, _ = item
				self.contacts_listbox.insert(tk.END, pseudo)
		# Ajout : si plus de contacts, efface la zone de chat et masque la zone d'envoi
		if len(rows) == 0:
			self.chat_text.config(state=tk.NORMAL)
			self.chat_text.delete(1.0, tk.END)
			self.chat_text.config(state=tk.DISABLED)
			self.current_contact_pubkey = None
			self.msg_entry.master.pack_forget()

	def add_contact(self, pseudo, pubkey):
		'''
		Ajoute un nouveau contact.
		'''
		if not Client.verify_key(pubkey):
			show_error("Assure-toi d’avoir correctement saisi la clé publique !")
			return
		self.contacts_cursor.execute("SELECT 1 FROM contacts WHERE pseudo=?", (pseudo,))
		if self.contacts_cursor.fetchone():
			show_error("Un contact avec ce pseudo existe déjà.")
			return
		try:
			self.contacts_cursor.execute("INSERT INTO contacts (pseudo, pubkey) VALUES (?, ?)", (pseudo, pubkey))
			self.contacts_db.commit()
			self.load_contacts()
		except sqlite3.IntegrityError:
			show_error("Le contact existe déjà.")

	def fenêtre_contacts(self):
		# prevent multiple contact dialogs
		if getattr(self, 'contact_dialog', None) and self.contact_dialog.winfo_exists():
			self.contact_dialog.lift()
			self.contact_dialog.focus_force()
			self.contact_dialog.attributes('-topmost', 1)
			return
		dialog = tk.Toplevel(self)
		self.contact_dialog = dialog
		dialog.withdraw()
		dialog.geometry("270x115")
		dialog.update_idletasks()
		# center over main window
		px, py = self.winfo_rootx(), self.winfo_rooty()
		pw, ph = self.winfo_width(), self.winfo_height()
		x = px + (pw - 270)//2; y = py + (ph - 115)//2
		dialog.geometry(f"270x115+{x}+{y}")
		self.after(100, lambda: (dialog.deiconify(), dialog.lift(), dialog.focus_force(), dialog.attributes('-topmost', 1)))
		dialog.minsize(270, 115)									# Taille min de la fenêtre de création de contact
		dialog.maxsize(700, 115)
		content_frame = ttk.Frame(dialog, style='TFrame', padding=10)
		content_frame.pack(fill=tk.BOTH, expand=True)
		# permettre aux colonnes de s'étendre
		content_frame.columnconfigure(1, weight=1)
		dialog.title("Nouveau contact")
		icon_path = os.path.join(SCRIPT_DIR, "Nexa.ico")
		if os.path.exists(icon_path):
			try:
				dialog.iconbitmap(icon_path)
			except:
				pass
		# champs pseudo et clé
		ttk.Label(content_frame, text="Pseudo :").grid(row=0, column=0, padx=5, pady=5, sticky='w')
		pseudo_var = StringVar()
		pseudo_entry = ttk.Entry(content_frame, textvariable=pseudo_var)
		pseudo_entry.grid(row=0, column=1, padx=5, pady=5, sticky='we')
		pseudo_entry.focus_set()
		ttk.Label(content_frame, text="Clé publique :").grid(row=1, column=0, padx=5, pady=5, sticky='w')
		pubkey_var = StringVar()
		pubkey_entry = ttk.Entry(content_frame, textvariable=pubkey_var)
		pubkey_entry.grid(row=1, column=1, padx=5, pady=5, sticky='we')
		# boutons d'action
		btn_frame = ttk.Frame(content_frame)
		btn_frame.grid(row=2, column=0, columnspan=2, pady=10)
		# validation et ajout de contact
		def _on_add():
			pseudo = pseudo_var.get().strip()
			key = pubkey_var.get().strip()
			if not pseudo:
				return
			if not key:
				return
			if not Client.verify_key(key):
				show_error("Assure-toi d’avoir correctement saisi la clé publique !", parent=dialog)
				pubkey_entry.focus_set()
				return
			if self.contacts_cursor.execute("SELECT 1 FROM contacts WHERE pseudo=?", (pseudo,)).fetchone():
				show_error("Un contact avec ce pseudo existe déjà.", parent=dialog)
				pseudo_entry.focus_set()
				return
			try:
				self.contacts_cursor.execute("INSERT INTO contacts (pseudo, pubkey) VALUES (?, ?)", (pseudo, key))
				self.contacts_db.commit()
				self.load_contacts()
				dialog.destroy()
			except sqlite3.IntegrityError:
				show_error("Le contact existe déjà.", parent=dialog)
				pseudo_entry.focus_set()
		if self.is_mac:
			ttk.Button(btn_frame, text="Ajouter", command=_on_add).pack(side=tk.LEFT, padx=5)
			ttk.Button(btn_frame, text="Annuler", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
		else:
			tk.Button(btn_frame, text="Ajouter", command=_on_add,
					  bg=self.primary_color, fg="white",
					  font=(self.default_font, 9, 'bold'),
					  relief=tk.RAISED, borderwidth=0, cursor="hand2").pack(side=tk.LEFT, padx=5)
			tk.Button(btn_frame, text="Annuler", command=dialog.destroy,
					  bg=self.primary_color, fg="white",
					  font=(self.default_font, 9, 'bold'),
					  relief=tk.RAISED, borderwidth=0, cursor="hand2").pack(side=tk.LEFT, padx=5)
		dialog.bind("<Return>", lambda e: _on_add())
		dialog.bind("<Escape>", lambda e: dialog.destroy())		

		 # S'assure que la fenêtre reste au premier plan si on clique ailleurs
		def keep_on_top(event=None):
			try:
				dialog.attributes('-topmost', 1)
			except:
				pass
		dialog.bind('<FocusOut>', keep_on_top)
		dialog.bind('<Unmap>', keep_on_top)

		dialog.bind("<Destroy>", lambda e: setattr(self, 'contact_dialog', None))

	def on_contact_select(self):
		selection = self.contacts_listbox.curselection()
		if not selection:
			self.chat_text.config(state=tk.NORMAL)
			self.chat_text.delete(1.0, tk.END)
			self.chat_text.config(state=tk.DISABLED)
			self.current_contact_pubkey = None
			# Cache la zone d'envoi de message
			self.msg_entry.master.pack_forget()
			return
		index = selection[0]
		pseudo, pubkey = self.contacts[index]
		self.current_contact_pubkey = pubkey
		self.recipient_key.set(pubkey)
		# Affiche la zone d'envoi de message
		self.msg_entry.master.pack(fill=tk.X, side=tk.BOTTOM)
		# Recharge l'historique à chaque sélection
		self.load_message_history_for_contact(pseudo, pubkey)
		# Donne le focus à la zone de saisie du message
		self.msg_entry.focus_set()

	def load_message_history_for_contact(self, contact_pseudo, contact_pubkey=None):
		self.delete_old_messages()  # Nettoyage avant chargement
		self.chat_text.config(state=tk.NORMAL)
		self.chat_text.delete(1.0, tk.END)
		my_pubkey = self.key_var.get().strip()
		self.msg_cursor.execute("SELECT sender, \"to\", message, timestamp FROM message WHERE (\"to\"=? OR sender=?) ORDER BY id", (contact_pubkey, contact_pubkey))
		rows = self.msg_cursor.fetchall()
		# Grouper les messages par date
		messages_by_date = {}
		for sender, to, message, timestamp in rows:
			msg_date = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").date()
			messages_by_date.setdefault(msg_date, []).append((sender, to, message, timestamp))
		# Afficher les messages par date
		if not messages_by_date:
			# Affiche la date du jour même si aucun message
			date_str = datetime.now().strftime("%A %d %B %Y")
			date_str = date_str[0].upper() + date_str[1:]
			self.chat_text.insert(tk.END, "\n", "system_message")
			self.chat_text.insert(tk.END, date_str + "\n", "system_message_center")
		else:
			for msg_date in sorted(messages_by_date.keys()):
				day_msgs = messages_by_date[msg_date]
				if not day_msgs:
					continue
				date_str = msg_date.strftime("%A %d %B %Y")
				date_str = date_str[0].upper() + date_str[1:]
				self.chat_text.insert(tk.END, "\n", "system_message")
				self.chat_text.insert(tk.END, date_str + "\n", "system_message_center")
				for sender, to, message, timestamp in day_msgs:
					time_str = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").strftime("%H:%M")
					if sender == "Toi":
						display_sender = "Toi"
						tag = "message_sent"
					else:
						display_sender = contact_pseudo
						tag = "message_received"
					self.chat_text.insert(tk.END, f"[{time_str}] {display_sender}: ", "sender_name")
					self.chat_text.insert(tk.END, f"{message}\n", tag)
		self.chat_text.config(state=tk.DISABLED)
		self.chat_text.see(tk.END)

	# menu contextuel Actions
	def show_contact_menu(self, event):
		selection = self.contacts_listbox.nearest(event.y)
		self.contacts_listbox.selection_clear(0, tk.END)
		self.contacts_listbox.selection_set(selection)
		self.on_contact_select()
		try:
			self.contact_menu.tk_popup(event.x_root, event.y_root)
		finally:
			self.contact_menu.grab_release()

	def delete_contact(self):
		'''Supprime le contact sélectionné après confirmation et efface l'historique de la conversation.'''
		sel = self.contacts_listbox.curselection()
		if not sel: return
		pseudo, pubkey = self.contacts[sel[0]]
		if messagebox.askyesno("Supprimer", f"Supprimer le contact '{pseudo}' ?"):
			# Efface l'historique des messages pour ce contact (équivalent à /clear)
			try:
				self.msg_cursor.execute("DELETE FROM message WHERE \"to\"=?", (pubkey,))
				self.msg_db.commit()
			except Exception as e:
				show_error(f"Erreur lors de la suppression de l'historique. ({e})")
			self.contacts_cursor.execute("DELETE FROM contacts WHERE pseudo=?", (pseudo,))
			self.contacts_db.commit()
			self.load_contacts()
			# Vide la zone de chat et affiche le message comme /clear
			self.chat_text.config(state=tk.NORMAL)
			self.chat_text.delete(1.0, tk.END)
			self.chat_text.insert(tk.END, "Historique de la conversation effacé.\n", "system_message_center")
			self.chat_text.config(state=tk.DISABLED)
			self.chat_text.see(tk.END)

	def connect(self):
		'''
		Gère la connexion aux nœuds.
		'''
		self.status.set("Connexion en cours...")
		self.connect_button.config(state=tk.DISABLED)
					
		
		def setup_client():
			try:
				if not self.client_wrapper.start_client("auto", 9102):
					self.after(0, lambda: show_error("Une connexion est déjà en cours"))
					return
					
				self.client = self.client_wrapper.client

				# Met à jour l'interface
				self.after(0, lambda: self.key_var.set(self.client.pubKey))
				self.after(0, self.show_chat_interface)

				# redirige stdout sans stocker de pseudo UI
				redirect = MessageRedirect(self.chat_text, save_message_callback=self.save_message)
				self.original_stdout = sys.stdout
				sys.stdout = redirect
				# input() renvoyant toujours le login pour l'enregistrement serveur
				login = os.getlogin()
				self.original_input = __builtins__.input
				__builtins__.input = lambda prompt="": login

			except Exception as e:  # En cas d'erreur, revenir à l'écran de connexion
				self.after(0, lambda: self.status.set(f"Erreur : {e}"))
				self.after(0, lambda: self.connect_button.config(state=tk.NORMAL))
				self.after(0, lambda e=e: show_error(f"Impossible de se connecter. ({e})"))
				self.after(0, self.show_login_interface)
		threading.Thread(target=setup_client, daemon=True).start()

	def show_chat_interface(self):
		'''
		Affiche l'interface de chat.
		'''
		self.login_frame.pack_forget()
		self.chat_frame.pack(fill=tk.BOTH, expand=True)
		self.connected = True
		self.chat_text.config(state=tk.NORMAL)
		self.chat_text.delete(1.0, tk.END)
		self.chat_text.config(state=tk.DISABLED)
		self.contacts_listbox.selection_clear(0, tk.END)
		self.current_contact_pubkey = None
		self.msg_entry.focus_set()
		# Cache la zone d'envoi de message tant qu'aucun contact n'est sélectionné
		self.msg_entry.master.pack_forget()
		# Ne charge pas l'historique ici

	def show_login_interface(self):
		'''
		Affiche l'interface de connexion.
		'''
		self.chat_frame.pack_forget()
		self.login_frame.pack(fill=tk.BOTH, expand=True)
		self.connected = False
		self.connect_button.config(state=tk.NORMAL)
		# Ajout du binding et focus sur le champ pseudo
		for child in self.login_frame.winfo_children():
			for subchild in child.winfo_children():
				if isinstance(subchild, ttk.Entry):
					subchild.bind("<Return>", lambda event: self.connect() if self.connect_button['state'] != tk.DISABLED else None)
					subchild.focus_set()

	def mock_input(self, prompt=""):
		'''
		Simule la fonction input() pour le client.
		'''
		if "pseudo" in prompt.lower():
			return os.getlogin()
		elif "destinataire" in prompt.lower() or "clé" in prompt.lower():
			future = queue.Queue()
			self.key_queue.put(future)
			try:
				key = future.get(timeout=60)
				if key:
					return key
			except queue.Empty:
				pass

			entered_key = self.recipient_key.get().strip()
			if entered_key:
				return entered_key
			return "temp_key"
		return ""

	def check_input_needed(self):
		if self.connected and hasattr(self, 'client') and self.client:
			if hasattr(self.client, 'key_requested') and self.client.key_requested:
				key = self.recipient_key.get().strip()
				if key:
					try:
						future = self.key_queue.get_nowait()
						future.put(key)
					except queue.Empty:
						pass
		self.after(100, self.check_input_needed)

	def copy_key(self):
		'''
		Copie la clé publique dans le presse-papiers.
		'''
		key = self.key_var.get()
		if key and key != "Non disponible":
			pyperclip.copy(key)

	def apply_theme_colors(self):
		self.style.configure('Header.TFrame', background=self.primary_color)
		self.style.configure('Header.TLabel', background=self.primary_color)
		self.style.configure('Header.Subtitle.TLabel', background=self.primary_color)
		self.style.configure('Status.TLabel', background=self.primary_color)
		self.chat_text.tag_configure("sender_name", foreground=self.primary_color)
		# Mise à jour du selectbackground de la Listbox contacts
		if hasattr(self, 'contacts_listbox'):
			self.contacts_listbox.config(selectbackground=self.primary_color)
		# Mise à jour dynamique de tous les boutons
		def update_buttons(widget):
			if isinstance(widget, tk.Button):
				widget.config(bg=self.primary_color)
			for child in widget.winfo_children():
				update_buttons(child)
		if not self.is_mac:
			if hasattr(self, 'connect_button') and isinstance(self.connect_button, tk.Button):
				self.connect_button.config(bg=self.primary_color)
			if hasattr(self, 'chat_frame'):
				update_buttons(self.chat_frame)

	def set_theme_color(self, color_name):
		color_name = color_name.lower().strip()
		if color_name in COLOR_CHOICES:
			primary, secondary = COLOR_CHOICES[color_name]
			self.primary_color = primary
			self.secondary_color = secondary
			save_color_settings(primary, secondary)
			self.apply_theme_colors()
			return True
		return False

	def send_message(self):
		'''
		Gère l'envoi des messages.
		'''
		if not self.connected or not hasattr(self, 'client') or not self.client:
			show_error("Vous n'êtes pas connecté.")
			return
		message = self.message_to_send.get().strip()
		if not message:
			return
		if message.startswith("/color "):
			color_value = message[7:].strip()
			# Try named color first
			if self.set_theme_color(color_value.lower()):
				self.message_to_send.set("")
				return
			# Try custom color (hex or rgb)
			parsed = parse_color_input(color_value)
			if not parsed:
				# Accept /color RRGGBB (without #)
				if re.fullmatch(r'[0-9a-fA-F]{6}', color_value):
					parsed = parse_color_input("#" + color_value)
				# Accept /color r,g,b (without rgb())
				elif re.fullmatch(r'\d{1,3},\d{1,3},\d{1,3}', color_value):
					parts = color_value.split(",")
					if all(0 <= int(x) <= 255 for x in parts):
						parsed = parse_color_input(f"rgb({parts[0]},{parts[1]},{parts[2]})")
			if parsed:
				primary, secondary = parsed
				# Empêche les couleurs trop claires
				if luminosite(primary) > 200:
					show_error("Cette couleur est trop claire. Essaye une autre !")
					return

				self.primary_color = primary
				self.secondary_color = secondary
				save_color_settings(primary, secondary)
				self.message_to_send.set("")
				return
			return
		if message.startswith("/path"):
			dialog = tk.Toplevel(self)
			self.path_dialog = dialog
			dialog.withdraw()
			dialog.title("Info")
			# Ajout de l'icône Nexa.ico
			icon_path = os.path.join(SCRIPT_DIR, "Nexa.ico")
			if os.path.exists(icon_path):
				try:
					dialog.iconbitmap(icon_path)
				except Exception:
					pass
			w, h = 300, 100
			dialog.geometry(f"{w}x{h}")
			dialog.update_idletasks()
			px, py = self.winfo_rootx(), self.winfo_rooty(); pw, ph = self.winfo_width(), self.winfo_height()
			x = px + (pw - w)//2; y = py + (ph - h)//2
			dialog.geometry(f"{w}x{h}+{x}+{y}")
			dialog.minsize(w,h)						# Taille fenêtre du chemin /path
			dialog.maxsize(600,h)
			content_frame = ttk.Frame(dialog, style='TFrame', padding=10)
			content_frame.pack(fill=tk.BOTH, expand=True)
			content_frame.columnconfigure(1, weight=1)
			ttk.Label(content_frame, text="Chemin d'accès aux données et paramètres :", justify='center').pack(anchor='center')
			ttk.Label(content_frame, text=DATA_DIR, justify='center').pack(anchor='center', pady=(0, 10))
			btn_frame = ttk.Frame(content_frame)
			btn_frame.pack(pady=(0, 10))
			def open_folder():
				import subprocess, platform
				if platform.system() == "Windows":
					os.startfile(DATA_DIR)
				elif platform.system() == "Darwin":
					subprocess.Popen(["open", DATA_DIR])
				else:
					subprocess.Popen(["xdg-open", DATA_DIR])
				dialog.destroy()
			voir_btn = tk.Button(btn_frame, text="Voir", command=open_folder,
								 bg=self.primary_color, fg="white",
								 font=(self.default_font, 9, 'bold'),
								 relief=tk.RAISED, borderwidth=0, cursor="hand2")
			voir_btn.pack(side=tk.LEFT, padx=5)
			def copier_et_fermer():
				pyperclip.copy(DATA_DIR)
				dialog.destroy()
			copier_btn = tk.Button(btn_frame, text="Copier", command=copier_et_fermer,
								   bg=self.primary_color, fg="white",
								   font=(self.default_font, 9, 'bold'),
								   relief=tk.RAISED, borderwidth=0, cursor="hand2")
			copier_btn.pack(side=tk.LEFT, padx=5)
			dialog.bind("<Escape>", lambda e: dialog.destroy())
			self.after(100, lambda: (dialog.deiconify(), dialog.lift(), dialog.focus_force(), dialog.attributes('-topmost', 1)))
			self.message_to_send.set("")
			return
		if message == "/reconnect":
			self._reconnecting = True
			self.disconnect_and_reset()
			self.message_to_send.set("")
			return
		if message == "/clear":
			if not getattr(self, 'current_contact_pubkey', None):
				return
			contact_pubkey = str(self.current_contact_pubkey).strip()
			try:
				self.msg_cursor.execute("DELETE FROM message WHERE \"to\"=?", (contact_pubkey,))
				self.msg_db.commit()
				pseudo = None
				for p, pk in self.contacts:
					if pk == contact_pubkey:
						pseudo = p
						break
				self.load_message_history_for_contact(pseudo, contact_pubkey)
				self.chat_text.config(state=tk.NORMAL)
				self.chat_text.insert(tk.END, "Historique de la conversation effacé.\n", "system_message_center")
				self.chat_text.config(state=tk.DISABLED)
				self.chat_text.see(tk.END)
			except Exception as e:
				show_error(f"Erreur lors de la suppression de l'historique. ({e})")
			self.message_to_send.set("")
			return
		if message == "/clear all":
			try:
				self.msg_cursor.execute("DELETE FROM message")
				self.msg_db.commit()
				self.chat_text.config(state=tk.NORMAL)
				self.chat_text.delete(1.0, tk.END)
				# Afficher la date du jour
				date_str = datetime.now().strftime("%A %d %B %Y")
				date_str = date_str[0].upper() + date_str[1:]
				self.chat_text.insert(tk.END, "\n", "system_message")
				self.chat_text.insert(tk.END, date_str + "\n", "system_message_center")
				self.chat_text.insert(tk.END, "Tous les messages ont été effacés.\n", "system_message_center")
				self.chat_text.config(state=tk.DISABLED)
				self.chat_text.see(tk.END)
			except Exception as e:
				show_error(f"Erreur lors de la suppression de tous les messages. ({e})")
			self.message_to_send.set("")
			return
		
		# Vérification de la longueur du message (sans compter les espaces)
		message_no_spaces = message.replace(" ", "")
		if len(message_no_spaces) > 10000:
			show_error("Le message est trop long. La limite est de 10000 caractères (espaces non compris).")
			return
		
		# Il faut qu'un contact soit sélectionné pour envoyer
		if not getattr(self, 'current_contact_pubkey', None):
			return
		key = self.current_contact_pubkey
		if not key:
			return
		if hasattr(self.client, 'verify_key') and self.client.verify_key(key):
			if hasattr(self.client, 'message_to_send') and hasattr(self.client, 'recipient_key'):
				self.client.message_to_send = message
				self.client.recipient_key = key
				self.message_to_send.set("")
			else:
				print(message)

	def disconnect_and_reset(self):
		"""
		Déconnecte le client et réinitialise l'interface
		"""
		# Arrête le client proprement
		if self.client_wrapper:
			self.client_wrapper.stop_client()
			
		# Restaure les redirections standard
		if hasattr(self, 'original_stdout') and self.original_stdout:
			sys.stdout = self.original_stdout
		if hasattr(self, 'original_input') and self.original_input:
			__builtins__.input = self.original_input
			
		# Réinitialise le client
		self.client = None
		self.connected = False
		self.key_var.set("Non disponible")
		
		# Retour à l'interface de login
		self.show_login_interface()
		if available_nodes:
			self.connect_button.config(state=tk.NORMAL)
		else:
			self.connect_button.config(state=tk.DISABLED)

	def on_closing(self):
		'''
		Gère la fermeture du programme.
		'''
		global stop_async_getnodes
		stop_async_getnodes = True  # Stoppe la recherche des nœuds
		if self.client_wrapper:
			self.client_wrapper.stop_client()
		try:
			self.msg_db.close()
		except:
			pass
		try:
			self.contacts_db.close()
		except:
			pass
		try:
			self.seen_db.close()
		except:
			pass
		try:
			self.quit()
		except:
			pass
		try:
			self.destroy()
		except:
			pass
		os._exit(0)

if __name__ == "__main__":
	app = NexaInterface()
	app.mainloop()