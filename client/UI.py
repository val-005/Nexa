import asyncio, websockets, threading, ast, uuid, requests, pyperclip, random, sys, os, platform, signal, locale, sqlite3, configparser, queue, time, concurrent.futures, tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, StringVar
from ecies import encrypt, decrypt
from ecies.utils import generate_eth_key
from datetime import datetime
from PIL import Image, ImageTk
from appdirs import user_data_dir

if getattr(sys, 'frozen', False):
    SCRIPT_DIR = sys._MEIPASS
else:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Chemin pour lecture (dans le bundle) et écriture (user_data_dir)
SETTINGS_BUNDLE_PATH = os.path.join(SCRIPT_DIR, "settings.ini")
SETTINGS_USER_PATH = os.path.join(user_data_dir("Nexa", "Nexa"), "settings.ini")

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

COLOR_CHOICES = {
	'dark grey': ('#424242', '#212121'),	'gris foncé': ('#424242', '#212121'),
	'dark blue': ('#1565c0', '#0d47a1'),	'bleu foncé': ('#1565c0', '#0d47a1'),
	'light green': ('#7ED957', '#388E3C'),	'vert clair': ('#7ED957', '#388E3C'),
	'light green': ('#00FF00', '#00FF00'),	'vert clair': ('#00FF00', '#00FF00'),
	'light blue': ('#339CFF', '#1976D2'),	'bleu clair': ('#339CFF', '#1976D2'),
	'reset': ('#339CFF', '#1976D2'),		'default': ('#339CFF', '#1976D2'),
	'red': ('#D50000', '#B71C1C'),			'rouge': ('#D50000', '#B71C1C'),
	'yellow': ('#FFEB3B', '#FBC02D'),		'jaune': ('#FFEB3B', '#FBC02D'),
	'green': ('#388E3C', '#1B5E20'),		'vert': ('#388E3C', '#1B5E20'),
	'pink': ('#FF69B4', '#C2185B'),			'rose': ('#FF69B4', '#C2185B'),
	'black': ('#212121', '#000000'),		'noir': ('#212121', '#000000'),
	'blue': ('#1976d2', '#0d47a1'),			'bleu': ('#1976d2', '#0d47a1'),
	'violet': ('#8e24aa', '#512da8'),
	'orange': ('#FF9800', '#F57C00'),
}

def load_color_settings():
    config = configparser.ConfigParser()
    # Priorité à la version utilisateur (modifiable)
    if os.path.exists(SETTINGS_USER_PATH):
        config.read(SETTINGS_USER_PATH)
    elif os.path.exists(SETTINGS_BUNDLE_PATH):
        config.read(SETTINGS_BUNDLE_PATH)
        # Copie la config du bundle vers le dossier utilisateur si pas déjà présent
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

def signal_handler(sig, frame):
	'''
	Ferme le programme quand Crtl+C est saisi.
	'''
	global app
	if app:
		app.destroy()
	try:
		if platform.system() == 'Windows':
			os.system(f'taskkill /PID {os.getpid()} /F >nul 2>&1')
	except Exception:
		pass
	try:
		os.kill(os.getpid(), 9)
	except Exception:
		pass
	sys.exit(0)

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
		print(f"Erreur lors de la recherche des nœuds: {str(e)}")
		if node_detection_callback:
			node_detection_callback([])
		return []

def async_getnodes(interval=60):
	'''
	Exécute la fonction get_nodes toutes les 60 secondes.
	'''
	global available_nodes
	available_nodes = get_nodes()
	if len(available_nodes) == 0:
		print("Aucun noeud en ligne.")
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
		
		data_dir = user_data_dir("Nexa", "Nexa")
		os.makedirs(data_dir, exist_ok=True)
		privkey_path = os.path.join(data_dir, "privkey.key")
		
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
		self.key_requested = False		# Indique si le client attend une clé
		self.message_to_send = None		# Stocke temporairement le message à envoyer
		self.recipient_key = None		# Stocke temporairement la clé destinataire
		
		self.loop = asyncio.new_event_loop()
		asyncio.set_event_loop(self.loop)
		self.websocket = None

	def verify_key(self, key):
		'''
		Vérifie si une clé publique est au bon format.
		'''
		try:
			if key and isinstance(key, str) and key.strip():
				return True
			return False
		except:
			return False

	async def receive_messages(self):
		"""
		Gère la réception des messages en continu, essaie de les déchiffrer,
		s'il y arrive, affiche le message, sinon ne fait rien.
		"""
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
				print(f"Erreur lors de la réception du message. (\"{e}\")")

	async def send_message_with_key(self, message, recipient_key, pseudo):
		'''
		Méthode pour envoyer un message directement avec une clé (spécifiquement pour l'interface).
		'''
		if not self.websocket:
			print("Tu n'es pas connecté au serveur.")
			return False
		try:
			new_msg = ""
			for lettre in message:
				if lettre == "'":
					new_msg += "¤"
				else:
					new_msg += lettre

			if not self.verify_key(recipient_key):
				messagebox.showerror("Erreur", "Assure-toi d’avoir correctement saisi la clé publique !")
				return False
			msg_id = str(uuid.uuid4())
			msgEncrypt = encrypt(recipient_key, new_msg.encode())
			await self.websocket.send(f"{pseudo};{msgEncrypt.hex()};{recipient_key};{msg_id}")

			print(f"Toi: {message}")					# Simule la réception de son propre message avec "Toi:" au lieu du pseudo)
			return True
		except Exception as e:
			print(f"Erreur lors de l'envoi du message : {str(e)}")
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
						print("\nTu ne peux pas avoir un pseudo vide.")
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
							print(f"Vous: {message}")
							message_queue.task_done()
							await asyncio.sleep(0.01)	# Légère pause pour éviter de surcharger le serveur
						except asyncio.CancelledError:
							break
						except Exception as e:
							messagebox.showerror("Erreur", "Assure-toi d'avoir correctement saisi la clé publique. Réessaie.")
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
								print("Erreur: Clé du destinataire invalide.")
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
				print("Erreur: Connexion fermée par le serveur.")
		except asyncio.CancelledError:
			pass
		except Exception as e:
			if not self.quitting:
				print(f"Erreur: Problème de connexion au serveur. (\"{e}\")")

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
				print(f"Erreur inattendue dans le maintien de la connexion : {e}")

	async def reconnect(self):
		'''
		Tente de se reconnecter au serveur en cas de déconnexion.
		'''
		try:
			print("Tentative de reconnexion...")
			await self.connect_and_send()
		except Exception as e:
			print(f"Échec de la reconnexion : {e}")

	def start(self):
		'''
		Démarre le client.
		'''
		try:
			self.loop.run_until_complete(self.connect_and_send())
		except KeyboardInterrupt:
			self.quitting = True
			print("\nFermeture du programme...\n")
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
            # Ne pas afficher l'erreur spécifique de la boucle événementielle
            if "Event loop stopped before Future completed" not in str(e):
                print(f"Erreur dans le client: {e}")
        finally:
            self.client = None
        
    def stop_client(self):
        if not self.client:
            return
            
        self.quitting = True
        if self.client:
            self.client.quitting = True
            
        # Fermer la websocket et annuler toutes les tâches en attente
        try:
            if hasattr(self.client, 'websocket') and self.client.websocket:
                loop = self.client.loop
                if loop and loop.is_running():
                    # Annuler toutes les tâches en cours
                    for task in asyncio.all_tasks(loop):
                        task.cancel()
                    
                    # Fermer la websocket proprement
                    coro = self.client.websocket.close()
                    future = asyncio.run_coroutine_threadsafe(coro, loop)
                    try:
                        # Attendre la fermeture avec timeout
                        future.result(timeout=1.0)
                    except (asyncio.TimeoutError, concurrent.futures.TimeoutError, Exception):
                        pass
        except Exception as e:
            pass
            
        # Attendre que le thread du client se termine
        max_wait = 2.0  # secondes
        start_time = time.time()
        while self.client_thread and self.client_thread.is_alive() and time.time() - start_time < max_wait:
            time.sleep(0.1)
            
        # Forcer l'arrêt de la boucle événementielle
        if self.client and hasattr(self.client, 'loop') and self.client.loop:
            try:
                loop = self.client.loop
                if loop.is_running():
                    # Définir un signal de sortie pour toutes les tâches en attente
                    for task in asyncio.all_tasks(loop):
                        if not task.done():
                            task.cancel()
                    
                    # Arrêter la boucle
                    loop.call_soon_threadsafe(loop.stop)
            except Exception:
                pass
                
        # Nettoyer le client
        self.client = None

# Interface graphique
class MessageRedirect:
	def __init__(self, text_widget, pseudo, save_message_callback=None):
		self.text_widget = text_widget
		self.pseudo = pseudo
		self.queue = queue.Queue()
		self.original_stdout = sys.stdout
		self.updating = True
		self.save_message_callback = save_message_callback
		self.root = None
		threading.Thread(target=self.update_loop, daemon=True).start()

	def write(self, string):
		if "Erreur" in string or "erreur" in string:
			self.queue.put(("error", string))
		elif "Erreur lors de la recherche des nœuds" in string or ("Erreur:" in string and "nœud" in string.lower()):
			print("DEBUG:", string, file=self.original_stdout)
		else:
			if ": " in string and not any(x in string for x in ("===", "Ta clé", "Connexion")):
				try:
					parts = string.split(": ", 1)
					if len(parts) >= 2:
						sender, message = parts[0], parts[1].strip()
						if self.save_message_callback:
							timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
							self.save_message_callback(sender, message, timestamp)
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
							self.text_widget.winfo_toplevel().after(0, lambda s=string: messagebox.showerror("Erreur", s.strip()))
					else:
						self.text_widget.config(state=tk.NORMAL)
						string = string.rstrip()
						if ": " in string and not any(x in string for x in ("Ta clé", "Connexion")):
							try:
								parts = string.split(": ", 1)
								if len(parts) >= 2:
									sender, message = parts[0], parts[1]
									time_str = datetime.now().strftime("%H:%M")
									if sender.strip() == self.pseudo.strip():
										self.text_widget.insert(tk.END, f"[{time_str}] {sender}: ", "sender_name")
										self.text_widget.insert(tk.END, f"{message.strip()}", "message_sent")
									else:
										self.text_widget.insert(tk.END, f"[{time_str}] {sender}: ", "sender_name")
										self.text_widget.insert(tk.END, f"{message.strip()}", "message_received")
									self.text_widget.insert(tk.END, "\n", "")
							except Exception as e:
								print(f"DEBUG: Erreur format message: {e}", file=self.original_stdout)
								self.text_widget.insert(tk.END, string)
						else:
							if not ("erreur" in string.lower() or "error" in string.lower()):
								string = string.strip()
								if string:
									self.text_widget.insert(tk.END, string, "system_message")
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
		self.title("Nexa Chat")
		self.geometry("490x700")			# Taille de la fenêtre
		self.minsize(490, 600)				# Taille minimale

		self.center_window()
		self.protocol("WM_DELETE_WINDOW", self.on_closing)

		self.is_mac = platform.system() == "Darwin"			# Adapte l'interface en fonction de l'OS utilisé
		
		# Forcer le mode clair sur toutes les plateformes
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
		self.pseudo = StringVar()
		self.status = StringVar(value="Déconnecté")
		self.key_var = StringVar(value="Non disponible")
		self.nodes_var = StringVar(value="Recherche de nœuds...")
		self.client = None
		self.connected = False
		self.message_queue = queue.Queue()
		self.key_queue = queue.Queue()
		self.client_wrapper = WrapperClient()

		if platform.system() == "Windows":
			icon_path = os.path.join(SCRIPT_DIR, "NexaIcon.ico")
			if os.path.exists(icon_path):
				try:
					self.iconbitmap(icon_path)
				except Exception as e:
					print(f"DEBUG: L'icône Windows n'a pas pu être chargée : {e}", file=sys.stdout)

		data_dir = user_data_dir("Nexa", "Nexa")
		os.makedirs(data_dir, exist_ok=True)
		self.msg_db = sqlite3.connect(os.path.join(data_dir, "message.db"), check_same_thread=False)

		self.msg_cursor = self.msg_db.cursor()
		self.msg_cursor.execute('''
			CREATE TABLE IF NOT EXISTS messages (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				sender TEXT,
				message TEXT,
				timestamp TEXT
			)
		''')
		self.msg_db.commit()
		self.create_widgets()
		self.load_message_history()			# Charge l'historique des messages précédents
		self.after(100, self.check_input_needed)
		self.setup_nodes_detection()

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
		ttk.Label(header_padding, text="Nexa Chat", style='Header.TLabel').pack(anchor=tk.CENTER, expand=True)

		# Page de connexion
		self.login_frame = ttk.Frame(main_frame, padding=20)	
		self.login_frame.pack(fill=tk.BOTH, expand=True, pady=(60, 0))  # Ajout d'un padding vertical
		
		icon_path = os.path.join(SCRIPT_DIR, "NexaIcon.png")
		if os.path.exists(icon_path):
			try:
				pil_image = Image.open(icon_path)
				# Redimensionne l'image pour qu'elle ne soit pas trop grosse
				pil_image = pil_image.resize((64, 64), Image.LANCZOS if hasattr(Image, 'LANCZOS') else Image.ANTIALIAS)
				self.tk_logo = ImageTk.PhotoImage(pil_image)
				logo_label = ttk.Label(self.login_frame, image=self.tk_logo)
			except Exception as e:
				logo_label = ttk.Label(self.login_frame, text="📱", font=(self.default_font, 48))
		else:
			logo_label = ttk.Label(self.login_frame, text="📱", font=(self.default_font, 48))
		logo_label.pack(pady=(30, 20))
				
		ttk.Label(self.login_frame,
					text="Bienvenue sur Nexa Chat !",
					font=(self.default_font, 16, "bold")).pack(pady=(0, 30))
		
		# Formulaire de connexion
		form_frame = ttk.Frame(self.login_frame, padding=10)
		form_frame.pack(fill=tk.X)

		ttk.Label(form_frame, text="Saisis ton pseudo :").pack(anchor=tk.W, pady=(0, 5))
		pseudo_entry = ttk.Entry(form_frame, textvariable=self.pseudo, font=(self.default_font, 12))
		pseudo_entry.pack(fill=tk.X, pady=(0, 20))
		pseudo_entry.bind("<Return>", lambda event: self.connect() if self.connect_button['state'] != tk.DISABLED else None)
		ttk.Label(form_frame, textvariable=self.nodes_var).pack(anchor=tk.W, pady=(0, 10))
		
		# Bouton de connexion avec style adapté selon la plateforme
		if self.is_mac:
			self.connect_button = ttk.Button(form_frame, 
								 text="Me connecter",
								 command=self.connect,
								 style='TButton')
			self.connect_button.pack(fill=tk.X, pady=5)
		else:
			self.connect_button = tk.Button(form_frame,
								text="Me connecter",
								command=self.connect,
								bg=self.primary_color,
								fg="white", 
								font=(self.default_font, 10, 'bold'),
								relief=tk.RAISED,
								borderwidth=0,
								padx=10, pady=8,
								cursor="hand2")
			self.connect_button.pack(fill=tk.X, ipady=8)
		
		self.connect_button.config(state=tk.DISABLED)  # Désactivé par défaut jusqu'à ce que des nœuds soient trouvés
			
		# Fenêtre de chat
		self.chat_frame = ttk.Frame(main_frame)

		# En-tête avec clé publique de l'utilisateur
		key_frame = ttk.Frame(self.chat_frame, padding=10)
		key_frame.pack(fill=tk.X)
		ttk.Label(key_frame, text="Ta clé publique :", font=(self.default_font, 9, 'bold')).pack(anchor=tk.W)
		
		key_display_frame = ttk.Frame(key_frame)
		key_display_frame.pack(fill=tk.X, pady=5)

		self.key_label = ttk.Label(key_display_frame,
							 textvariable=self.key_var,
							 style='Key.TLabel',
							 wraplength=0,
							 anchor='w',
							 background='#EEEEEE')
		
		self.key_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5), ipady=5, ipadx=5)
		
		# Bouton pour copier la clé
		if self.is_mac:
			copy_btn = ttk.Button(key_display_frame,
						   text="Copier",
						   command=self.copy_key,
						   style='TButton')
		else:
			copy_btn = tk.Button(key_display_frame,
						   text="Copier",
						   command=self.copy_key,
						   bg=self.primary_color,
						   fg="white",
						   font=(self.default_font, 9, 'bold'),
						   relief=tk.RAISED,
						   borderwidth=0,
						   padx=8, pady=2,
						   cursor="hand2")
		
		copy_btn.pack(side=tk.RIGHT)
		ttk.Separator(self.chat_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)

		 # Zone d'affichage des messages
		self.chat_text = scrolledtext.ScrolledText(self.chat_frame,
												wrap=tk.WORD,
												height=15,
												font=(self.default_font, 11),
												bd=1 if self.is_mac else 0,  # Bordure légère sur Mac
												relief=tk.SUNKEN if self.is_mac else tk.FLAT
												)
		self.chat_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
		self.chat_text.config(state=tk.DISABLED)

		# Configuration des tags pour le formatage du texte
		self.chat_text.tag_configure("message_sent",
									font=(self.default_font, 11),
									spacing1=0, spacing2=0, spacing3=0,
									lmargin1=5, lmargin2=5,
									foreground="black")

		self.chat_text.tag_configure("system_message_center",
									foreground="#757575",
									font=(self.default_font, 9),
									justify='center',
									spacing1=2, spacing2=0, spacing3=2)
							
		self.chat_text.tag_configure("message_received",
									font=(self.default_font, 11),
									spacing1=0, spacing2=0, spacing3=0,
									lmargin1=5, lmargin2=5,
									foreground="black")
		
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
		dest_frame = ttk.Frame(self.chat_frame, padding=10)
		dest_frame.pack(fill=tk.X)
		ttk.Label(dest_frame, text="Clé du destinataire :", font=(self.default_font, 9, 'bold')).pack(anchor=tk.W)
		
		dest_entry = ttk.Entry(dest_frame, textvariable=self.recipient_key)
		dest_entry.pack(fill=tk.X, pady=5)
		ttk.Separator(self.chat_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)
		
		msg_frame = ttk.Frame(self.chat_frame, padding=10)
		msg_frame.pack(fill=tk.X, side=tk.BOTTOM)
		ttk.Label(msg_frame, text="Message :", font=(self.default_font, 9, 'bold')).pack(anchor=tk.W)

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
				
			for btn in buttons:
				btn.bind("<Enter>", lambda e, b=btn: b.config(bg=self.secondary_color))
				btn.bind("<Leave>", lambda e, b=btn: b.config(bg=self.primary_color))

	def load_message_history(self):
		'''
		Charge l'historique des messages stockés dans message.db et les affiche.
		'''
		try:
			self.msg_cursor.execute("SELECT sender, message, timestamp FROM messages ORDER BY id")
			rows = self.msg_cursor.fetchall()
			if rows:
				self.chat_text.config(state=tk.NORMAL)
				for sender, message, timestamp in rows:
					time_str = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").strftime("%H:%M")
					self.chat_text.insert(tk.END, f"[{time_str}] {sender}: ", "sender_name")
					self.chat_text.insert(tk.END, f"{message}\n", "message_received")
				self.chat_text.config(state=tk.DISABLED)
				self.chat_text.see(tk.END)					# Défilement automatique vers le bas (pour voir les messages récents)
		except Exception as e:
			print(f"DEBUG: Erreur lors du chargement de l'historique: {e}", file=sys.stdout)

	def save_message(self, sender, message, timestamp):
		'''
		Sauvegarde les messages dans message.db.
		'''
		try:
			self.msg_cursor.execute("INSERT INTO messages (sender, message, timestamp) VALUES (?, ?, ?)", (sender, message, timestamp))
			self.msg_db.commit()
		except Exception as e:
			print(f"DEBUG: Erreur lors de la sauvegarde du message: {e}", file=sys.stdout)

	def connect(self):
		'''
		Gère la connexion aux nœuds.
		'''
		pseudo = self.pseudo.get().strip()
		if not pseudo:
			messagebox.showerror("Erreur", "Tu dois forcément avoir un pseudo !")
			return
		
		self.status.set("Connexion en cours...")
		self.connect_button.config(state=tk.DISABLED)
		
		def setup_client():
			try:
				if not self.client_wrapper.start_client("auto", 9102):
					self.after(0, lambda: messagebox.showerror("Erreur", "Une connexion est déjà en cours"))
					return
					
				self.client = self.client_wrapper.client

				# Met à jour l'interface
				self.after(0, lambda: self.key_var.set(self.client.pubKey))
				self.after(0, self.show_chat_interface)

				redirect = MessageRedirect(self.chat_text, pseudo, save_message_callback=self.save_message)
				self.original_stdout = sys.stdout
				sys.stdout = redirect
				self.original_input = __builtins__.input
				__builtins__.input = self.mock_input

			except Exception as e:  # En cas d'erreur, revenir à l'écran de connexion
				self.after(0, lambda: self.status.set(f"Erreur : {str(e)}"))
				self.after(0, lambda: self.connect_button.config(state=tk.NORMAL))
				self.after(0, lambda e=e: messagebox.showerror("Erreur", f"Impossible de se connecter :\n{str(e)}"))
				self.after(0, self.show_login_interface)
		threading.Thread(target=setup_client, daemon=True).start()

	def show_chat_interface(self):
		'''
		Affiche l'interface de chat.
		 '''
		self.login_frame.pack_forget()
		self.chat_frame.pack(fill=tk.BOTH, expand=True)
		self.connected = True
		# Affiche la date (au centre) uniquement si ce n'est pas un /reconnect
		if not hasattr(self, '_reconnecting') or not self._reconnecting:
			current_date = datetime.now().strftime("%A %d %B %Y")
			current_date = current_date[0].upper() + current_date[1:]
			self.chat_text.config(state=tk.NORMAL)
			self.chat_text.insert(tk.END, "\n", "system_message")
			self.chat_text.insert(tk.END, current_date + "\n", "system_message_center")
			self.chat_text.config(state=tk.DISABLED)
		self.msg_entry.focus_set()
		self._reconnecting = False

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
			return self.pseudo.get().strip()
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
			messagebox.showerror("Erreur", "Vous n'êtes pas connecté.")
			return
		message = self.message_to_send.get().strip()
		if not message:
			return
		if message.startswith("/color "):
			color_name = message[7:].strip().lower()
			if self.set_theme_color(color_name):
				self.message_to_send.set("")
			return
		if message == "/reconnect":
			self._reconnecting = True
			self.disconnect_and_reset()
			self.message_to_send.set("")
			return
		if message == "/clear":
			try:
				self.msg_cursor.execute("DELETE FROM messages")
				self.msg_db.commit()
				self.chat_text.config(state=tk.NORMAL)
				self.chat_text.delete(1.0, tk.END)
				self.chat_text.config(state=tk.DISABLED)
				# Réaffiche la date après avoir effacé les messages
				current_date = datetime.now().strftime("%A %d %B %Y")
				current_date = current_date[0].upper() + current_date[1:]
				self.chat_text.config(state=tk.NORMAL)
				self.chat_text.insert(tk.END, "\n", "system_message")
				self.chat_text.insert(tk.END, current_date + "\n", "system_message_center")
				self.chat_text.insert(tk.END, "Historique des messages effacé.\n", "system_message_center")
				self.chat_text.config(state=tk.DISABLED)
				self.chat_text.see(tk.END)
			except Exception as e:
				print(f"Erreur lors de la suppression de l'historique: {e}")
			self.message_to_send.set("")
			return
			
		# Vérification de la longueur du message (sans compter les espaces)
		message_no_spaces = message.replace(" ", "")
		if len(message_no_spaces) > 10000:
			messagebox.showerror("Erreur", "Le message est trop long. La limite est de 10000 caractères (espaces non compris).")
			return
		
		self.message_to_send.set("")
		if hasattr(self.client, 'key_requested') and self.client.key_requested:
			key = self.recipient_key.get().strip()
			if key and hasattr(self.client, 'verify_key') and self.client.verify_key(key):
				try:
					future = self.key_queue.get_nowait()
					future.put(key)
				except queue.Empty:
					print(key)
			else:
				messagebox.showerror("Erreur", "La clé publique du destinataire n'est pas valide.\nLa clé doit être au format hexadécimal.")
				for widget in self.winfo_children():
					if isinstance(widget, ttk.Entry) and widget.winfo_parent() == str(self.chat_frame.winfo_child("!frame2")):
						widget.focus_set()
						break
			return
		key = self.recipient_key.get().strip()
		if not key or not (hasattr(self.client, 'verify_key') and self.client.verify_key(key)):
			messagebox.showerror("Erreur", "Vérifie la clé publique et réessaie.")
			return
		if hasattr(self.client, 'message_to_send') and hasattr(self.client, 'recipient_key'):
			self.client.message_to_send = message
			self.client.recipient_key = key
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
		if self.client_wrapper:
			self.client_wrapper.stop_client()
		try:
			self.msg_db.close()
		except:
			pass
		self.destroy()
		self.quitting = True
		try:
			if platform.system() == 'Windows':
				os.system(f'taskkill /PID {os.getpid()} /F >nul 2>&1')
		except Exception:
			pass
		try:
			os.kill(os.getpid(), 9)
		except Exception:
			pass
		sys.exit(0)

if __name__ == "__main__":
	app = NexaInterface()
	app.mainloop()