import asyncio, websockets, threading, ast, uuid, requests, pyperclip, random, sys, os, platform, signal
import queue, time, tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, StringVar
from ecies import encrypt, decrypt
from ecies.utils import generate_eth_key
from datetime import datetime
import locale
import sqlite3

# Définir la locale en français
try:
    locale.setlocale(locale.LC_TIME, 'fr_FR.UTF-8')
except:
    try:
        locale.setlocale(locale.LC_TIME, 'fr_FR')
    except:
        try:
            locale.setlocale(locale.LC_TIME, 'fra_fra')
        except:
            pass  # Garder la locale par défaut si impossible de définir le français

# Variables globales
available_nodes = []
node_detection_callback = None
app = None  # Variable globale pour stocker l'instance de l'application

# Gestionnaire de signal pour Ctrl+C
def signal_handler(sig, frame):
    global app
    #print("\nFermeture du programme via Ctrl+C...")
    if app:
        app.destroy()
    if platform.system() == "Windows":
        os.system("taskkill /F /PID " + str(os.getppid()))
    else:
        os.kill(os.getpid(), signal.SIGTERM)
    sys.exit(0)

# Configurer le gestionnaire de signal
signal.signal(signal.SIGINT, signal_handler)

def get_nodes():
    '''
    récupère la liste des noeuds sur le bootstrap
    '''
    try:
        url = "https://bootstrap.nexachat.tech/upNodes"
        response = requests.get(url)
        response.raise_for_status()
        nodes = response.json()
        
        # Si un callback est défini, appeler la fonction avec les nœuds
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
    éxécute la fonction get_nodes toutes les 60 sec
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
        try:
            with open("privkey.key", "r") as f:
                content = f.read().strip()
                if not content:
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
                    else:
                        print("Format de fichier de clés incorrect, régénération...")
                        self.keys = generate_eth_key()
                        self.privKey = self.keys.to_hex()
                        self.pubKey = self.keys.public_key.to_compressed_bytes().hex()
                        with open("privkey.key", "w") as f2:
                            f2.write(self.privKey + "\n" + self.pubKey)
        except FileNotFoundError:
            self.keys = generate_eth_key()
            self.privKey = self.keys.to_hex()
            self.pubKey = self.keys.public_key.to_compressed_bytes().hex()
            with open("privkey.key", "w") as f:
                f.write(self.privKey + "\n" + self.pubKey)
        
        self.seen_messages = set()
        self.quitting = False
        self.key_requested = False  # Indique si le client attend une clé
        self.message_to_send = None  # Pour stocker temporairement le message à envoyer
        self.recipient_key = None   # Pour stocker temporairement la clé destinataire
        
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.websocket = None
        
    def verify_key(self, key):
        """Vérifie si une clé est valide"""
        try:
            if key and isinstance(key, str) and key.strip():
                return True
            return False
        except:
            return False
        
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
    
    async def send_message_with_key(self, message, recipient_key, pseudo):
        """Méthode pour envoyer un message directement avec une clé (pour l'interface)"""
        if not self.websocket:
            print("Vous n'êtes pas connecté au serveur.")
            return False

        try:
            # Formater le message comme dans la méthode connect_and_send
            new_msg = ""
            for lettre in message:
                if lettre == "'":
                    new_msg += "¤"
                else:
                    new_msg += lettre

            # Vérifier que la clé du destinataire est valide
            if not self.verify_key(recipient_key):
                print("Erreur: Veuillez entrer une clé publique valide avant d'envoyer un message.")
                return False

            # Chiffrer et envoyer immédiatement (sans délai)
            msg_id = str(uuid.uuid4())
            msgEncrypt = encrypt(recipient_key, new_msg.encode())
            await self.websocket.send(f"{pseudo};{msgEncrypt.hex()};{recipient_key};{msg_id}")
            
            # Auto-feedback pour l'émetteur (simule la réception de son propre message avec "Vous:" au lieu du pseudo)
            print(f"Vous: {message}")
            
            return True

        except Exception as e:
            print(f'Erreur lors de l\'envoi du message : {str(e)}')
            return False
    
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
        
        uri = f"ws://{host}:{port}"
        try:
            async with websockets.connect(uri) as websocket:
                self.websocket = websocket
                
                # Tâche de ping pour maintenir la connexion active
                ping_task = asyncio.create_task(self.keep_connection_alive())
        
                pseudo = ""
                while not pseudo.strip():
                    pseudo = input("Entrez votre pseudo : ")
                    if not pseudo.strip():
                        print("\nTu ne peux pas avoir un pseudo vide.")
                        
                registration_msg = f"register;client;{pseudo};{self.pubKey}"
                await websocket.send(registration_msg)
                
                receive_task = asyncio.create_task(self.receive_messages())
                
                # File d'attente pour les messages à envoyer
                message_queue = asyncio.Queue()
                
                # Tâche qui consomme les messages de la file d'attente et les envoie
                async def message_processor():
                    while True:
                        try:
                            # Récupérer un message de la file d'attente
                            msg_data = await message_queue.get()
                            message, recipient_key = msg_data
                            
                            # Formater le message
                            new_msg = ""
                            for lettre in message:
                                if lettre == "'":
                                    new_msg += "¤"
                                else:
                                    new_msg += lettre

                            # Chiffrer et envoyer
                            msg_id = str(uuid.uuid4())
                            msgEncrypt = encrypt(recipient_key, new_msg.encode())
                            await websocket.send(f"{pseudo};{msgEncrypt.hex()};{recipient_key};{msg_id}")
                            
                            # Feedback pour l'émetteur
                            print(f"Vous: {message}")
                            
                            # Marquer cette tâche comme terminée
                            message_queue.task_done()
                            
                            # Petite pause pour éviter de surcharger le serveur
                            await asyncio.sleep(0.01)
                            
                        except Exception as e:
                            print(f"Erreur lors de l'envoi: {str(e)}")
                            message_queue.task_done()
                
                # Démarrer la tâche de traitement des messages
                processor_task = asyncio.create_task(message_processor())
                
                while True:
                    # Si un message et une clé ont été définis par l'interface
                    if self.message_to_send and self.recipient_key:
                        msg = self.message_to_send
                        key = self.recipient_key
                        
                        # Réinitialiser les variables après capture
                        self.message_to_send = None
                        self.recipient_key = None
                        
                        # Vérifier que la clé est valide
                        if self.verify_key(key):
                            # Ajouter à la file d'attente au lieu d'envoyer directement
                            await message_queue.put((msg, key))
                        else:
                            print("Erreur: Clé du destinataire invalide.")
                    
                    # Pause pour éviter une boucle infinie trop rapide
                    await asyncio.sleep(0.05)
        
        except websockets.exceptions.ConnectionClosed:
            print("Erreur: Connexion fermée par le serveur.")
        except Exception as e:
            print(f'Erreur: Problème de connexion au serveur. ("{e}")')
    
    async def keep_connection_alive(self, interval=30):
        """Envoie périodiquement un ping pour maintenir la connexion active"""
        try:
            while True:
                await asyncio.sleep(interval)
                if self.websocket and not self.quitting:
                    try:
                        # Envoi d'un ping silencieux
                        await self.websocket.ping()
                        #print("Ping envoyé pour maintenir la connexion active.")
                    except Exception as e:
                        print(f"Erreur lors de l'envoi du ping : {e}")
                        # Tentative de reconnexion si le ping échoue
                        await self.reconnect()
        except asyncio.CancelledError:
            print("Tâche de ping annulée.")
        except Exception as e:
            if not self.quitting:
                print(f"Erreur inattendue dans le maintien de la connexion : {e}")

    async def reconnect(self):
        """Tente de se reconnecter au serveur en cas de déconnexion"""
        try:
            print("Tentative de reconnexion...")
            await self.connect_and_send()
        except Exception as e:
            print(f"Échec de la reconnexion : {e}")
    
    def start(self):
        '''
        démarre le client
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

# Interface graphique
class MessageRedirect:
    def __init__(self, text_widget, pseudo, save_message_callback=None):
        self.text_widget = text_widget
        self.pseudo = pseudo
        self.queue = queue.Queue()
        self.original_stdout = sys.stdout
        self.updating = True
        self.save_message_callback = save_message_callback  # New callback for persisting messages
        self.root = None
        threading.Thread(target=self.update_loop, daemon=True).start()

    def write(self, string):
        if "Erreur" in string or "erreur" in string:
            # Mettre les erreurs dans une queue spéciale pour le traitement UI
            self.queue.put(("error", string))
        elif "Erreur lors de la recherche des nœuds" in string or ("Erreur:" in string and "nœud" in string.lower()):
            # Débug uniquement, pas d'affichage
            print("DEBUG:", string, file=self.original_stdout)
        else:
            # For normal chat messages with ": " (sender and message)
            if ": " in string and not any(x in string for x in ("===", "Ta clé", "Connexion")):
                try:
                    parts = string.split(": ", 1)
                    if len(parts) >= 2:
                        sender, message = parts[0], parts[1].strip()
                        # Call callback to store message
                        if self.save_message_callback:
                            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            self.save_message_callback(sender, message, timestamp)
                except Exception as e:
                    pass
            self.queue.put(("message", string))

    def flush(self): pass

    def update_loop(self):
        """Boucle de mise à jour du widget de texte avec formatage amélioré"""
        last_date = None
        while self.updating:
            try:
                while True:
                    item = self.queue.get_nowait()
                    item_type, string = item
                    
                    if item_type == "error":
                        # Utiliser after pour exécuter messagebox dans le thread principal
                        if self.text_widget.winfo_toplevel():
                            self.text_widget.winfo_toplevel().after(0, 
                                lambda s=string: messagebox.showerror("Erreur", s.strip()))
                    else:
                        # Traitement normal des messages
                        self.text_widget.config(state=tk.NORMAL)

                        # Supprimer les retours à la ligne superflus
                        string = string.rstrip()
                        
                        # Format spécial pour les messages envoyés/reçus
                        if ": " in string and not any(x in string for x in ("===", "Ta clé", "Connexion")):
                            try:
                                # Extraction du message et du destinataire
                                parts = string.split(": ", 1)
                                
                                if len(parts) >= 2:
                                    sender, message = parts[0], parts[1]
                                    time_str = datetime.now().strftime("%H:%M")
                                    
                                    # Message envoyé ou reçu
                                    if sender.strip() == self.pseudo.strip():
                                        self.text_widget.insert(tk.END, f"[{time_str}] {sender}: ", "sender_name")
                                        self.text_widget.insert(tk.END, f"{message.strip()}", "message_sent")
                                        #print(f"DEBUG: Message envoyé traité: '{message.strip()}'", file=self.original_stdout)
                                    else:
                                        self.text_widget.insert(tk.END, f"[{time_str}] {sender}: ", "sender_name")
                                        self.text_widget.insert(tk.END, f"{message.strip()}", "message_received")
                                    
                                    # Ajouter un seul retour à la ligne pour tous les messages
                                    self.text_widget.insert(tk.END, "\n", "")
                            except Exception as e:
                                print(f"DEBUG: Erreur format message: {e}", file=self.original_stdout)
                                self.text_widget.insert(tk.END, string)
                                # Ne pas ajouter de \n supplémentaire ici
                        else:
                            # Messages système (garder compact)
                            if not ("erreur" in string.lower() or "error" in string.lower()):
                                string = string.strip()  # Éliminer tous les espaces et retours à la ligne superflus
                                if string:  # Ne pas insérer de lignes vides
                                    self.text_widget.insert(tk.END, string, "system_message")
                                    # Ajouter un seul retour à la ligne
                                    self.text_widget.insert(tk.END, "\n", "")

                        self.text_widget.config(state=tk.DISABLED)
                        self.text_widget.see(tk.END)  # Défilement automatique vers le bas
                    
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
        self.geometry("490x700")                # Taille de la fenêtre
        self.minsize(490, 600)
        
        # Centrer la fenêtre sur l'écran
        self.center_window()
        
        # Configurer le gestionnaire d'événement pour la fermeture de la fenêtre
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Configuration du style
        self.style = ttk.Style()
        self.style.theme_use('clam')  # Utiliser le thème 'clam' qui est plus moderne
        
        # Palette de couleurs modernes
        self.primary_color = "#6C63FF"  # Violet/bleu moderne
        self.secondary_color = "#5A54D9"  # Violet plus foncé
        self.accent_color = "#4CAF50"  # Vert pour les statuts connectés
        self.error_color = "#FF5252"  # Rouge pour les erreurs
        self.bg_color = "#FAFAFA"  # Fond presque blanc
        self.text_color = "#212121"  # Texte presque noir
        self.message_sent_bg = "#E6F9E6"  # Vert clair pour les messages envoyés (anciennement bleu clair #E3F2FD)
        self.message_received_bg = "#F1F0FE"  # Violet très clair pour les messages reçus
        
        # Configuration des styles
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('Header.TFrame', background=self.primary_color)
        
        self.style.configure('TLabel', 
                                background=self.bg_color, 
                                foreground=self.text_color)
        
        self.style.configure('Header.TLabel', 
                            font=('Segoe UI', 16, 'bold'), 
                            foreground='white',
                            background=self.primary_color)
        
        self.style.configure('Header.Subtitle.TLabel', 
                            font=('Segoe UI', 10), 
                            foreground='white',
                            background=self.primary_color)
        
        # Style de bouton avec coins arrondis
        self.style.configure('TButton', 
                            font=('Segoe UI', 10),
                            borderwidth=0,
                            relief="flat",
                            padding=5)
        
        self.style.map('TButton', 
                        foreground=[('pressed', 'white'), ('active', 'white')],
                        background=[('pressed', self.secondary_color), 
                                ('active', self.secondary_color)])
        
        # Style spécifique pour les boutons d'action
        self.style.configure('Rounded.TButton', 
                            font=('Segoe UI', 10, 'bold'),
                            background=self.primary_color,
                            foreground='white',
                            borderwidth=0,
                            padding=8)
        
        self.style.map('Rounded.TButton', 
                        foreground=[('pressed', 'white'), ('active', 'white')],
                        background=[('pressed', self.secondary_color), 
                                ('active', self.secondary_color)])
        
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
        
        self.style.configure('Status.TLabel', 
                            foreground=self.error_color)
        
        self.style.configure('Connected.Status.TLabel', 
                            foreground=self.accent_color)
        
        self.style.configure('Key.TLabel', 
                            font=('Segoe UI', 9), 
                            background='#EEEEEE')
        
        # Style pour les boutons avec coins arrondis
        self.style.configure('RoundedButton.TButton', 
                            font=('Segoe UI', 10, 'bold'),
                            background=self.primary_color,
                            foreground='white',
                            padding=(10, 5),
                            relief='flat',
                            borderwidth=0)
        
        self.style.map('RoundedButton.TButton', 
                        foreground=[('pressed', 'white'), ('active', 'white')],
                        background=[('pressed', self.secondary_color), 
                                ('active', self.secondary_color)])
        
        # Variables
        self.message_to_send = StringVar()
        self.recipient_key = StringVar()
        self.pseudo = StringVar()
        self.status = StringVar(value="Déconnecté")
        self.key_var = StringVar(value="Non disponible")
        self.nodes_var = StringVar(value="Recherche de nœuds...")
        
        # Variables d'état
        self.client = None
        self.connected = False
        self.message_queue = queue.Queue()
        self.key_queue = queue.Queue()
        
        # Icône d'application (si disponible)
        try:
            self.iconbitmap('icon.ico')
        except:
            pass  # Pas d'icône disponible
        
        # Open (or create) the message database and table
        self.msg_db = sqlite3.connect(r"c:\Users\crist\Desktop\dev\Nexa\message.db", check_same_thread=False)
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
        
        # Créer l'interface
        self.create_widgets()
        self.load_message_history()  # Load history on startup
        
        # Polling des entrées utilisateur toutes les 100ms
        self.after(100, self.check_input_needed)
        
        # Lancer la détection des nœuds
        self.setup_nodes_detection()
    
    def center_window(self):
        """Centre la fenêtre sur l'écran"""
        # Mettre à jour la fenêtre pour s'assurer que les dimensions sont correctes
        self.update_idletasks()
        
        # Obtenir les dimensions de l'écran
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        
        # Calculer la position pour centrer la fenêtre
        width = self.winfo_width()
        height = self.winfo_height()
        x = (screen_width - width) // 2
        
        # Ajustement pour positionner un peu plus haut sur l'écran
        y = (screen_height - height) // 2 - 50  # Décaler de 50 pixels vers le haut
        
        # Définir la position de la fenêtre
        self.geometry(f"{width}x{height}+{x}+{y}")
    
    def setup_nodes_detection(self):
        """Configure la détection des nœuds"""
        # Fonction callback pour mettre à jour l'interface
        def update_nodes(nodes):
            if nodes:
                if len(nodes) == 1:
                    self.nodes_var.set("1 nœud disponible")
                else:
                    self.nodes_var.set(f"{len(nodes)} nœuds disponibles")
                
                # Activer le bouton de connexion
                self.connect_button.config(state=tk.NORMAL)
            else:
                self.nodes_var.set("Aucun nœud disponible")
                # Désactiver le bouton de connexion
                self.connect_button.config(state=tk.DISABLED)
        
        global node_detection_callback
        node_detection_callback = update_nodes
        
        # Lancer la détection
        async_getnodes()
    
    def create_widgets(self):
        """Crée les widgets de l'interface"""
        # Conteneur principal
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # --- EN-TÊTE --- 
        header_frame = ttk.Frame(main_frame, style='Header.TFrame')
        header_frame.pack(fill=tk.X)
        
        # Ajouter du padding à l'en-tête
        header_padding = ttk.Frame(header_frame, style='Header.TFrame')
        header_padding.pack(fill=tk.X, padx=15, pady=15)
        
        # Titre et statut de connexion
        ttk.Label(header_padding, text="Nexa Chat", style='Header.TLabel').pack(anchor=tk.W)
        
        # Afficher le statut de connexion sous le titre
        status_frame = ttk.Frame(header_padding, style='Header.TFrame')
        status_frame.pack(fill=tk.X, pady=(2, 0))
        
        self.status_label = ttk.Label(status_frame, 
                                    textvariable=self.status, 
                                    style='Header.Subtitle.TLabel')
        self.status_label.pack(side=tk.LEFT)
        
        #--- ÉCRAN DE CONNEXION ---#
        self.login_frame = ttk.Frame(main_frame, padding=20)
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        
        # Logo ou icône (à remplacer par votre propre logo)
        logo_label = ttk.Label(self.login_frame, text="📱", font=("Segoe UI", 48))
        logo_label.pack(pady=(30, 20))
        
        ttk.Label(self.login_frame, 
                    text="Bienvenue sur Nexa Chat", 
                    font=("Segoe UI", 16, "bold")).pack(pady=(0, 30))
        
        # Formulaire de connexion
        form_frame = ttk.Frame(self.login_frame, padding=10)
        form_frame.pack(fill=tk.X)
        
        ttk.Label(form_frame, text="Votre pseudo :").pack(anchor=tk.W, pady=(0, 5))
        ttk.Entry(form_frame, textvariable=self.pseudo, font=("Segoe UI", 12)).pack(fill=tk.X, pady=(0, 20))
        
        # Statut des nœuds
        ttk.Label(form_frame, textvariable=self.nodes_var).pack(anchor=tk.W, pady=(0, 10))
        
        # Bouton de connexion
        self.connect_button = tk.Button(form_frame, 
                                        text="Se connecter", 
                                        command=self.connect,
                                        bg=self.primary_color,
                                        fg="white",
                                        font=('Segoe UI', 10, 'bold'),
                                        relief=tk.RAISED,
                                        borderwidth=0,
                                        padx=10,
                                        pady=8,
                                        cursor="hand2")
        self.connect_button.pack(fill=tk.X, ipady=8)
        self.connect_button.config(state=tk.DISABLED)  # Désactivé par défaut jusqu'à ce que des nœuds soient trouvés
        
        #--- ÉCRAN DE CHAT ---#
        self.chat_frame = ttk.Frame(main_frame)
        # Ne pas afficher tout de suite
        
        # En-tête avec info sur la clé
        key_frame = ttk.Frame(self.chat_frame, padding=10)
        key_frame.pack(fill=tk.X)
        
        ttk.Label(key_frame, text="Votre clé publique :", font=('Segoe UI', 9, 'bold')).pack(anchor=tk.W)
        
        key_display_frame = ttk.Frame(key_frame)
        key_display_frame.pack(fill=tk.X, pady=5)
        
        self.key_label = ttk.Label(key_display_frame, 
                                   textvariable=self.key_var, 
                                   style='Key.TLabel',
                                   wraplength=0,  # Désactiver le retour à la ligne
                                   anchor='w',  # Alignement à gauche
                                   background='#EEEEEE')
        self.key_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5), ipady=5, ipadx=5)
        
        copy_btn = tk.Button(key_display_frame, 
                            text="Copier", 
                            command=self.copy_key,
                            bg=self.primary_color,
                            fg="white",
                            font=('Segoe UI', 9, 'bold'),
                            relief=tk.RAISED,
                            borderwidth=0,
                            padx=8,
                            pady=2,
                            cursor="hand2")
        copy_btn.pack(side=tk.RIGHT)
        
        ttk.Separator(self.chat_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)
        
        # Zone d'affichage des messages
        self.chat_text = scrolledtext.ScrolledText(self.chat_frame, wrap=tk.WORD, height=15)
        self.chat_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.chat_text.config(state=tk.DISABLED)
        
        # Configurer les tags pour les messages avec des styles améliorés
        self.chat_text.tag_configure("message_sent", 
                                    font=('Segoe UI', 11),
                                    spacing1=0,  # Réduit à 0
                                    spacing2=0,  # Réduit à 0
                                    spacing3=0,  # Réduit à 0
                                    lmargin1=5,
                                    lmargin2=5,
                                    foreground="black")  # Couleur noire pour les messages

        # Tag pour centrer les messages système comme la date
        self.chat_text.tag_configure("system_message_center", 
                                    foreground="#757575",
                                    font=('Segoe UI', 9),
                                    justify='center',
                                    spacing1=2,  # Réduit
                                    spacing2=0,  # Réduit à 0
                                    spacing3=2)  # Réduit
        
        self.chat_text.tag_configure("message_received", 
                                    font=('Segoe UI', 11),
                                    spacing1=0,  # Réduit à 0
                                    spacing2=0,  # Réduit à 0
                                    spacing3=0,  # Réduit à 0
                                    lmargin1=5,
                                    lmargin2=5,
                                    foreground="black")  # Couleur noire pour les messages
        
        self.chat_text.tag_configure("sender_name", 
                                    font=('Segoe UI', 10, 'bold'),
                                    justify='left',
                                    lmargin1=5,
                                    lmargin2=5,
                                    foreground=self.primary_color)  # Couleur pour les noms
        
        self.chat_text.tag_configure("system_message", 
                                    foreground="#757575",
                                    font=('Segoe UI', 9),
                                    justify='left',
                                    spacing1=1,  # Réduit à 1
                                    spacing2=0,  # Réduit à 0
                                    spacing3=1,  # Réduit à 1
                                    lmargin1=5,
                                    lmargin2=5)
        
        # Zone de destinataire
        dest_frame = ttk.Frame(self.chat_frame, padding=10)
        dest_frame.pack(fill=tk.X)
        
        ttk.Label(dest_frame, text="Clé du destinataire :", font=('Segoe UI', 9, 'bold')).pack(anchor=tk.W)
        
        dest_entry = ttk.Entry(dest_frame, textvariable=self.recipient_key)
        dest_entry.pack(fill=tk.X, pady=5)
        
        # Séparateur
        ttk.Separator(self.chat_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)
        
        # Zone de saisie de message
        msg_frame = ttk.Frame(self.chat_frame, padding=10)
        msg_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        ttk.Label(msg_frame, text="Message:", font=('Segoe UI', 9, 'bold')).pack(anchor=tk.W)
        
        input_frame = ttk.Frame(msg_frame)
        input_frame.pack(fill=tk.X, pady=5)
        
        self.msg_entry = ttk.Entry(input_frame, textvariable=self.message_to_send, font=('Segoe UI', 10))
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.msg_entry.bind("<Return>", lambda e: self.send_message())
        
        send_btn = tk.Button(input_frame, 
                            text="Envoyer", 
                            command=self.send_message,
                            bg=self.primary_color,
                            fg="white",
                            font=('Segoe UI', 9, 'bold'),
                            relief=tk.RAISED,
                            borderwidth=0,
                            padx=10,
                            pady=4,
                            cursor="hand2")
        send_btn.pack(side=tk.RIGHT)
        
        # Ajouter des événements pour les effets de survol des boutons
        for btn in [self.connect_button, copy_btn, send_btn]:
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg=self.secondary_color))
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg=self.primary_color))
        
        # Appliquer des coins arrondis aux boutons après le chargement complet
        self.after(10, self.apply_rounded_corners)
    
    def load_message_history(self):
        """Charge l'historique des messages stocké dans message.db et les affiche."""
        try:
            self.msg_cursor.execute("SELECT sender, message, timestamp FROM messages ORDER BY id")
            rows = self.msg_cursor.fetchall()
            if rows:
                self.chat_text.config(state=tk.NORMAL)
                for sender, message, timestamp in rows:
                    # Format each message (you can adjust formatting as desired)
                    time_str = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").strftime("%H:%M")
                    self.chat_text.insert(tk.END, f"[{time_str}] {sender}: ", "sender_name")
                    self.chat_text.insert(tk.END, f"{message}\n", "message_received")
                self.chat_text.config(state=tk.DISABLED)
        except Exception as e:
            print(f"DEBUG: Erreur lors du chargement de l'historique: {e}", file=sys.stdout)
    
    def save_message(self, sender, message, timestamp):
        """Sauvegarde un message dans message.db."""
        try:
            self.msg_cursor.execute("INSERT INTO messages (sender, message, timestamp) VALUES (?, ?, ?)",
                                      (sender, message, timestamp))
            self.msg_db.commit()
        except Exception as e:
            print(f"DEBUG: Erreur lors de la sauvegarde du message: {e}", file=sys.stdout)
    
    def connect(self):
        """Se connecter au serveur"""
        pseudo = self.pseudo.get().strip()
        if not pseudo:
            messagebox.showerror("Erreur", "Veuillez entrer un pseudo.")
            return
        
        # Mettre à jour le statut
        self.status.set("Connexion en cours...")
        self.status_label.configure(style='Header.Subtitle.TLabel')
        self.connect_button.config(state=tk.DISABLED)
        
        # Créer le client en arrière-plan
        def setup_client():
            try:
                # Créer le client
                self.client = Client("auto", 9102)
                
                # Mettre à jour l'interface
                self.after(0, lambda: self.key_var.set(self.client.pubKey))
                self.after(0, self.show_chat_interface)
                
                # Configurer la redirection et les mocks
                redirect = MessageRedirect(self.chat_text, pseudo, save_message_callback=self.save_message)
                
                self.original_stdout = sys.stdout
                sys.stdout = redirect
                
                self.original_input = __builtins__.input
                __builtins__.input = self.mock_input
                
                # Démarrer le client
                self.client.start()
                
            except Exception as e:
                # En cas d'erreur, revenir à l'écran de connexion
                self.after(0, lambda: self.status.set(f"Erreur: {str(e)}"))
                self.after(0, lambda: self.status_label.configure(style='Status.TLabel'))
                self.after(0, lambda: self.connect_button.config(state=tk.NORMAL))
                self.after(0, lambda: messagebox.showerror("Erreur", f"Impossible de se connecter:\n{str(e)}"))
                
            finally:
                # Restaurer stdout et input
                sys.stdout = self.original_stdout
                __builtins__.input = self.original_input
                
                # Revenir à l'écran de connexion
                self.after(0, self.show_login_interface)
        
        # Lancer dans un thread
        threading.Thread(target=setup_client, daemon=True).start()
    
    def show_chat_interface(self):
        """Affiche l'interface de chat"""
        self.login_frame.pack_forget()
        self.chat_frame.pack(fill=tk.BOTH, expand=True)
        self.status.set("Connecté")
        self.connected = True

        # Afficher la date au centre
        current_date = datetime.now().strftime("%A %d %B %Y")
        self.chat_text.config(state=tk.NORMAL)
        self.chat_text.insert(tk.END, "\n", "system_message")
        self.chat_text.insert(tk.END, current_date + "\n", "system_message_center")
        self.chat_text.config(state=tk.DISABLED)

        # Donner le focus à l'entrée de message
        self.msg_entry.focus_set()
    
    def show_login_interface(self):
        """Revient à l'interface de connexion"""
        self.chat_frame.pack_forget()
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        self.status.set("Déconnecté")
        self.status_label.configure(style='Status.TLabel')
        self.connected = False
        self.connect_button.config(state=tk.NORMAL)
    
    def mock_input(self, prompt=""):
        """Simule la fonction input() pour le client"""
        if "pseudo" in prompt.lower():
            # Retourner le pseudo
            return self.pseudo.get().strip()
            
        elif "destinataire" in prompt.lower() or "clé" in prompt.lower():
            # Mettre un élément dans la queue pour signaler qu'on attend une clé
            #print("\nEn attente de la clé destinataire...\n")
            
            # Créer une future pour attendre la valeur
            future = queue.Queue()
            self.key_queue.put(future)
            
            # Attendre avec un timeout
            try:
                key = future.get(timeout=60)  # Attendre jusqu'à 60 secondes
                if key:
                    return key
            except queue.Empty:
                pass
                
            # Si pas de clé valide, utiliser celle de l'entrée
            entered_key = self.recipient_key.get().strip()
            if entered_key:
                return entered_key
                
            # En dernier recours
            return "temp_key"
            
        # Pour les autres prompts, retourner vide
        return ""
    
    def check_input_needed(self):
        """Vérifie régulièrement si le client attend une entrée"""
        if self.connected and hasattr(self, 'client') and self.client:
            # Vérifier si le client attend une clé
            if hasattr(self.client, 'key_requested') and self.client.key_requested:
                # Prendre la clé de l'interface et l'envoyer
                key = self.recipient_key.get().strip()
                if key:
                    # Si une future attend dans la queue
                    try:
                        future = self.key_queue.get_nowait()
                        future.put(key)
                    except queue.Empty:
                        pass
        
        # Planifier le prochain check
        self.after(100, self.check_input_needed)
    
    def copy_key(self):
        """Copie la clé publique dans le presse-papiers"""
        key = self.key_var.get()
        if key and key != "Non disponible":
            pyperclip.copy(key)
            #messagebox.showinfo("Information", "Clé publique copiée dans le presse-papiers.")
    
    def is_valid_public_key(self, key):
        """Vérifie si une clé publique est valide"""
        try:
            # Vérification de base
            if not key or len(key.strip()) == 0:
                return False
                
            # Utiliser les fonctions de validation de client si disponibles
            if hasattr(self.client, 'verify_key') and callable(self.client.verify_key):
                return self.client.verify_key(key)
            else:
                # Vérification basique si les fonctions spécifiques ne sont pas disponibles
                # Vérifier que la clé est composée uniquement de caractères hexadécimaux
                return all(c in '0123456789abcdefABCDEF' for c in key)
        except Exception as e:
            print(f"DEBUG: Erreur lors de la validation de la clé: {e}", file=self.original_stdout)
            return False
    
    def send_message(self):
        """Envoie un message"""
        if not self.connected or not hasattr(self, 'client') or not self.client:
            messagebox.showerror("Erreur", "Vous n'êtes pas connecté.")
            return
        
        message = self.message_to_send.get().strip()
        if not message:
            return
        
        # Vider le champ
        self.message_to_send.set("")
        
        # Si le client attend une clé destinataire
        if hasattr(self.client, 'key_requested') and self.client.key_requested:
            # Prendre la clé et vérifier sa validité
            key = self.recipient_key.get().strip()
            
            # Vérifier la validité de la clé
            if key and (hasattr(self.client, 'verify_key') and self.client.verify_key(key) or 
                      all(c in '0123456789abcdefABCDEF' for c in key)):
                try:
                    # Si une future attend dans la queue
                    future = self.key_queue.get_nowait()
                    future.put(key)
                except queue.Empty:
                    # Simuler une entrée utilisateur
                    print(key)
            else:
                messagebox.showerror("Erreur", "La clé publique du destinataire n'est pas valide.\nLa clé doit être au format hexadécimal.")
                # Redonner le focus à l'entrée de la clé
                for widget in self.winfo_children():
                    if isinstance(widget, ttk.Entry) and widget.winfo_parent() == str(self.chat_frame.winfo_child("!frame2")):
                        widget.focus_set()
                        break
            return
        
        # Vérifier si une clé valide est entrée avant d'envoyer le message
        key = self.recipient_key.get().strip()
        if not key or not (hasattr(self.client, 'verify_key') and self.client.verify_key(key) or 
                         all(c in '0123456789abcdefABCDEF' for c in key)):
            messagebox.showerror("Erreur", "Veuillez entrer une clé publique valide avant d'envoyer un message.")
            return
        
        # Utiliser la nouvelle méthode pour envoyer directement le message avec la clé
        if hasattr(self.client, 'message_to_send') and hasattr(self.client, 'recipient_key'):
            self.client.message_to_send = message
            self.client.recipient_key = key
        else:
            # Fallback à l'ancienne méthode
            print(message)
    
    def apply_rounded_corners(self):
        """Applique des coins arrondis aux boutons en utilisant des bordures personnalisées"""
        try:
            # Cette méthode utilise des fonctionnalités spécifiques à Windows
            # Pour les boutons avec le style 'Rounded.TButton'
            button_style = 'Rounded.TButton'
            self.style.configure(button_style, relief="flat")
            
            # Pour les boutons d'envoi
            send_style = 'Send.TButton'
            self.style.configure(send_style, relief="flat")
            
            # Appliquer des styles CSS personnalisés si possible
            for widget in self.winfo_children():
                self._apply_rounded_to_child(widget)
        except Exception as e:
            pass  # Ignorer les erreurs si la plateforme ne supporte pas cette fonctionnalité
    
    def _apply_rounded_to_child(self, widget):
        """Applique récursivement le style arrondi à tous les boutons"""
        try:
            if isinstance(widget, ttk.Button):
                if widget.cget('style') == 'Rounded.TButton' or widget.cget('style') == 'Send.TButton':
                    widget.configure(padding=(10, 8))
            
            # Appliquer récursivement aux enfants
            for child in widget.winfo_children():
                self._apply_rounded_to_child(child)
        except:
            pass

    def create_rounded_button(self, parent, text, command, width=None, height=None, bg=None, fg=None):
        """Crée un bouton avec des coins arrondis en utilisant Canvas et Frame"""
        if bg is None:
            bg = self.primary_color
        if fg is None:
            fg = 'white'
        
        # Créer un frame container pour le bouton
        btn_frame = tk.Frame(parent, bg=self.bg_color)
        
        # Créer un canvas avec des coins arrondis
        radius = 10  # Rayon des coins arrondis
        if width is None:
            width = 80
        if height is None:
            height = 30
            
        canvas = tk.Canvas(btn_frame, width=width, height=height, bg=self.bg_color, 
                            bd=0, highlightthickness=0)
        canvas.pack()
        
        # Dessiner un rectangle arrondi
        canvas.create_roundrectangle = lambda x1, y1, x2, y2, radius, **kwargs: canvas.create_polygon(
            x1 + radius, y1,
            x2 - radius, y1,
            x2, y1 + radius,
            x2, y2 - radius,
            x2 - radius, y2,
            x1 + radius, y2,
            x1, y2 - radius,
            x1, y1 + radius,
            smooth=True, **kwargs)
        
        btn_bg = canvas.create_roundrectangle(0, 0, width, height, radius, fill=bg, outline="")
        btn_text = canvas.create_text(width//2, height//2, text=text, fill=fg, font=('Segoe UI', 10, 'bold'))
        
        # Ajouter des effets hover
        def on_enter(e):
            canvas.itemconfig(btn_bg, fill=self.secondary_color)
        
        def on_leave(e):
            canvas.itemconfig(btn_bg, fill=bg)
        
        def on_click(e):
            if command:
                command()
        
        canvas.bind("<Enter>", on_enter)
        canvas.bind("<Leave>", on_leave)
        canvas.bind("<Button-1>", on_click)
        canvas.bind("<ButtonRelease-1>", lambda e: on_leave(e))
        
        return btn_frame

    def on_closing(self):
        """Avant de fermer, on ferme aussi la connexion à la bdd des messages"""
        try:
            self.msg_db.close()
        except:
            pass
        self.destroy()
        self.quitting = True	
        if platform.system() == "Windows":
            os.system("taskkill /F /PID " + str(os.getppid()))
        else:
            os.kill(os.getpid(), signal.SIGTERM)
            sys.exit(0)

if __name__ == "__main__":
    app = NexaInterface()
    app.mainloop()