import threading, sys, pyperclip, time, queue, clientUI
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, StringVar
from clientUI import Client, async_getnodes
from datetime import datetime

class MessageRedirect:
	def __init__(self, text_widget, pseudo):
		self.text_widget = text_widget
		self.pseudo = pseudo
		self.queue = queue.Queue()
		self.original_stdout = sys.stdout
		self.updating = True
		threading.Thread(target=self.update_loop, daemon=True).start()

	def write(self, string):
		if "Erreur lors de la recherche des nœuds" in string or ("Erreur:" in string and "nœud" in string.lower()):
			print("DEBUG:", string, file=self.original_stdout)
		else:
			self.queue.put(string)

	def flush(self): pass

	def update_loop(self):
		"""Boucle de mise à jour du widget de texte avec formatage amélioré"""
		last_date = None
		while self.updating:
			try:
				while True:
					string = self.queue.get_nowait()
					self.text_widget.config(state=tk.NORMAL)

					# Obtenir la date actuelle
					current_date = datetime.now().strftime("%d %m %Y")
					if current_date != last_date:
						self.text_widget.insert(tk.END, f"\n{current_date}\n", "system_message")
						last_date = current_date

					if ": " in string and not any(string.startswith(x) for x in ("===", "Ta clé", "Connexion")):
						sender, message = string.split(": ", 1)
						time_str = datetime.now().strftime("%H:%M")

						if sender.strip() == self.pseudo.strip():
							self.text_widget.insert(tk.END, f"Vous {time_str}\n", "sender_name")
							self.text_widget.insert(tk.END, f"{' ' * 50}{message.strip()}\n", "message_sent")
						else:
							self.text_widget.insert(tk.END, f"{sender} {time_str}\n", "sender_name")
							self.text_widget.insert(tk.END, f"{message.strip()}\n", "message_received")

					else:
						self.text_widget.insert(tk.END, string)

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
		self.geometry("490x700")				# Taille de la fenêtre
		self.minsize(490, 600)
		
		# Centrer la fenêtre sur l'écran
		self.center_window()
		
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
		
		# Créer l'interface
		self.create_widgets()
		
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
		
		clientUI.node_detection_callback = update_nodes
		
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
									background="#E6F9E6",  # Vert clair
									foreground="black",
									font=('Segoe UI', 11),
									spacing1=6,
									spacing2=4,
									spacing3=6,
									justify='right',  # Alignement à droite pour les messages envoyés
									lmargin1=5,  # Marge à gauche réduite à 5
									lmargin2=5)  # Marge à gauche réduite à 5
		
		self.chat_text.tag_configure("message_received", 
									background="#F1F0FE",  # Violet très clair
									foreground="black",
									font=('Segoe UI', 11),
									spacing1=6,
									spacing2=4,
									spacing3=6,
									justify='left',  # Alignement à gauche pour les messages reçus
									lmargin1=5,  # Marge à gauche de 5
									lmargin2=5)  # Marge à gauche de 5
		
		self.chat_text.tag_configure("sender_name", 
									foreground=self.primary_color,
									font=('Segoe UI', 10, 'bold'),
									justify='left',
									lmargin1=5,  # Marge à gauche
									lmargin2=5)  # Marge à gauche pour les lignes suivantes
		
		self.chat_text.tag_configure("system_message", 
									foreground="#757575",
									font=('Segoe UI', 9),
									justify='left',
									lmargin1=5,  # Marge à gauche
									lmargin2=5)  # Marge à gauche pour les lignes suivantes
		
		self.chat_text.tag_configure("system_success", 
									foreground=self.accent_color,
									font=('Segoe UI', 9, 'bold'),
									justify='left',
									lmargin1=5,  # Marge à gauche
									lmargin2=5)  # Marge à gauche pour les lignes suivantes
		
		self.chat_text.tag_configure("system_error", 
									foreground=self.error_color,
									font=('Segoe UI', 9),
									justify='left',
									lmargin1=5,  # Marge à gauche
									lmargin2=5)  # Marge à gauche pour les lignes suivantes
		
		self.chat_text.tag_configure("system_prompt", 
									foreground=self.secondary_color,
									font=('Segoe UI', 9, 'bold'),
									justify='left',
									lmargin1=5,  # Marge à gauche
									lmargin2=5)  # Marge à gauche pour les lignes suivantes
		
		self.chat_text.tag_configure("time_left", 
									foreground="#9E9E9E",
									font=('Segoe UI', 8),
									justify='left',
									lmargin1=5,  # Marge à gauche
									lmargin2=5)  # Marge à gauche pour les lignes suivantes
		
		self.chat_text.tag_configure("time_right", 
									foreground="#9E9E9E",
									font=('Segoe UI', 8),
									justify='right',
									lmargin1=5,  # Marge à gauche
									lmargin2=5)  # Marge à gauche pour les lignes suivantes
		
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
				redirect = MessageRedirect(self.chat_text, pseudo)
				
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
		#self.status_label.configure(style='Connected.Status.TLabel')
		self.connected = True
		
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
			print("\nEn attente de la clé destinataire...\n")
			
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
		"""Vérifie si une clé publique est valide en utilisant clientUI"""
		try:
			# Vérification de base
			if not key or len(key.strip()) == 0:
				return False
				
			# Utiliser les fonctions de validation de clientUI si disponibles
			if hasattr(clientUI, 'verify_key') and callable(clientUI.verify_key):
				return clientUI.verify_key(key)
			elif hasattr(self.client, 'verify_key') and callable(self.client.verify_key):
				return self.client.verify_key(key)
			else:
				# Vérification basique si les fonctions spécifiques ne sont pas disponibles
				return key.startswith('pk:') and len(key) >= 10
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
			if self.is_valid_public_key(key):
				try:
					# Si une future attend dans la queue
					future = self.key_queue.get_nowait()
					future.put(key)
				except queue.Empty:
					# Simuler une entrée utilisateur
					print(key)
			else:
				messagebox.showerror("Erreur", "La clé publique du destinataire n'est pas valide.\nLa clé doit commencer par 'pk:' et avoir un format correct.")
				# Redonner le focus à l'entrée de la clé
				for widget in self.winfo_children():
					if isinstance(widget, ttk.Entry) and widget.winfo_parent() == str(self.chat_frame.winfo_child("!frame2")):
						widget.focus_set()
						break
			return
		
		# Vérifier si une clé valide est entrée avant d'envoyer le message
		key = self.recipient_key.get().strip()
		if not self.is_valid_public_key(key):
			messagebox.showerror("Erreur", "Veuillez entrer une clé publique valide avant d'envoyer un message.")
			return
		
		# Sinon, envoyer comme message normal
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

if __name__ == "__main__":
	app = NexaInterface()
	app.mainloop()