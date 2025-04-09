# -*- coding: utf-8 -*-

import	tkinter	as tk
import	tkinter.ttk	as ttk
import	tkinter.simpledialog as simpledialog
import	tkinter.font as tkFont
from	ttkthemes	import ThemedTk
import	asyncio, websockets, threading, ast, uuid, requests, pyperclip, random, sys, os, platform, signal, queue

# --- Partie Client.py modifiée ---

# Garde tes fonctions et imports initiaux de client.py
from ecies import encrypt, decrypt
from ecies.utils import generate_eth_key

available_nodes = []

def get_nodes():
	url = "https://bootstrap.nexachat.tech/upNodes"
	try:
		response = requests.get(url, timeout=5) # Ajout timeout
		response.raise_for_status()
		nodes = response.json()
		return nodes
	except requests.exceptions.RequestException as e:
		print(f"Erreur lors de la récupération des nœuds: {e}")
		return []

def update_nodes_periodically(gui_queue, interval=60):
	global available_nodes
	new_nodes = get_nodes()
	if new_nodes:
		available_nodes = new_nodes
		# Optionnel: Informer l'interface de la mise à jour (si nécessaire)
		# gui_queue.put(("INFO", f"Nœuds mis à jour: {len(available_nodes)} disponibles"))
	elif not available_nodes: # Si on n'a jamais eu de noeuds et que la récupération échoue encore
		gui_queue.put(("ERROR", "Aucun nœud de bootstrap joignable."))

	# Planifier la prochaine mise à jour uniquement si on n'arrête pas
	# La gestion de l'arrêt propre du thread Timer est complexe,
	# pour cet exemple simple, on le laisse tourner.
	threading.Timer(interval, update_nodes_periodically, [gui_queue, interval]).start()


class AsyncClientLogic:
	def __init__(self, gui_queue, network_queue, host: str, port: int, pseudo: str):
		self.gui_queue = gui_queue
		self.network_queue = network_queue
		self.host = host
		self.port = port
		self.pseudo = pseudo
		self.websocket = None
		self.quitting = False
		self.loop = None
		self.receive_task = None
		self.send_task = None

		try:
			with open("privkey.key", "r") as f:
				content = f.read().strip()
				if not content:
					raise FileNotFoundError # Traité comme si le fichier était vide/absent
				lines = content.splitlines()
				if len(lines) == 2:
					self.privKey = lines[0]
					self.pubKey = lines[1]
				else:
					self.gui_queue.put(("ERROR", "Format de fichier de clés incorrect, régénération..."))
					raise FileNotFoundError # Force la régénération
		except FileNotFoundError:
			self.gui_queue.put(("INFO", "Génération de nouvelles clés..."))
			keys = generate_eth_key()
			self.privKey = keys.to_hex()
			self.pubKey = keys.public_key.to_compressed_bytes().hex()
			try:
				with open("privkey.key", "w") as f:
					f.write(self.privKey + "\n" + self.pubKey)
				self.gui_queue.put(("INFO", "Nouvelles clés sauvegardées dans privkey.key"))
			except IOError as e:
				self.gui_queue.put(("ERROR", f"Impossible de sauvegarder les clés: {e}"))
				# Gérer l'erreur critique - l'application ne peut pas fonctionner sans clés
				self.signal_quit() # Arrêter si on ne peut pas sauver les clés


		self.seen_messages = set()
		self.gui_queue.put(("PUBLIC_KEY", self.pubKey)) # Envoyer la clé publique à l'interface

	def signal_quit(self):
		self.quitting = True
		# Mettre un message spécial dans la queue pour débloquer le send_loop si besoin
		self.network_queue.put(("QUIT", ""))

	async def receive_messages(self):
		"""Gère la réception des messages en continu"""
		try:
			async for message in self.websocket:
				if self.quitting:
					break
				if not message:
					self.gui_queue.put(("INFO", "Déconnecté du serveur."))
					break

				if "register;" not in message:
					try:
						parts = message.split(';')
						sender = parts[0]
						content = parts[1]
						msg_id = parts[3] if len(parts) > 3 else None

						if msg_id and msg_id in self.seen_messages:
							continue # Ignore les messages déjà vus

						if msg_id:
							self.seen_messages.add(msg_id)
							if len(self.seen_messages) > 1000: # Limite la taille du cache
								# Retire un ancien élément (méthode simple, pas forcément le plus ancien)
								self.seen_messages.pop()

						try:
							decrypted_bytes = decrypt(self.privKey, bytes.fromhex(content))
							# Essayer de décoder en UTF-8, sinon afficher en repr()
							try:
								msg_decoded = decrypted_bytes.decode('utf-8')
								# Remplacer le caractère spécial utilisé pour l'apostrophe
								msg_display = msg_decoded.replace("¤", "'")
							except UnicodeDecodeError:
								msg_display = repr(decrypted_bytes) # Au cas où ce ne serait pas du texte

							self.gui_queue.put(("MESSAGE", (sender, msg_display)))

						except ValueError as e: # Erreur de déchiffrement probable
							if "Bad MAC" in str(e) or "Unable to decrypt" in str(e):
								# Message probablement pas pour nous ou corrompu, ignorer silencieusement ou logguer
								# print(f"DEBUG: Impossible de déchiffrer un message: {e}")
								pass
							else: # Autre erreur de valeur pendant le déchiffrement
								self.gui_queue.put(("ERROR", f"Erreur de déchiffrement: {e}"))
						except Exception as e: # Autres erreurs (parsing hex, etc.)
							self.gui_queue.put(("ERROR", f"Erreur traitement message reçu: {e} - Message: {message[:50]}..."))

					except IndexError:
						self.gui_queue.put(("WARNING", f"Message reçu mal formé: {message}"))
					except Exception as e:
						# Catch plus large pour les erreurs inattendues pendant le traitement
						self.gui_queue.put(("ERROR", f"Erreur inattendue réception: {e}"))

		except websockets.exceptions.ConnectionClosedOK:
			if not self.quitting:
				self.gui_queue.put(("INFO", "Connexion fermée proprement par le serveur."))
		except websockets.exceptions.ConnectionClosedError as e:
			if not self.quitting:
				self.gui_queue.put(("ERROR", f"Connexion perdue: {e}"))
		except asyncio.CancelledError:
			# Tâche annulée, c'est normal lors de l'arrêt
			pass
		except Exception as e:
			if not self.quitting:
				self.gui_queue.put(("ERROR", f"Erreur majeure réception: {e}"))
		finally:
			if not self.quitting:
				self.gui_queue.put(("DISCONNECTED", "")) # Signaler la déconnexion à l'UI


	async def send_loop(self):
		""" Boucle pour attendre les messages de l'interface et les envoyer """
		while not self.quitting:
			try:
				# Attendre un message de la queue venant de l'interface
				# Utiliser get() dans un thread executor pour ne pas bloquer l'event loop
				# ou utiliser une queue asyncio si possible/nécessaire.
				# Ici, on suppose que network_queue.get() est appelé depuis
				# l'event loop via run_in_executor ou une approche similaire gérée par start_client.
				# Pour simplifier ici, on va supposer que start_client gère ça.
				# **Correction:** `network_queue` est une `queue.Queue` standard, `get()` est bloquant.
				# Il faut donc l'exécuter dans un thread pour ne pas bloquer l'event loop asyncio.
				item = await self.loop.run_in_executor(None, self.network_queue.get)

				if item is None or self.quitting: # Condition d'arrêt
					self.network_queue.task_done()
					break

				command, data = item
				if command == "SEND":
					to_pubkey, message_text = data
					if not to_pubkey or not message_text:
						self.gui_queue.put(("WARNING", "Clé destinataire vide."))
						self.network_queue.task_done()
						continue

					# Remplacer l'apostrophe par le caractère spécial
					processed_msg = message_text.replace("'", "¤")

					msg_id = str(uuid.uuid4())
					try:
						msgEncrypt = encrypt(to_pubkey, processed_msg.encode('utf-8'))
						payload = f"{self.pseudo};{msgEncrypt.hex()};{to_pubkey};{msg_id}"
						await self.websocket.send(payload)
						# Confirmer l'envoi à l'interface (pour affichage côté client)
						self.gui_queue.put(("MESSAGE_SENT", (self.pseudo, message_text)))
					except websockets.exceptions.ConnectionClosed:
						self.gui_queue.put(("ERROR", "Impossible d'envoyer: Déconnecté."))
						# Remettre le message dans la queue pour réessayer ? Non, trop complexe ici.
						# Il faudrait reconnecter d'abord.
						self.signal_quit() # Arrêter si déconnecté
						break # Sortir de la boucle send
					except ValueError as e: # Souvent clé publique invalide
						if "Invalid public key" in str(e) or "public key format is invalid" in str(e):
							self.gui_queue.put(("ERROR", f"Clé publique destinataire invalide: {to_pubkey[:10]}..."))
						else:
							self.gui_queue.put(("ERROR", f"Erreur chiffrement (vérifiez clé): {e}"))
					except Exception as e:
						self.gui_queue.put(("ERROR", f"Erreur lors de l'envoi: {e}"))

				elif command == "QUIT":
					self.signal_quit()
					# Pas besoin de break ici, la condition `while not self.quitting` s'en chargera
					# ou l'annulation des tâches le fera.

				self.network_queue.task_done() # Indiquer que la tâche est terminée

			except asyncio.CancelledError:
			    # La tâche a été annulée, probablement pendant l'arrêt
				break
			except Exception as e:
				# Gérer les erreurs inattendues dans la boucle d'envoi
				if not self.quitting:
					self.gui_queue.put(("ERROR", f"Erreur critique boucle d'envoi: {e}"))
					self.signal_quit() # Arrêter en cas d'erreur grave
				break # Sortir de la boucle en cas d'erreur

	async def connect_and_run(self):
		"""Établit la connexion et lance les tâches de réception/envoi."""
		self.loop = asyncio.get_running_loop()

		host = self.host
		port = self.port

		# Logique de connexion automatique si host == 'auto'
		if host == "auto":
			global available_nodes
			if not available_nodes:
				self.gui_queue.put(("INFO", "Récupération initiale des nœuds..."))
				available_nodes = get_nodes() # Essai de récupération synchrone au démarrage

			if available_nodes:
				node = random.choice(available_nodes)
				try:
					host, port_str = node.split(":")
					port = int(port_str)
					self.gui_queue.put(("INFO", f"Connexion auto -> {host}:{port}"))
				except ValueError:
					self.gui_queue.put(("ERROR", f"Format de nœud invalide reçu: {node}"))
					self.signal_quit()
					return # Arrêter si le noeud est invalide
			else:
				self.gui_queue.put(("ERROR", "Aucun nœud disponible pour connexion auto."))
				self.signal_quit()
				return # Arrêter si aucun noeud

		uri = f"ws://{host}:{port}"
		connect_timeout = 10 # Timeout pour la connexion en secondes

		try:
			# Essayer de se connecter avec un timeout
			self.websocket = await asyncio.wait_for(websockets.connect(uri), timeout=connect_timeout)
			self.gui_queue.put(("INFO", f"Connecté à {host}:{port}"))

			# Enregistrer le client auprès du serveur
			registration_msg = f"register;client;{self.pseudo}"
			await self.websocket.send(registration_msg)
			self.gui_queue.put(("INFO", f"Enregistré comme '{self.pseudo}'"))
			self.gui_queue.put(("CONNECTED", "")) # Signaler la connexion réussie

			# Lancer les tâches de réception et d'envoi
			self.receive_task = asyncio.create_task(self.receive_messages())
			self.send_task = asyncio.create_task(self.send_loop())

			# Attendre que l'une des tâches se termine (ou soit annulée)
			# `wait` attend la fin d'au moins une des tâches fournies.
			done, pending = await asyncio.wait(
			    [self.receive_task, self.send_task],
			    return_when=asyncio.FIRST_COMPLETED,
			)

			# Si on arrive ici, c'est qu'une tâche s'est terminée (erreur, déco, etc.)
			# ou que l'arrêt a été demandé. On annule les tâches restantes.
			self.quitting = True # S'assurer que l'état est bien à quitter
			for task in pending:
				task.cancel()
			# Attendre que les tâches annulées se terminent effectivement
			if pending:
				await asyncio.wait(pending)


		except asyncio.TimeoutError:
			self.gui_queue.put(("ERROR", f"Timeout lors de la connexion à {uri}"))
		except websockets.exceptions.InvalidURI:
			self.gui_queue.put(("ERROR", f"URI invalide: {uri}"))
		except websockets.exceptions.WebSocketException as e:
			self.gui_queue.put(("ERROR", f"Erreur WebSocket connexion: {e}"))
		except OSError as e: # Peut arriver si l'adresse/port est mauvais
			self.gui_queue.put(("ERROR", f"Erreur réseau/OS connexion: {e}"))
		except Exception as e:
			self.gui_queue.put(("ERROR", f"Erreur inconnue connexion/run: {e}"))
		finally:
			if self.websocket and not self.websocket.closed:
				await self.websocket.close()
			self.gui_queue.put(("INFO", "Connexion fermée."))
			if not self.quitting:
				self.gui_queue.put(("DISCONNECTED", "")) # Signaler la déconnexion si ce n'était pas voulu


	def run_in_thread(self):
		"""Point d'entrée pour exécuter le client asyncio dans un thread séparé."""
		try:
			# Créer une nouvelle event loop pour ce thread
			asyncio.run(self.connect_and_run())
		except Exception as e:
			# Capturer toute exception non gérée qui pourrait survenir dans asyncio.run
			self.gui_queue.put(("FATAL", f"Erreur fatale dans le thread client: {e}"))
		finally:
			# S'assurer que la déconnexion est signalée même si une exception se produit
			if not self.quitting:
				self.gui_queue.put(("DISCONNECTED", ""))
			print("Thread client terminé.") # Pour le debug

# --- Fin Partie Client.py modifiée ---


# --- Interface Tkinter ---

class ChatApplication(ttk.Frame):
	def __init__(self, master, gui_queue, network_queue, pseudo, public_key):
		super().__init__(master)
		self.master = master
		self.gui_queue = gui_queue
		self.network_queue = network_queue
		self.pseudo = pseudo
		self.public_key = public_key

		self.master.title(f"Chat Client - {self.pseudo}")
		# Tente de définir une taille initiale raisonnable
		self.master.geometry("400x600")
		self.pack(fill=tk.BOTH, expand=True)
		self.bold_font = tkFont.Font(family="TkDefaultFont", size=10, weight="bold")
		self.normal_font = tkFont.Font(family="TkDefaultFont", size=10)

		# Création des widgets
		self.create_widgets()

		# Configuration des styles
		self.configure_styles()		

		# Lancer la vérification de la queue GUI
		self.master.after(100, self.process_incoming)

		# Afficher la clé publique initiale
		self.update_public_key_display(self.public_key)

	def configure_styles(self):
		style = ttk.Style()
		# Définir des polices


		# Configurer les tags pour le Text widget
		# Note: ttk n'affecte pas directement le Text widget standard,
		# mais on utilise ttk pour les autres widgets.
		# Les couleurs sont des exemples, tu peux les changer.
		self.message_area.tag_configure("pseudo_other", font=self.bold_font, foreground="#007bff") # Bleu pour les autres
		self.message_area.tag_configure("message_other", font=self.normal_font, spacing1=2, spacing3=10, lmargin1=5, lmargin2=5) # Indentation et espacement après

		self.message_area.tag_configure("pseudo_own", font=self.bold_font, foreground="#28a745", justify=tk.RIGHT) # Vert pour soi, aligné à droite
		self.message_area.tag_configure("message_own", font=self.normal_font, spacing1=2, spacing3=10, justify=tk.RIGHT, rmargin=5) # Espacement après, aligné à droite

		self.message_area.tag_configure("info", font=self.normal_font, foreground="grey", justify=tk.CENTER, spacing1=5, spacing3=5)
		self.message_area.tag_configure("error", font=self.normal_font, foreground="red", justify=tk.CENTER, spacing1=5, spacing3=5)
		self.message_area.tag_configure("warning", font=self.normal_font, foreground="orange", justify=tk.CENTER, spacing1=5, spacing3=5)

	def create_widgets(self):
		# Frame principale divisée en 3: Info Clé, Messages, Input
		self.grid_rowconfigure(1, weight=1) # La zone de message prend l'espace
		self.grid_columnconfigure(0, weight=1)

		# --- Frame Info Clé ---
		key_frame = ttk.Frame(self, padding="5 5 5 0")
		key_frame.grid(row=0, column=0, sticky="ew")
		key_frame.grid_columnconfigure(1, weight=1)

		key_label_prefix = ttk.Label(key_frame, text="Ta Clé:")
		key_label_prefix.grid(row=0, column=0, padx=(0, 5))

		self.key_label_var = tk.StringVar(value="Chargement...")
		key_label = ttk.Label(key_frame, textvariable=self.key_label_var, anchor="w", wraplength=250) # Wraplength pour éviter largeur excessive
		key_label.grid(row=0, column=1, sticky="ew")

		copy_button = ttk.Button(key_frame, text="Copier", command=self.copy_key)
		copy_button.grid(row=0, column=2, padx=(5, 0))

		# --- Frame Messages ---
		message_frame = ttk.Frame(self)
		message_frame.grid(row=1, column=0, sticky="nsew", pady=5)
		message_frame.grid_rowconfigure(0, weight=1)
		message_frame.grid_columnconfigure(0, weight=1)

		self.message_area = tk.Text(message_frame, wrap=tk.WORD, state=tk.DISABLED, height=15, padx=5, pady=5)
		# Utiliser les polices définies
		self.message_area.configure(font=self.normal_font)
		self.message_area.grid(row=0, column=0, sticky="nsew")

		scrollbar = ttk.Scrollbar(message_frame, command=self.message_area.yview)
		scrollbar.grid(row=0, column=1, sticky="ns")
		self.message_area['yscrollcommand'] = scrollbar.set

		# --- Frame Input ---
		input_frame = ttk.Frame(self, padding="5 0 5 5")
		input_frame.grid(row=2, column=0, sticky="ew")
		input_frame.grid_columnconfigure(0, weight=1) # Laisse l'entry s'étendre

		self.recipient_key_entry = ttk.Entry(input_frame, width=30)
		self.recipient_key_entry.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 3))
		self.recipient_key_entry.insert(0, "Clé publique du destinataire")
		self.recipient_key_entry.bind("<FocusIn>", self.on_entry_focus_in)
		self.recipient_key_entry.bind("<FocusOut>", self.on_entry_focus_out)
		self.recipient_key_entry.bind("<Return>", self.send_message_event) # Envoyer avec Entrée aussi

		self.message_entry = ttk.Entry(input_frame, width=50)
		self.message_entry.grid(row=1, column=0, sticky="ew", padx=(0, 5))
		self.message_entry.bind("<Return>", self.send_message_event) # Envoyer avec Entrée
		self.message_entry.insert(0, "Ton message ici...")
		self.message_entry.bind("<FocusIn>", self.on_entry_focus_in)
		self.message_entry.bind("<FocusOut>", self.on_entry_focus_out)

		send_button = ttk.Button(input_frame, text="Envoyer", command=self.send_message)
		send_button.grid(row=1, column=1)

	# --- Fonctions utilitaires pour les Entry placeholder ---
	def on_entry_focus_in(self, event):
		widget = event.widget
		placeholder_texts = ["Clé publique du destinataire", "Ton message ici..."]
		if widget.get() in placeholder_texts:
			widget.delete(0, tk.END)
			widget.config(foreground='black') # Ou la couleur de texte normale du thème

	def on_entry_focus_out(self, event):
		widget = event.widget
		if not widget.get():
			widget.config(foreground='grey')
			if widget == self.recipient_key_entry:
				widget.insert(0, "Clé publique du destinataire")
			elif widget == self.message_entry:
				widget.insert(0, "Ton message ici...")

	def update_public_key_display(self, key):
		if key:
			self.public_key = key # Mettre à jour la clé locale
			# Afficher une version tronquée pour éviter de prendre trop de place
			display_key = key[:15] + "..." + key[-15:] if len(key) > 30 else key
			self.key_label_var.set(display_key)
		else:
			self.key_label_var.set("Clé non disponible")

	def copy_key(self):
		if self.public_key:
			try:
				pyperclip.copy(self.public_key)
				self.display_info("Clé publique copiée dans le presse-papiers.")
			except Exception as e:
				self.display_error(f"Erreur copie: {e}")
		else:
			self.display_warning("Aucune clé publique à copier.")

	def send_message_event(self, event=None): # Accepte un argument event
		self.send_message()

	def send_message(self):
		recipient_key = self.recipient_key_entry.get().strip()
		message = self.message_entry.get().strip()

		if not recipient_key or recipient_key == "Clé publique du destinataire":
			self.display_warning("Entre la clé publique du destinataire.")
			return

		# Envoyer au thread client via la queue
		self.network_queue.put(("SEND", (recipient_key, message)))

		# Effacer l'entrée de message après envoi (pas la clé destinataire)
		self.message_entry.delete(0, tk.END)

		# --- Nouvelle façon de remettre le placeholder ---
		# Fonction pour vérifier et remettre le placeholder si besoin
		def reset_placeholder_if_empty(widget, placeholder_text):
			# On vérifie si le widget existe toujours (par sécurité) et s'il est vide
			if widget and not widget.get():
				try:
					widget.config(foreground='grey')
					widget.insert(0, placeholder_text)
				except tk.TclError:
					# Le widget a peut-être été détruit entre temps, on ignore l'erreur
					pass

		# Planifier l'appel à cette fonction après 50ms
		# On passe le widget et le texte en argument à la lambda pour éviter les problèmes de scope
		self.master.after(50, lambda w=self.message_entry, p="": reset_placeholder_if_empty(w, p))
		# -------------------------------------------------

	# La fonction on_entry_focus_out(self, event) reste comme elle était,
	# elle sera appelée correctement par les vrais événements FocusOut.


	def display_message(self, sender, message):
		self.message_area.config(state=tk.NORMAL)
		is_own_message = (sender == self.pseudo)

		if is_own_message:
			pseudo_tag = "pseudo_own"
			message_tag = "message_own"
			# Mettre le pseudo sur la même ligne, aligné à droite
			self.message_area.insert(tk.END, f"{message}\n", message_tag)
			# Pas besoin d'insérer le pseudo séparément si on l'intègre au style du message
		else:
			pseudo_tag = "pseudo_other"
			message_tag = "message_other"
			# Insérer le pseudo puis le message
			self.message_area.insert(tk.END, f"{sender}\n", pseudo_tag)
			self.message_area.insert(tk.END, f"{message}\n", message_tag)

		# Ajoute un saut de ligne supplémentaire pour l'espacement visuel entre blocs
		# self.message_area.insert(tk.END, "\n") # Peut-être trop d'espace, ajuster via spacing3

		self.message_area.config(state=tk.DISABLED)
		self.message_area.see(tk.END) # Auto-scroll

	def display_info(self, message):
		self.message_area.config(state=tk.NORMAL)
		self.message_area.insert(tk.END, f"{message}\n", "info")
		self.message_area.config(state=tk.DISABLED)
		self.message_area.see(tk.END)

	def display_warning(self, message):
		self.message_area.config(state=tk.NORMAL)
		self.message_area.insert(tk.END, f"{message}\n", "warning")
		self.message_area.config(state=tk.DISABLED)
		self.message_area.see(tk.END)

	def display_error(self, message):
		self.message_area.config(state=tk.NORMAL)
		self.message_area.insert(tk.END, f"{message}\n", "error")
		self.message_area.config(state=tk.DISABLED)
		self.message_area.see(tk.END)

	def process_incoming(self):
		""" Vérifie la queue pour les messages du thread client """
		while True: # Traiter tous les messages dans la queue
			try:
				msg = self.gui_queue.get_nowait()
				command, data = msg

				if command == "MESSAGE":
					sender, message_text = data
					self.display_message(sender, message_text)
				elif command == "MESSAGE_SENT": # Afficher son propre message quand envoyé
					sender, message_text = data
					self.display_message(sender, message_text)
				elif command == "INFO":
					self.display_info(data)
				elif command == "WARNING":
					self.display_warning(data)
				elif command == "ERROR":
					self.display_error(data)
				elif command == "FATAL":
					self.display_error(f"ERREUR FATALE: {data}")
				    # On pourrait fermer l'app ici ou désactiver les inputs
					self.message_entry.config(state=tk.DISABLED)
					self.recipient_key_entry.config(state=tk.DISABLED)
				elif command == "PUBLIC_KEY":
					self.update_public_key_display(data)
				elif command == "CONNECTED":
					self.display_info("--- Connecté ---")
				    # Activer les entrées si elles étaient désactivées
					self.recipient_key_entry.config(state=tk.NORMAL)
					self.message_entry.config(state=tk.NORMAL)
				elif command == "DISCONNECTED":
					self.display_error("--- Déconnecté ---")
				    # Désactiver les entrées pour éviter l'envoi
					self.message_entry.config(state=tk.DISABLED)
					self.recipient_key_entry.config(state=tk.DISABLED)
				    # On pourrait ajouter un bouton "Reconnecter" ici

			except queue.Empty: # Si la queue est vide, on arrête de vérifier pour ce cycle
				break
			except Exception as e: # Attrape d'autres erreurs potentielles
				print(f"Erreur traitement queue GUI: {e}")

		# Planifier la prochaine vérification
		self.master.after(100, self.process_incoming)

	def on_closing(self):
		print("Fermeture demandée...")
		# Envoyer un signal d'arrêt au thread client
		self.network_queue.put(("QUIT", ""))
		# Donner un peu de temps au thread pour s'arrêter (optionnel)
		# On pourrait attendre que le thread se termine réellement ici si besoin
		self.master.destroy()
		# Forcer l'arrêt si le thread ne se termine pas (brutal)
		# os._exit(0) # À éviter si possible


# --- Fonction principale ---
def main():
	# Initialiser les queues pour la communication inter-threads
	gui_queue = queue.Queue()
	network_queue = queue.Queue()

	# Lancer la mise à jour périodique des nœuds en arrière-plan
	# Le thread Timer est daemon par défaut, il ne bloquera pas la sortie
	# Mais il faut le gérer proprement à la fermeture idéalement.
	update_nodes_periodically(gui_queue) # Lance la 1ere récup et planifie les suivantes

	# Configuration initiale Tkinter pour la boîte de dialogue du pseudo
	root_for_dialog = tk.Tk()
	root_for_dialog.withdraw() # Cacher la fenêtre Tkinter vide initiale

	pseudo = ""
	while not pseudo:
		pseudo = simpledialog.askstring("Pseudo", "Entre ton pseudo, champion:", parent=root_for_dialog)
		if pseudo is None: # Si l'utilisateur annule ou ferme la boîte
			print("Annulé par l'utilisateur. Bye.")
			return # Quitter l'application
		if not pseudo.strip():
			tk.messagebox.showwarning("Pseudo Requis", "Eh oh, le pseudo ne peut pas être vide!")
			pseudo = "" # Redemander

	root_for_dialog.destroy() # Fermer la fenêtre Tkinter temporaire

	# --- Initialisation du client logique (partie non-async) ---
	# Crée une instance pour récupérer la clé publique AVANT de lancer le thread async
	# C'est un peu moche mais évite de devoir attendre le thread pour avoir la clé
	try:
		temp_client = AsyncClientLogic(gui_queue, network_queue, "auto", 9102, pseudo)
		public_key = temp_client.pubKey
	    # Nettoyer cette instance temporaire si elle n'est pas nécessaire ensuite
	    # Ou mieux : passer cette instance au thread pour qu'il l'utilise.
	    # Ici, on va recréer l'instance dans le thread, donc on garde juste la clé.
	except Exception as e:
	    # Gérer le cas où même l'init échoue (ex: impossible de sauver la clé)
		tk.messagebox.showerror("Erreur Initiale", f"Impossible d'initialiser le client: {e}")
		return # Quitter si l'initialisation de base échoue


	# --- Création de la fenêtre principale avec le thème ---
	# Utiliser ThemedTk pour les thèmes ttk
	root = ThemedTk(theme="equilux") # Essaye "arc", "plastik", "adapta", etc.
	if not root.get_themes():
		print("ttkthemes non installé ou aucun thème trouvé. Utilisation du thème par défaut.")
		root = tk.Tk() # Revenir à Tk standard si pas de thèmes


	app = ChatApplication(root, gui_queue, network_queue, pseudo, public_key)
	root.protocol("WM_DELETE_WINDOW", app.on_closing) # Gérer la fermeture de la fenêtre


	# --- Démarrage du thread client ---
	# On recrée l'instance ici pour la passer au thread
	client_logic = AsyncClientLogic(gui_queue, network_queue, "auto", 9102, pseudo)

	client_thread = threading.Thread(target=client_logic.run_in_thread, daemon=True)
	client_thread.start()

	# Lancer la boucle principale de Tkinter
	try:
		root.mainloop()
	except KeyboardInterrupt:
	    # Gérer Ctrl+C dans le terminal (peut ne pas toujours marcher avec Tkinter)
	    app.on_closing()

if __name__ == "__main__":
	# Vérifier si pyperclip est disponible
	try:
		import pyperclip
	except ImportError:
		print("Le module 'pyperclip' est manquant. La fonction 'Copier' ne marchera pas.")
		print("Installe-le avec: pip install pyperclip")
	    # On pourrait choisir de quitter ou de continuer sans la fonction copier

	main()