import asyncio
import websockets
import threading
import time
import uuid
import json
import requests # Ajouté pour les requêtes HTTP
from concurrent.futures import ThreadPoolExecutor # Ajouté pour exécuter requests en non-bloquant
from http.server import BaseHTTPRequestHandler, HTTPServer
from collections import deque
import sqlite3

class Node:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.client_connections = set()
        self.node_connections = set()
        # La liste initiale peut être vide ou contenir des nœuds connus au départ
        self.nodeIpPort_list = []
        self.lock = threading.Lock()
        # Cache des messages déjà traités (limité à 1000 entrées)
        self.message_cache = deque(maxlen=1000)
        # TTL par défaut pour les messages
        self.DEFAULT_TTL = 5
        # Event loop pour les opérations asynchrones
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        # Executor pour les tâches bloquantes (comme requests)
        self.executor = ThreadPoolExecutor(max_workers=2)
        # URL du serveur bootstrap (corrigé en HTTPS)
        self.bootstrap_url = "https://bootstrap.nexachat.tech/upNodes" # <- Corrigé ici
        self.client_pubkey = {}
        self.db_co = sqlite3.connect(f"node_{self.port}_messages.db", check_same_thread=False)
        self._init_db()


    def _init_db(self):
        with self.db_co:
            self.db_co.execute('''
                CREATE TABLE IF NOT EXISTS pending_messages (
                    id TEXT PRIMARY KEY,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    encrypted_message TEXT NOT NULL,
                    expiration_time TEXT
                )
            ''')

    # --- (Le reste des méthodes handle_client, send_to_clients, send_to_nodes reste pareil) ---
    async def handle_client(self, websocket):
        remote_address = websocket.remote_address
        print(f"Nouvelle connexion de {remote_address}")

        try:
            async for message in websocket:
                # print(f"Reçu: {message} par {remote_address[0]}") # Peut être trop verbeux

                # Traitement des messages de contrôle
                if "register;client;" in message:
                    parts = message.split(';')
                    if len(parts) >= 4:
                        pseudo = parts[2]
                        pubkey = parts[3]
                        with self.lock:
                            self.client_connections.add(websocket)
                            self.client_pubkey[pubkey] = websocket
                            print(f"Client {remote_address} enregistré avec pseudo '{pseudo}' et pubkey {pubkey[:10]}...")
                            print(self.client_pubkey)
                    else:
                        print(f"Format de registre client invalide reçu: {message}")


                elif "register;node;" in message:
                    # Enregistrement d'un nouveau nœud via connexion directe
                    parts = message.split(';')
                    if len(parts) >= 4:
                        node_ip = parts[2]
                        node_port_str = parts[3]
                        try:
                            node_port = int(node_port_str)
                            # Utiliser l'IP de la connexion si l'IP fournie est 0.0.0.0 ou locale
                            if node_ip == "0.0.0.0" or node_ip == "127.0.0.1":
                               node_ip = remote_address[0] # Utiliser l'IP vue par le serveur

                            node_tuple = (node_ip, node_port)
                            print(f"Tentative d'enregistrement du noeud: {node_tuple}")

                            with self.lock:
                                # Vérifier si ce noeud (IP, port) est déjà connu
                                is_known = any(n[0] == node_ip and n[1] == node_port for n in self.nodeIpPort_list)

                                # Vérifier si la connexion websocket existe déjà pour ce noeud
                                is_connected_ws = websocket in self.node_connections

                                if not is_known:
                                    print(f"Nouveau noeud ajouté à la liste : {node_tuple}")
                                    self.nodeIpPort_list.append([node_ip, node_port, 1]) # Marquer comme connecté (état initial)
                                    if not is_connected_ws:
                                         self.node_connections.add(websocket)
                                else:
                                    # Si le noeud est connu mais la connexion websocket est nouvelle
                                    # ou si on veut juste confirmer la connexion
                                    # print(f"Noeud {node_tuple} déjà connu. Mise à jour état/connexion.") # Moins verbeux
                                    # Mettre à jour l'état si nécessaire
                                    for node_info in self.nodeIpPort_list:
                                        if node_info[0] == node_ip and node_info[1] == node_port:
                                            node_info[2] = 1 # Marquer comme connecté
                                            break
                                    if not is_connected_ws:
                                        self.node_connections.add(websocket)
                        except ValueError:
                             print(f"Erreur: Port invalide reçu lors de l'enregistrement du noeud: {node_port_str}")


                # Traitement des messages ordinaires (non-contrôle)
                elif message != "register;":
                    parts = message.split(';')

                    # Si le format est ancien (sans ID et TTL), ajoutons-les
                    if len(parts) <= 4:
                        # Créer un ID unique
                        msg_id = str(uuid.uuid4())
                        # Ajouter un TTL par défaut
                        # S'assurer qu'il y a assez de parties pour l'ancien format
                        if len(parts) >= 3:
                            message = f"{parts[0]};{parts[1]};{parts[2]};{msg_id};{self.DEFAULT_TTL}"
                            parts = message.split(';')
                        else:
                            print(f"Message ancien format invalide ignoré: {message}")
                            continue # Ignorer ce message

                    # Vérifier si le format est correct après ajout potentiel de ID/TTL
                    if len(parts) == 5:
                        sender, content, recipient, msg_id, ttl_str = parts
                        try:
                            ttl = int(ttl_str)

                            # Vérifier si nous avons déjà traité ce message
                            if msg_id in self.message_cache:
                                # print(f"Message {msg_id} déjà traité, ignoré.")
                                continue  # Ignorer les messages déjà traités

                            # Ajouter ce message à notre cache
                            self.message_cache.append(msg_id)

                            # Décrémenter le TTL
                            ttl -= 1

                            # Si le TTL est positif, on continue la propagation
                            if ttl > 0:
                                # Nouveau message avec TTL décrémenté
                                next_message = f"{sender};{content};{recipient};{msg_id};{ttl}"

                                # Envoi aux clients locaux (sauf l'expéditeur si c'est un client)
                                await self.send_to_clients(next_message, websocket if websocket in self.client_connections else None)

                                # Envoi aux autres nœuds (sauf l'expéditeur si c'est un noeud)
                                await self.send_to_nodes(next_message, websocket if websocket in self.node_connections else None)
                            # else:
                                # print(f"TTL épuisé pour le message {msg_id}")

                        except ValueError:
                            print(f"Erreur: TTL invalide dans le message '{message}'")
                        except Exception as e:
                            print(f"Erreur inattendue lors du traitement du message: {e}")
                    else:
                        # Ne pas printer tous les messages invalides, peut être bruyant
                        # print(f"Message au format invalide ignoré: {message}")
                        pass


                if 'quit' in message.lower():
                    print(f"Client {remote_address} a demandé à quitter.")
                    break

        except websockets.exceptions.ConnectionClosed as e:
            # Log plus concis pour les fermetures normales
            if e.code != 1000 and e.code != 1001 : # 1000 = Normal Closure, 1001 = Going Away
                 print(f"Connexion fermée anormalement avec {remote_address} - Raison: {e.reason} (code: {e.code})")
            # else:
                 # print(f"Connexion fermée normalement avec {remote_address}") # Optionnel
        except Exception as e:
            print(f"Erreur inattendue avec {remote_address}: {e}")
        finally:
            # print(f"Nettoyage de la connexion pour {remote_address}") # Moins verbeux
            with self.lock:
                removed_client = websocket in self.client_connections
                removed_node = websocket in self.node_connections
                if removed_client:
                    self.client_connections.remove(websocket)
                    # print(f"Client {remote_address} retiré des connexions clientes.")
                if removed_node:
                    self.node_connections.remove(websocket)
                    # print(f"Noeud {remote_address} retiré des connexions noeuds.")
                    # Marquer le noeud comme déconnecté dans nodeIpPort_list
                    try:
                        node_ip = remote_address[0]
                        node_port = remote_address[1]
                        for node_info in self.nodeIpPort_list:
                            if node_info[0] == node_ip and node_info[1] == node_port:
                                node_info[2] = 0 # Marquer comme déconnecté
                                # print(f"Noeud {node_info[0]}:{node_info[1]} marqué comme déconnecté suite à la fermeture.")
                                break
                    except Exception as e:
                         print(f"Erreur lors du marquage du noeud comme déconnecté: {e}")


    async def send_to_clients(self, message, sender_ws=None):
        """Envoie un message à tous les clients connectés sauf l'expéditeur"""
        if not self.client_connections:
            return # Rien à faire si pas de clients

        # Crée une copie pour itérer car le set peut être modifié pendant l'itération
        clients_copy = list(self.client_connections)
        closed_clients = set()

        for client in clients_copy:
            if client == sender_ws:
                continue # Ne pas renvoyer à l'expéditeur

            try:
                # print(f"Envoi à client {client.remote_address}: {message[:60]}...") # Log tronqué
                await client.send(message)
            except websockets.exceptions.ConnectionClosed:
                # print(f"Client {client.remote_address} déconnecté pendant l'envoi.") # Moins verbeux
                closed_clients.add(client)
            except Exception as e:
                print(f"Erreur envoi vers client {client.remote_address}: {e}")
                closed_clients.add(client) # Supposer déconnecté en cas d'erreur

        # Supprimer les clients déconnectés (si nécessaire)
        if closed_clients:
            with self.lock:
                self.client_connections.difference_update(closed_clients)
                # print(f"{len(closed_clients)} clients déconnectés retirés.")


    async def send_to_nodes(self, message, sender_ws=None):
        """Envoie un message à tous les nœuds connectés sauf l'expéditeur"""
        if not self.node_connections:
            return # Rien à faire si pas de noeuds connectés

        # Crée une copie pour itérer
        nodes_copy = list(self.node_connections)
        closed_nodes = set()

        for node_ws in nodes_copy:
             # Ne pas renvoyer au noeud qui a envoyé le message initialement
            if node_ws == sender_ws:
                continue

            try:
                # print(f"Envoi à noeud {node_ws.remote_address}: {message[:60]}...") # Log tronqué
                await node_ws.send(message)
            except websockets.exceptions.ConnectionClosed:
                remote_addr = node_ws.remote_address
                # print(f"Noeud {remote_addr} déconnecté pendant l'envoi.") # Moins verbeux
                closed_nodes.add(node_ws)
                # Marquer comme déconnecté dans la liste principale
                with self.lock:
                    for node_info in self.nodeIpPort_list:
                        # Comparer IP et Port pour être sûr
                        if remote_addr and node_info[0] == remote_addr[0] and node_info[1] == remote_addr[1]:
                            node_info[2] = 0
                            # print(f"Noeud {remote_addr} marqué déconnecté dans la liste.")
                            break
            except Exception as e:
                remote_addr = node_ws.remote_address
                print(f"Erreur envoi vers noeud {remote_addr}: {e}")
                closed_nodes.add(node_ws) # Supposer déconnecté
                 # Marquer comme déconnecté dans la liste principale
                with self.lock:
                    for node_info in self.nodeIpPort_list:
                        if remote_addr and node_info[0] == remote_addr[0] and node_info[1] == remote_addr[1]:
                            node_info[2] = 0
                            # print(f"Noeud {remote_addr} marqué déconnecté dans la liste (erreur envoi).")
                            break

        # Supprimer les nœuds déconnectés du set de connexions actives
        if closed_nodes:
            with self.lock:
                self.node_connections.difference_update(closed_nodes)
                # print(f"{len(closed_nodes)} noeuds déconnectés retirés des connexions actives.")


    async def connect_to_node(self, ip, port):
        """Établit une connexion WebSocket sortante avec un autre nœud"""
        # Éviter de se connecter à soi-même
        if (ip == self.host or ip == '127.0.0.1' or ip == 'localhost') and port == self.port:
             return

        # Vérifier si une connexion active existe déjà vers ce noeud
        with self.lock:
             already_connected = any(
                 node_ws.remote_address and node_ws.remote_address[0] == ip and node_ws.remote_address[1] == port
                 for node_ws in self.node_connections
             )
             if already_connected:
                 # S'assurer que l'état dans nodeIpPort_list est correct (marqué comme connecté)
                 for node_info in self.nodeIpPort_list:
                     if node_info[0] == ip and node_info[1] == port:
                         if node_info[2] == 0:
                             node_info[2] = 1
                         break
                 return


        uri = f"ws://{ip}:{port}"
        websocket = None
        try:
            # print(f"Tentative de connexion sortante vers {uri}")
            websocket = await asyncio.wait_for(websockets.connect(uri), timeout=5.0)
            print(f"Connecté avec succès à {uri}")

            # S'enregistrer auprès de l'autre nœud
            # Envoyer 0.0.0.0:port, l'autre noeud utilisera l'IP de la connexion
            await websocket.send(f"register;node;0.0.0.0;{self.port}")

            with self.lock:
                # Ajouter la nouvelle connexion au set des connexions actives
                self.node_connections.add(websocket)
                # Mettre à jour l'état dans la liste principale ou ajouter si absent
                found = False
                for node_info in self.nodeIpPort_list:
                    if node_info[0] == ip and node_info[1] == port:
                        node_info[2] = 1  # Marquer comme connecté
                        found = True
                        break
                if not found:
                    # Si le noeud n'était pas dans la liste (ex: bootstrap l'a ajouté)
                    self.nodeIpPort_list.append([ip, port, 1])
                    print(f"Noeud {ip}:{port} ajouté à la liste suite à connexion réussie.")


            # Lancer une tâche séparée pour écouter ce websocket spécifique
            # Si on ne fait pas ça, la fonction connect_to_node se termine
            # et la boucle async for message in websocket n'est jamais atteinte
            # pour les connexions sortantes réussies.
            asyncio.create_task(self.listen_to_node(websocket, ip, port))


        except (websockets.exceptions.ConnectionClosed, websockets.exceptions.InvalidURI, websockets.exceptions.InvalidHandshake, OSError, asyncio.TimeoutError) as e:
            # print(f"Erreur de connexion sortante vers {ip}:{port}: {type(e).__name__} - {e}") # Moins verbeux
            # Marquer le nœud comme déconnecté dans la liste
            with self.lock:
                for node_info in self.nodeIpPort_list:
                    if node_info[0] == ip and node_info[1] == port:
                        if node_info[2] == 1: # Seulement si on le pensait connecté
                            node_info[2] = 0
                            # print(f"Noeud {ip}:{port} marqué déconnecté suite à échec/fermeture connexion sortante.")
                        break
                # S'assurer que le websocket (s'il a été créé et ajouté) est retiré
                if websocket in self.node_connections:
                    self.node_connections.remove(websocket)
        except Exception as e:
             print(f"Erreur inattendue lors de la connexion sortante vers {ip}:{port}: {e}")
             # Gérer comme une déconnexion
             with self.lock:
                for node_info in self.nodeIpPort_list:
                    if node_info[0] == ip and node_info[1] == port:
                         node_info[2] = 0
                         break
                if websocket and websocket in self.node_connections:
                    self.node_connections.remove(websocket)


    async def listen_to_node(self, websocket, ip, port):
        """Écoute en continu les messages d'un nœud auquel on s'est connecté."""
        try:
            async for message in websocket:
                # print(f"Message reçu de {ip}:{port} (connexion sortante): {message[:60]}...")
                await self.process_incoming_message(message, websocket)
        except websockets.exceptions.ConnectionClosed as e:
             # print(f"Connexion sortante vers {ip}:{port} fermée.") # Moins verbeux
             pass # L'erreur est déjà gérée dans connect_to_node ou via la boucle principale
        except Exception as e:
            print(f"Erreur écoute sur connexion sortante {ip}:{port}: {e}")
        finally:
            # Assurer le nettoyage si la tâche se termine pour une raison quelconque
            with self.lock:
                if websocket in self.node_connections:
                    self.node_connections.remove(websocket)
                # Marquer comme déconnecté
                for node_info in self.nodeIpPort_list:
                    if node_info[0] == ip and node_info[1] == port:
                        node_info[2] = 0
                        break


    async def process_incoming_message(self, message, websocket):
        """Traite un message reçu (depuis connexion sortante ou entrante)"""
        # print(f"Traitement message entrant: {message[:60]}...")
        try:
            parts = message.split(';')

            # Ignorer les messages d'enregistrement ici car la connexion est déjà établie
            if message.startswith("register;"):
                return

            # Assurer le format ID/TTL
            if len(parts) <= 4:
                msg_id = str(uuid.uuid4())
                if len(parts) >= 3:
                    message = f"{parts[0]};{parts[1]};{parts[2]};{msg_id};{self.DEFAULT_TTL}"
                    parts = message.split(';')
                else:
                    # print(f"Message ancien format invalide ignoré (process_incoming): {message}")
                    return

            if len(parts) == 5:
                sender, content, recipient, msg_id, ttl_str = parts
                try:
                    ttl = int(ttl_str)

                    if msg_id in self.message_cache:
                        # print(f"Message {msg_id} déjà traité (process_incoming), ignoré.")
                        return

                    self.message_cache.append(msg_id)
                    ttl -= 1

                    if ttl > 0:
                        next_message = f"{sender};{content};{recipient};{msg_id};{ttl}"

                        # Envoi direct
                        recipient_ws = self.client_pubkey.get(recipient)
                        if recipient_ws and recipient_ws in self.client_connections:
                            await recipient_ws.send(next_message)
                        else:
                            # Sinon, propager aux autres noeuds
                            await self.send_to_nodes(next_message, websocket if websocket in self.node_connections else None)

                except ValueError:
                    print(f"Erreur: TTL invalide dans le message '{message}' (process_incoming)")
                except Exception as e:
                    print(f"Erreur traitement message (process_incoming): {e}")
            # else:
                # print(f"Message format invalide ignoré (process_incoming): {message}")

        except Exception as e:
            print(f"Erreur majeure dans process_incoming_message: {e}")


    def _fetch_up_nodes_sync(self):
        """Fonction synchrone pour récupérer les nœuds depuis le bootstrap."""
        try:
            # Utilisation de verify=False peut être nécessaire si le certif SSL pose problème, mais c'est moins sécurisé
            # response = requests.get(self.bootstrap_url, timeout=10, verify=False)
            response = requests.get(self.bootstrap_url, timeout=10) # Timeout de 10s
            response.raise_for_status()  # Lève une exception pour les codes d'erreur HTTP
            # La réponse est maintenant supposée être une liste de strings "ip:port"
            nodes_data = response.json() # Attend une réponse JSON contenant une liste de strings
            print(f"Liste brute reçue du bootstrap: {len(nodes_data)} entrées")
            return nodes_data
        except requests.exceptions.RequestException as e:
            print(f"Erreur lors de la récupération des nœuds depuis {self.bootstrap_url}: {e}")
        except json.JSONDecodeError as e:
            print(f"Erreur de décodage JSON depuis {self.bootstrap_url} (réponse non JSON?): {e}")
            # Essayer de lire comme texte brut si le JSON échoue?
            try:
                # Re-faire la requête ou utiliser response.text si disponible
                response_text = requests.get(self.bootstrap_url, timeout=10).text
                # Supposer une ligne par noeud? Ou séparé par des espaces? A adapter selon le format réel
                nodes_data = response_text.strip().splitlines() # Exemple si une ligne par noeud
                print(f"Liste brute (texte) reçue du bootstrap: {len(nodes_data)} lignes")
                return nodes_data
            except Exception as e_text:
                 print(f"Impossible de lire la réponse comme texte brut non plus: {e_text}")

        except Exception as e:
            print(f"Erreur inattendue lors du fetch bootstrap: {e}")
        return None # Retourne None en cas d'erreur


    async def update_node_list_from_bootstrap(self):
        """Met à jour la liste des nœuds en appelant le serveur bootstrap."""
        print("Tentative de mise à jour de la liste des nœuds depuis le bootstrap...")
        nodes_data = await self.loop.run_in_executor(self.executor, self._fetch_up_nodes_sync)

        if nodes_data is not None and isinstance(nodes_data, list): # S'assurer que c'est une liste
            with self.lock:
                existing_nodes = set((n[0], n[1]) for n in self.nodeIpPort_list)
                nodes_added = 0
                # Traiter chaque entrée de la liste (maintenant supposée être une string "ip:port")
                for node_entry_str in nodes_data:
                    if not isinstance(node_entry_str, str):
                        print(f"Entrée de noeud ignorée (pas une string): {node_entry_str}")
                        continue

                    try:
                        # Séparer l'IP et le port
                        parts = node_entry_str.split(':')
                        if len(parts) == 2:
                            ip = parts[0].strip()
                            port_str = parts[1].strip()
                            port = int(port_str) # Essayer de convertir le port en entier

                            # Vérifier que l'IP et le port sont valides (simple vérification)
                            if ip and port > 0 and port < 65536:
                                # Éviter d'ajouter soi-même
                                if (ip == self.host or ip == '127.0.0.1') and port == self.port:
                                    continue

                                if (ip, port) not in existing_nodes:
                                    self.nodeIpPort_list.append([ip, port, 0]) # Ajouter avec état déconnecté (0)
                                    existing_nodes.add((ip, port))
                                    nodes_added += 1
                            else:
                                print(f"IP/Port invalide après split: {ip}:{port}")
                        else:
                            print(f"Format d'entrée de noeud invalide (pas 'ip:port'): {node_entry_str}")

                    except ValueError:
                        print(f"Port invalide (pas un nombre) dans l'entrée: {node_entry_str}")
                    except Exception as e:
                         print(f"Erreur traitement entrée noeud bootstrap '{node_entry_str}': {e}")

                if nodes_added > 0:
                    print(f"{nodes_added} nouveaux nœuds ajoutés depuis le bootstrap.")
                # print("Liste de nœuds après mise à jour:", self.nodeIpPort_list) # Peut être trop verbeux
        else:
            print("Aucune donnée de nœud valide reçue ou erreur lors du fetch.")


    async def connect_nodes_list(self):
        """Met à jour la liste depuis bootstrap et essaie de se connecter aux nœuds non connectés"""
        await asyncio.sleep(5) # Attendre un peu avant la première tentative

        while True:
            # 1. Mettre à jour la liste des nœuds depuis le serveur bootstrap
            await self.update_node_list_from_bootstrap()

            # 2. Tenter de se connecter aux nœuds marqués comme déconnectés (état 0)
            nodes_to_connect = []
            with self.lock:
                nodes_to_connect = [(node[0], node[1]) for node in self.nodeIpPort_list if node[2] == 0]

            if nodes_to_connect:
                print(f"Tentative de connexion à {len(nodes_to_connect)} nœud(s) déconnecté(s)...")
                # Créer des tâches pour chaque tentative de connexion
                # Ne pas utiliser gather ici pour ne pas attendre la fin de toutes les tentatives
                # Chaque tâche connect_to_node gère sa propre vie (connexion, écoute)
                for ip, port in nodes_to_connect:
                    asyncio.create_task(self.connect_to_node(ip, port))
            # else:
                # print("Aucun nœud déconnecté à contacter pour le moment.") # Moins verbeux

            # 3. Attendre avant le prochain cycle de mise à jour et de connexion
            await asyncio.sleep(60) # Attendre 60 secondes


    async def start_server(self):
        """Démarre le serveur WebSocket"""
        server = None
        connect_task = None # Garder une référence à la tâche
        try:
            server = await websockets.serve(
                self.handle_client,
                self.host,
                self.port,
                # Optionnel: augmenter ping_interval et ping_timeout pour garder les connexions plus longtemps
                # ping_interval=60,
                # ping_timeout=120,
            )
            print(f"\nServeur WebSocket démarré sur {self.host}:{self.port}")

            # Démarrer la tâche de connexion aux autres nœuds en arrière-plan
            connect_task = asyncio.create_task(self.connect_nodes_list())

            # Garder le serveur en cours d'exécution
            await server.wait_closed()

        except OSError as e:
             print(f"Erreur au démarrage du serveur WebSocket sur {self.host}:{self.port}: {e}")
             print("Vérifiez si le port est déjà utilisé ou si l'adresse est correcte.")
        except Exception as e:
            print(f"Erreur inattendue dans start_server: {e}")
        finally:
            print("Arrêt du serveur WebSocket...")
            if connect_task and not connect_task.done():
                 connect_task.cancel() # Annuler la tâche de connexion
                 try:
                     await connect_task # Attendre l'annulation
                 except asyncio.CancelledError:
                     print("Tâche de connexion annulée.")
            if server:
                server.close()
                await server.wait_closed()
                print("Serveur WebSocket fermé.")
            # Nettoyer l'executor
            print("Arrêt de l'executor...")
            self.executor.shutdown(wait=True) # Attendre la fin des tâches de l'executor
            print("Executor arrêté.")


    def start(self):
        """Démarre le nœud dans la boucle d'événements actuelle"""
        print("Démarrage du nœud...")
        try:
            # Lancer la boucle d'événements asyncio
            self.loop.run_until_complete(self.start_server())
        except KeyboardInterrupt:
            print("\nArrêt demandé par l'utilisateur (Ctrl+C)...")
            # La logique d'arrêt est principalement dans le finally de start_server
        finally:
            # S'assurer que la boucle est arrêtée proprement si elle tourne encore
            if self.loop.is_running():
                 print("Arrêt de la boucle d'événements...")
                 # Donner un peu de temps pour que les tâches d'annulation se terminent
                 # self.loop.call_soon_threadsafe(self.loop.stop) # Méthode thread-safe si appelée depuis un autre thread
                 self.loop.stop() # Si appelé depuis le même thread que run_until_complete

            # Fermer la boucle d'événements
            # Il est souvent recommandé de fermer la boucle après l'avoir arrêtée
            # et après que toutes les tâches soient terminées/annulées.
            # Attention: Ne pas fermer si elle pourrait être réutilisée.
            if not self.loop.is_closed():
                 # Attendre que les tâches restantes (comme les fermetures de websockets) se terminent
                 # Peut nécessiter une gestion plus fine des tâches en cours
                 # current_tasks = asyncio.all_tasks(self.loop)
                 # if current_tasks:
                 #    print(f"Attente de la fin de {len(current_tasks)} tâches...")
                 #    await asyncio.gather(*current_tasks, return_exceptions=True)

                 print("Fermeture de la boucle d'événements.")
                 self.loop.close()
            print("Nœud arrêté proprement.")

if __name__ == "__main__":
    # Créer l'instance du nœud
    node = Node('0.0.0.0', 9102)
    #node.nodeIpPort_list.append(["10.66.66.4", 9102])		# Pour tests
    # Démarrer le nœud principal (bloquant jusqu'à Ctrl+C)
    node.start()

    # Le programme attend ici que node.start() se termine
    # Le thread HTTP étant daemon, il s'arrêtera avec le thread principal
    print("Programme principal terminé.")