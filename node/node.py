import asyncio
import websockets
import threading
import time
import uuid
import json
import requests
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, HTTPServer
from collections import deque
import sqlite3

class Node:
    def __init__(self, host: str, port: int):
        '''
        Initialisation du noeud, avec tout ses attributs de base
        '''
        self.host = host
        self.port = port
        self.client_connections = set()
        self.node_connections = set()
        self.nodeIpPort_list = []
        self.lock = threading.Lock()
        self.message_cache = deque(maxlen=1000)
        self.DEFAULT_TTL = 5
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.executor = ThreadPoolExecutor(max_workers=2)
        self.bootstrap_url = "https://bootstrap.nexachat.tech/upNodes"
        self.client_pubkey = {}
        self.db_co = sqlite3.connect(f"node_{self.port}_messages.db", check_same_thread=False)
        self._init_db()


    def _init_db(self):
        '''
        Initialise la database où seront stockés les messages vers des clients non connectés
        '''
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

    async def handle_client(self, websocket):
        '''
        Gère :
        - l'enregistrement des clients sous la forme : register;client;peudo;pubKey
        - l'enregistrement des noeuds sous la forme : register;node;ip;port

        - le stockage des connections avec les clients dans self.client_connections
        - le stockage des connections avec les noeuds dans self.node_connections sous la forme d'un tuple (ip, port)

        - le transfert de messages reçus par les clients sous la forme : envoyeur;contenu;receveur;uuidMessage;TTL

        - l'envoi des messages aux clients (via send_to_clients) et aux noeuds (via send_to_nodes)
        '''
        remote_address = websocket.remote_address
        print(f"Nouvelle connexion de {remote_address}")

        try:
            async for message in websocket:
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
                    parts = message.split(';')
                    if len(parts) >= 4:
                        node_ip = parts[2]
                        node_port_str = parts[3]
                        try:
                            node_port = int(node_port_str)
                            if node_ip == "0.0.0.0" or node_ip == "127.0.0.1":
                               node_ip = remote_address[0]

                            node_tuple = (node_ip, node_port)
                            print(f"Tentative d'enregistrement du noeud: {node_tuple}")

                            with self.lock:
                                is_known = any(n[0] == node_ip and n[1] == node_port for n in self.nodeIpPort_list)
                                is_connected_ws = websocket in self.node_connections

                                if not is_known:
                                    print(f"Nouveau noeud ajouté à la liste : {node_tuple}")
                                    self.nodeIpPort_list.append([node_ip, node_port, 1])
                                    if not is_connected_ws:
                                         self.node_connections.add(websocket)
                                else:
                                    for node_info in self.nodeIpPort_list:
                                        if node_info[0] == node_ip and node_info[1] == node_port:
                                            node_info[2] = 1
                                            break
                                    if not is_connected_ws:
                                        self.node_connections.add(websocket)
                        except ValueError:
                             print(f"Erreur: Port invalide reçu lors de l'enregistrement du noeud: {node_port_str}")

                elif message != "register;":
                    parts = message.split(';')

                    if len(parts) <= 4:
                        msg_id = str(uuid.uuid4())
                        if len(parts) >= 3:
                            message = f"{parts[0]};{parts[1]};{parts[2]};{msg_id};{self.DEFAULT_TTL}"
                            parts = message.split(';')
                        else:
                            print(f"Message ancien format invalide ignoré: {message}")
                            continue

                    if len(parts) == 5:
                        sender, content, recipient, msg_id, ttl_str = parts
                        try:
                            ttl = int(ttl_str)

                            if msg_id in self.message_cache:
                                continue

                            self.message_cache.append(msg_id)
                            ttl -= 1

                            if ttl > 0:
                                next_message = f"{sender};{content};{recipient};{msg_id};{ttl}"

                                await self.send_to_clients(next_message, websocket if websocket in self.client_connections else None)

                                await self.send_to_nodes(next_message, websocket if websocket in self.node_connections else None)

                        except ValueError:
                            print(f"Erreur: TTL invalide dans le message '{message}'")
                        except Exception as e:
                            print(f"Erreur inattendue lors du traitement du message: {e}")

                if 'quit' in message.lower():
                    print(f"Client {remote_address} a demandé à quitter.")
                    break

        except websockets.exceptions.ConnectionClosed as e:
            if e.code != 1000 and e.code != 1001 :
                 print(f"Connexion fermée anormalement avec {remote_address} - Raison: {e.reason} (code: {e.code})")
        except Exception as e:
            print(f"Erreur inattendue avec {remote_address}: {e}")
        finally:
            with self.lock:
                removed_client = websocket in self.client_connections
                removed_node = websocket in self.node_connections
                if removed_client:
                    self.client_connections.remove(websocket)
                if removed_node:
                    self.node_connections.remove(websocket)
                    try:
                        node_ip = remote_address[0]
                        node_port = remote_address[1]
                        for node_info in self.nodeIpPort_list:
                            if node_info[0] == node_ip and node_info[1] == node_port:
                                node_info[2] = 0
                                break
                    except Exception as e:
                         print(f"Erreur lors du marquage du noeud comme déconnecté: {e}")


    async def send_to_clients(self, message, sender_ws=None):
        '''
        Envoie un message à tous les clients connectés sauf l'expéditeur
        '''
        if not self.client_connections:
            return

        clients_copy = list(self.client_connections)
        closed_clients = set()

        for client in clients_copy:
            if client == sender_ws:
                continue

            try:
                await client.send(message)
            except websockets.exceptions.ConnectionClosed:
                closed_clients.add(client)
            except Exception as e:
                print(f"Erreur envoi vers client {client.remote_address}: {e}")
                closed_clients.add(client)

        if closed_clients:
            with self.lock:
                self.client_connections.difference_update(closed_clients)

    async def send_to_nodes(self, message, sender_ws=None):
        '''
        Envoie le message aux autres noeuds connectés
        '''
        if not self.node_connections:
            return

        nodes_copy = list(self.node_connections)
        closed_nodes = set()

        for node_ws in nodes_copy:
            if node_ws == sender_ws:
                continue

            try:
                await node_ws.send(message)
            except websockets.exceptions.ConnectionClosed:
                remote_addr = node_ws.remote_address
                closed_nodes.add(node_ws)
                with self.lock:
                    for node_info in self.nodeIpPort_list:
                        if remote_addr and node_info[0] == remote_addr[0] and node_info[1] == remote_addr[1]:
                            node_info[2] = 0
                            break
            except Exception as e:
                remote_addr = node_ws.remote_address
                print(f"Erreur envoi vers noeud {remote_addr}: {e}")
                closed_nodes.add(node_ws)
                with self.lock:
                    for node_info in self.nodeIpPort_list:
                        if remote_addr and node_info[0] == remote_addr[0] and node_info[1] == remote_addr[1]:
                            node_info[2] = 0
                            break

        if closed_nodes:
            with self.lock:
                self.node_connections.difference_update(closed_nodes)

    async def connect_to_node(self, ip, port):
        '''
        établit une connexion websocket avec les autres noeuds du réseau (sauf soi-même)
        '''
        if (ip == self.host or ip == '127.0.0.1' or ip == 'localhost') and port == self.port:
             return

        with self.lock:
             already_connected = any(
                 node_ws.remote_address and node_ws.remote_address[0] == ip and node_ws.remote_address[1] == port
                 for node_ws in self.node_connections
             )
             if already_connected:
                 for node_info in self.nodeIpPort_list:
                     if node_info[0] == ip and node_info[1] == port:
                         if node_info[2] == 0:
                             node_info[2] = 1
                         break
                 return


        uri = f"ws://{ip}:{port}"
        websocket = None
        try:
            websocket = await asyncio.wait_for(websockets.connect(uri), timeout=5.0)
            print(f"Connecté avec succès à {uri}")

            await websocket.send(f"register;node;0.0.0.0;{self.port}")

            with self.lock:
                self.node_connections.add(websocket)
                found = False
                for node_info in self.nodeIpPort_list:
                    if node_info[0] == ip and node_info[1] == port:
                        node_info[2] = 1
                        found = True
                        break
                if not found:
                    self.nodeIpPort_list.append([ip, port, 1])
                    print(f"Noeud {ip}:{port} ajouté à la liste suite à connexion réussie.")

            asyncio.create_task(self.listen_to_node(websocket, ip, port))


        except (websockets.exceptions.ConnectionClosed, websockets.exceptions.InvalidURI, websockets.exceptions.InvalidHandshake, OSError, asyncio.TimeoutError) as e:
            with self.lock:
                for node_info in self.nodeIpPort_list:
                    if node_info[0] == ip and node_info[1] == port:
                        if node_info[2] == 1:
                            node_info[2] = 0
                        break
                if websocket in self.node_connections:
                    self.node_connections.remove(websocket)
        except Exception as e:
             print(f"Erreur inattendue lors de la connexion sortante vers {ip}:{port}: {e}")
             with self.lock:
                for node_info in self.nodeIpPort_list:
                    if node_info[0] == ip and node_info[1] == port:
                         node_info[2] = 0
                         break
                if websocket and websocket in self.node_connections:
                    self.node_connections.remove(websocket)


    async def listen_to_node(self, websocket, ip, port):
        '''
        écoute continuellement les messages des noeuds auxquels on est connectés
        '''
        try:
            async for message in websocket:
                await self.process_incoming_message(message, websocket)
        except websockets.exceptions.ConnectionClosed as e:
             pass
        except Exception as e:
            print(f"Erreur écoute sur connexion sortante {ip}:{port}: {e}")
        finally:
            with self.lock:
                if websocket in self.node_connections:
                    self.node_connections.remove(websocket)
                for node_info in self.nodeIpPort_list:
                    if node_info[0] == ip and node_info[1] == port:
                        node_info[2] = 0
                        break


    async def process_incoming_message(self, message, websocket):
        '''
        traite les messages recus
        '''
        try:
            parts = message.split(';')
            if message.startswith("register;"):
                return

            if len(parts) <= 4:
                msg_id = str(uuid.uuid4())
                if len(parts) >= 3:
                    message = f"{parts[0]};{parts[1]};{parts[2]};{msg_id};{self.DEFAULT_TTL}"
                    parts = message.split(';')
                else:
                    return

            if len(parts) == 5:
                sender, content, recipient, msg_id, ttl_str = parts
                try:
                    ttl = int(ttl_str)

                    if msg_id in self.message_cache:
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
                            await self.send_to_nodes(next_message, websocket if websocket in self.node_connections else None)

                except ValueError:
                    print(f"Erreur: TTL invalide dans le message '{message}' (process_incoming)")
                except Exception as e:
                    print(f"Erreur traitement message (process_incoming): {e}")

        except Exception as e:
            print(f"Erreur majeure dans process_incoming_message: {e}")


    def _fetch_up_nodes_sync(self):
        '''
        récupère les noeuds depuis la bootstrap
        '''
        try:
            response = requests.get(self.bootstrap_url, timeout=10)
            response.raise_for_status()
            nodes_data = response.json()
            print(f"Liste brute reçue du bootstrap: {len(nodes_data)} entrées")
            return nodes_data
        except requests.exceptions.RequestException as e:
            print(f"Erreur lors de la récupération des nœuds depuis {self.bootstrap_url}: {e}")
        except json.JSONDecodeError as e:
            print(f"Erreur de décodage JSON depuis {self.bootstrap_url} (réponse non JSON?): {e}")
            try:
                response_text = requests.get(self.bootstrap_url, timeout=10).text
                nodes_data = response_text.strip().splitlines()
                print(f"Liste brute (texte) reçue du bootstrap: {len(nodes_data)} lignes")
                return nodes_data
            except Exception as e_text:
                 print(f"Impossible de lire la réponse comme texte brut non plus: {e_text}")

        except Exception as e:
            print(f"Erreur inattendue lors du fetch bootstrap: {e}")
        return None


    async def update_node_list_from_bootstrap(self):
        '''
        met continuellement a jour la liste des noeuds via le bootstrap
        '''
        print("Tentative de mise à jour de la liste des nœuds depuis le bootstrap...")
        nodes_data = await self.loop.run_in_executor(self.executor, self._fetch_up_nodes_sync)

        if nodes_data is not None and isinstance(nodes_data, list):
            with self.lock:
                existing_nodes = set((n[0], n[1]) for n in self.nodeIpPort_list)
                nodes_added = 0
                for node_entry_str in nodes_data:
                    if not isinstance(node_entry_str, str):
                        print(f"Entrée de noeud ignorée (pas une string): {node_entry_str}")
                        continue

                    try:
                        parts = node_entry_str.split(':')
                        if len(parts) == 2:
                            ip = parts[0].strip()
                            port_str = parts[1].strip()
                            port = int(port_str)
                            if ip and port > 0 and port < 65536:
                                if (ip == self.host or ip == '127.0.0.1') and port == self.port:
                                    continue

                                if (ip, port) not in existing_nodes:
                                    self.nodeIpPort_list.append([ip, port, 0])
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
        else:
            print("Aucune donnée de nœud valide reçue ou erreur lors du fetch.")


    async def connect_nodes_list(self):
        """Met à jour la liste depuis bootstrap et essaie de se connecter aux nœuds non connectés"""
        await asyncio.sleep(5)

        while True:
            await self.update_node_list_from_bootstrap()

            nodes_to_connect = []
            with self.lock:
                nodes_to_connect = [(node[0], node[1]) for node in self.nodeIpPort_list if node[2] == 0]

            if nodes_to_connect:
                print(f"Tentative de connexion à {len(nodes_to_connect)} nœud(s) déconnecté(s)...")
                for ip, port in nodes_to_connect:
                    asyncio.create_task(self.connect_to_node(ip, port))
            await asyncio.sleep(60)


    async def start_server(self):
        '''
        démarre le serveur websocket
        '''
        server = None
        connect_task = None
        try:
            server = await websockets.serve(
                self.handle_client,
                self.host,
                self.port,
            )
            print(f"\nServeur WebSocket démarré sur {self.host}:{self.port}")

            connect_task = asyncio.create_task(self.connect_nodes_list())

            await server.wait_closed()

        except OSError as e:
             print(f"Erreur au démarrage du serveur WebSocket sur {self.host}:{self.port}: {e}")
             print("Vérifiez si le port est déjà utilisé ou si l'adresse est correcte.")
        except Exception as e:
            print(f"Erreur inattendue dans start_server: {e}")
        finally:
            print("Arrêt du serveur WebSocket...")
            if connect_task and not connect_task.done():
                 connect_task.cancel()
                 try:
                     await connect_task
                 except asyncio.CancelledError:
                     print("Tâche de connexion annulée.")
            if server:
                server.close()
                await server.wait_closed()
                print("Serveur WebSocket fermé.")
            print("Arrêt de l'executor...")
            self.executor.shutdown(wait=True)
            print("Executor arrêté.")

    def start(self):
        """Démarre le nœud dans la boucle d'événements actuelle"""
        print("Démarrage du nœud...")
        try:
            self.loop.run_until_complete(self.start_server())
        except KeyboardInterrupt:
            print("\nArrêt demandé par l'utilisateur (Ctrl+C)...")
        finally:
            if self.loop.is_running():
                 print("Arrêt de la boucle d'événements...")
                 self.loop.stop()

            if not self.loop.is_closed():
                 print("Fermeture de la boucle d'événements.")
                 self.loop.close()
            print("Nœud arrêté proprement.")

if __name__ == "__main__":
    # Créer l'instance du nœud
    node = Node('0.0.0.0', 9102)
    node.start()

    print("Programme principal terminé.")