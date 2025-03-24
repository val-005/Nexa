import asyncio, websockets, threading, time, uuid, json
from http.server import BaseHTTPRequestHandler, HTTPServer
from collections import deque

class Node:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.client_connections = set()
        self.node_connections = set()
        self.nodeIpPort_list = []
        self.lock = threading.Lock()
        # Cache des messages déjà traités (limité à 1000 entrées)
        self.message_cache = deque(maxlen=1000)
        # TTL par défaut pour les messages
        self.DEFAULT_TTL = 5
        # Event loop pour les opérations asynchrones
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    async def handle_client(self, websocket):
        remote_address = websocket.remote_address
        print(f"Nouvelle connexion de {remote_address}")
        
        try:
            async for message in websocket:
                print(f"Reçu: {message} par {remote_address[0]}")
                
                # Traitement des messages de contrôle
                if "register;client;" in message:
                    with self.lock:
                        self.client_connections.add(websocket)
                
                elif "register;node;" in message:
                    # Enregistrement d'un nouveau nœud
                    parts = message.split(';')
                    if len(parts) >= 4:
                        node_ip = parts[2]
                        node_port = int(parts[3])
                        with self.lock:
                            # Vérifier s'il n'est pas déjà dans la liste
                            exists = False
                            for node in self.nodeIpPort_list:
                                if node[0] == node_ip and node[1] == node_port:
                                    # Ne pas réinitialiser l'état si déjà connecté
                                    exists = True
                                    break
                            if not exists and node_ip != "0.0.0.0":
                                self.nodeIpPort_list.append([node_ip, node_port, 0])
                                self.node_connections.add(websocket)
                
                # Traitement des messages ordinaires (non-contrôle)
                elif message != "register;":
                    parts = message.split(';')
                    
                    # Si le format est ancien (sans ID et TTL), ajoutons-les
                    if len(parts) <= 4:
                        # Créer un ID unique
                        msg_id = str(uuid.uuid4())
                        # Ajouter un TTL par défaut
                        message = f"{parts[0]};{parts[1]};{parts[2]};{msg_id};{self.DEFAULT_TTL}"
                        parts = message.split(';')
                    
                    sender, content, recipient, msg_id, ttl = parts[0], parts[1], parts[2], parts[3], int(parts[4])
                    
                    # Vérifier si nous avons déjà traité ce message
                    if msg_id in self.message_cache:
                        continue  # Ignorer les messages déjà traités
                    
                    # Ajouter ce message à notre cache
                    self.message_cache.append(msg_id)
                    
                    # Décrémenter le TTL
                    ttl -= 1
                    
                    # Si le TTL est positif, on continue la propagation
                    if ttl > 0:
                        # Nouveau message avec TTL décrémenté
                        next_message = f"{sender};{content};{recipient};{msg_id};{ttl}"
                        
                        # Envoi aux clients locaux
                        await self.send_to_clients(next_message, websocket)
                        
                        # Envoi aux autres nœuds
                        await self.send_to_nodes(next_message)
                
                if 'quit' in message.lower():
                    break
        
        except websockets.exceptions.ConnectionClosed:
            print(f"Connexion fermée avec {remote_address}")
        finally:
            with self.lock:
                if websocket in self.client_connections:
                    self.client_connections.remove(websocket)
                if websocket in self.node_connections:
                    self.node_connections.remove(websocket)

    async def send_to_clients(self, message, sender=None):
        """Envoie un message à tous les clients connectés sauf l'expéditeur"""
        closed_clients = set()
        
        for client in self.client_connections:
            if client != sender:  # Éviter de renvoyer au client d'origine
                try:
                    await client.send(message)
                except websockets.exceptions.ConnectionClosed:
                    closed_clients.add(client)
        
        # Supprimer les clients déconnectés
        with self.lock:
            self.client_connections -= closed_clients

    async def send_to_nodes(self, message):
        """Envoie un message à tous les nœuds connectés"""
        closed_nodes = set()
        
        for node in self.node_connections:
            try:
                await node.send(message)
            except websockets.exceptions.ConnectionClosed:
                closed_nodes.add(node)
                # Mise à jour de l'état du nœud dans la liste
                try:
                    remote_ip = node.remote_address[0]
                    for node_info in self.nodeIpPort_list:
                        if node_info[0] == remote_ip:
                            node_info[2] = 0  # Marquer comme déconnecté
                except Exception:
                    pass
        
        # Supprimer les nœuds déconnectés
        with self.lock:
            self.node_connections -= closed_nodes

    async def connect_to_node(self, ip, port):
        """Établit une connexion WebSocket avec un autre nœud"""
        if any(node.remote_address[0] == ip for node in self.node_connections):
            return  # Déjà connecté à ce nœud
        
        try:
            uri = f"ws://{ip}:{port}"
            print(f"Tentative de connexion à {uri}")
            
            async with websockets.connect(uri) as websocket:
                await websocket.send(f"register;node;{self.host};{self.port}")
                
                with self.lock:
                    self.node_connections.add(websocket)
                    # Mise à jour de l'état du nœud dans la liste
                    for node_info in self.nodeIpPort_list:
                        if node_info[0] == ip and node_info[1] == port:
                            node_info[2] = 1  # Marquer comme connecté
                
                # Boucle de maintien de la connexion
                async for message in websocket:
                    # Traiter les messages du nœud
                    parts = message.split(';')
                    if len(parts) > 3:
                        sender, content, recipient, msg_id = parts[0], parts[1], parts[2], parts[3]
                        if msg_id not in self.message_cache:
                            self.message_cache.append(msg_id)
                            await self.send_to_clients(message)
                            await self.send_to_nodes(message)
        
        except (websockets.exceptions.ConnectionClosed, OSError) as e:
            print(f"Erreur de connexion au nœud {ip}:{port}: {e}")
            # Marquer le nœud comme déconnecté
            for node_info in self.nodeIpPort_list:
                if node_info[0] == ip and node_info[1] == port:
                    node_info[2] = 0

    async def connect_nodes_list(self):
        """Essaie de se connecter périodiquement aux nœuds non connectés"""
        while True:
            with self.lock:
                nodes_to_connect = [(node[0], node[1]) for node in self.nodeIpPort_list if node[2] == 0]
            
            # Tentative de connexion aux nœuds non connectés
            for ip, port in nodes_to_connect:
                asyncio.create_task(self.connect_to_node(ip, port))
            
            await asyncio.sleep(5)  # Attendre avant de réessayer

    async def start_server(self):
        """Démarre le serveur WebSocket"""
        server = await websockets.serve(
            self.handle_client, 
            self.host, 
            self.port
        )
        print(f"\nServeur WebSocket démarré sur {self.host}:{self.port}")
        
        # Démarrer la tâche de connexion aux autres nœuds
        asyncio.create_task(self.connect_nodes_list())
        
        # Garder le serveur en cours d'exécution
        await server.wait_closed()

    def start(self):
        """Démarre le nœud dans un thread séparé"""
        self.loop.run_until_complete(self.start_server())

class StatusHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/status':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'OK')
        else:
            self.send_error(404)

def run_http_server():
    httpd = HTTPServer(('0.0.0.0', 8080), StatusHTTPRequestHandler)
    print("Serveur HTTP (endpoint /status) démarré sur le port 8080.\n")
    httpd.serve_forever()

if __name__ == "__main__":
    http_thread = threading.Thread(target=run_http_server)
    http_thread.daemon = True
    http_thread.start()
    
    node = Node('0.0.0.0', 9102)
    
    # Démarrer le nœud dans un thread séparé
    threading.Thread(target=node.start, daemon=True).start()
    
    # Garder le programme principal en cours d'exécution
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Arrêt du nœud...")