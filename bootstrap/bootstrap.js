const express = require("express");
const app = express();
app.use(express.json());

const supertest = require("supertest");  // Pour Jest
const axios = require("axios");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");
const https = require("https");
const net = require("net");
const WebSocket = require('ws');

// Initialisation de la BDD et des tables si elles n'existent pas déjà
const dbPath = process.env.DB_PATH || "db.sqlite";
const fullPath = path.resolve(dbPath);
const db = new sqlite3.Database(fullPath);
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, node TEXT UNIQUE)");
  db.run("CREATE TABLE IF NOT EXISTS upnodes (id INTEGER PRIMARY KEY AUTOINCREMENT, node TEXT UNIQUE)");
});

// PARTIE FONCTIONS
// Vérifier si un noeud est actif
const NodeSocketCheck = (host, port, timeout = 5000) => {
  return new Promise((resolve) => {
    const protocol = port === 443 ? 'wss' : 'ws';
    const url = `${protocol}://${host}:${port}`;
    const ws = new WebSocket(url);
    
    const timeoutId = setTimeout(() => {
      ws.terminate();
      resolve(false);
    }, timeout);
    
    // Si la connexion websockets s'ouvre à l'ip port donnée, alors le noeud est accessible
    ws.on('open', () => {
      clearTimeout(timeoutId);
      ws.close();
      resolve(true);
    });
    
    ws.on('error', () => {
      clearTimeout(timeoutId);
      ws.terminate();
      resolve(false);
    });
  });
};
// Vérifier périodiquement quels sont les noeuds actifs enregistrés dans la table nodes
const checkNodes = async () => {
  db.all("SELECT node FROM nodes", async (err, table) => {
    if (err) {
      console.log(err);
      return; 
    }

    const upNodes = [];
    for (const col of table) {
      try {
        const [host, port] = col.node.split(':');
        const isAlive = await NodeSocketCheck(host, parseInt(port));
        // On appelle isAlive pour chaque noeud dans la liste, si vrai on l'ajoute à upNodes
        if (isAlive) {
          upNodes.push(col.node);
        }
      } catch (error) {
      }
    }

    // On vide la table upnodes et on insère les noeuds actifs
    db.run("DELETE FROM upnodes", (err2) => {
      if (err2) {
        console.log(err2);
      } else {
        if (upNodes.length > 0) {
          const placeholders = upNodes.map(() => "(?)").join(",");
          db.run(`INSERT INTO upnodes (node) VALUES ${placeholders}`, upNodes, (err3) => {
            if (err3) {
              console.log(err3);
            }
          });
        }
      }
    });
  });
};
checkNodes();
// On utilise un setInterval pour faire tourner la fonction checkNodes toutes les 5 minutes
const checkNodesInterval = setInterval(checkNodes, 5 * 60 * 1000);


// PARTIE ROUTES
app.get("/status", (req, res) => {
  const status = {
    status: "Server is running",
    current_time: new Date().toLocaleString()
  };
  res.send(status);
});
// Récupérer les noeuds enregistrés
app.get("/nodes", (req, res) => {
  db.all("SELECT node FROM nodes", (err, table) => {
    if (err) {
      res.status(500).send({ error: "Failed to retrieve nodes" });
    } else {
      // On récupère la table noeuds et on renvoie la liste
      const nodes = table.map(col => col.node);
      res.send(nodes);
    }
  });
});
// Enregistrer un noeud
app.post("/registerNode", (req, res) => {
  let { node } = req.body;

  // On s'assure que le noeud est au format host:port
  node = node.replace(/^http:\/\//, '').replace(/\/$/, '');

  const regex = /^[a-zA-Z0-9.-]+:[0-9]+$/;  // Format host:port
  if (!regex.test(node)) {
    return res.status(400).send({ error: "Invalid node format. Use 'host:port'." });
  }

  db.get(`SELECT node FROM nodes WHERE node = ?`, [node], (err, col) => {
    if (err) {
      return res.status(500).send({ error: "Database error" });
    }
    if (col) {
      return res.status(400).send({ error: "Node is already registered" });
    }

    db.run(`INSERT INTO nodes (node) VALUES (?)`, [node], (err2) => {
      if (err2) {
        if (err2.code === 'SQLITE_CONSTRAINT') {
          return res.status(400).send({ error: "Node is already registered" });
        }
        return res.status(500).send({ error: "Failed to register node" });
      }
      res.send({ status: "success" });
    });
  });
});

// Liste des noeuds actifs
app.get("/upNodes", async (req, res) => {
  // On récupère la table upnodes et on renvoie la liste
  db.all("SELECT node FROM upnodes", (err, table) => {
    if (err) {
      res.status(500).send({ error: "Failed to retrieve nodes" });
    } else {
      const nodes = table.map(col => col.node);
      res.send(nodes);
    }
  });
});

app.get("/", (req, res) => {
  res.redirect("https://www.youtube.com/watch?v=dQw4w9WgXcQ");
});

// On définit les variables d'environnement qui sont données lors du lancement du conteneur
const SSL_ENABLED = process.env.SSL_ENABLED === "true";
const PORT = process.env.PORT || (SSL_ENABLED ? 443 : 80);
// Certificats SSL
const KEY_PATH = process.env.SSL_KEY_PATH;
const CRT_PATH = process.env.SSL_CRT_PATH;
const CA_PATH = process.env.SSL_CHAIN_PATH;
if (require.main === module) {
    if (SSL_ENABLED) { // Si SSL activé on expose sur le port 443 en https avec les certificats SSL qui sont donnés en variables d'environnement, sinon on expose en http sur le port 80
      const privateKey  = fs.readFileSync(KEY_PATH, 'utf8');
      const certificate = fs.readFileSync(CRT_PATH, 'utf8');
      const ca = CA_PATH ? fs.readFileSync(CA_PATH, 'utf8') : undefined;
      const credentials = { key: privateKey, cert: certificate };
      if(ca){ credentials.ca = ca; }
      https.createServer(credentials, app).listen(PORT, () => {
        console.log("HTTPS Server listening on PORT:", PORT);
      });
    } else {
      app.listen(PORT, () => {
        console.log("HTTP Server Listening on PORT:", PORT);
      });
    }
}
module.exports = { app, checkNodesInterval };