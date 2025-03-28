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

const dbPath = process.env.DB_PATH || "db.sqlite";
const fullPath = path.resolve(dbPath);
const db = new sqlite3.Database(fullPath);
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, node TEXT UNIQUE)");
  db.run("CREATE TABLE IF NOT EXISTS upnodes (id INTEGER PRIMARY KEY AUTOINCREMENT, node TEXT UNIQUE)");
});

const PROTOCOL = process.env.NODE_PROTOCOL || 'http';

const NodeSocketCheck = (host, port, timeout = 5000) => {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);
    
    socket.connect(port, host, () => {
      socket.destroy();
      resolve(true);
    });
    socket.on("error", () => {
      socket.destroy();
      resolve(false);
    });
    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });
  });
};

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
        
        if (isAlive) {
          upNodes.push(col.node);
        }
      } catch (error) {
      }
    }

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
const checkNodesInterval = setInterval(checkNodes, 5 * 60 * 1000);


app.get("/status", (req, res) => {
  const status = {
    status: "Server is running",
    current_time: new Date().toLocaleString()
  };
  res.send(status);
});

app.get("/nodes", (req, res) => {
  db.all("SELECT node FROM nodes", (err, table) => {
    if (err) {
      res.status(500).send({ error: "Failed to retrieve nodes" });
    } else {
      const nodes = table.map(col => col.node);
      res.send(nodes);
    }
  });
});

app.post("/registerNode", (req, res) => {
  let { node } = req.body;

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

app.get("/upNodes", async (req, res) => {
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

const SSL_ENABLED = process.env.SSL_ENABLED === "true";
const PORT = process.env.PORT || (SSL_ENABLED ? 443 : 80);
const KEY_PATH = process.env.SSL_KEY_PATH;
const CRT_PATH = process.env.SSL_CRT_PATH;
const CA_PATH = process.env.SSL_CHAIN_PATH;
if (require.main === module) {
    if (SSL_ENABLED) {
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