const express = require("express");
const app = express();
app.use(express.json());

const supertest = require("supertest");  // Pour Jest
const axios = require("axios");
const sqlite3 = require("sqlite3").verbose();


// A changer, mettre le path de l'environnement docker
const db = new sqlite3.Database('db.sqlite');
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, node TEXT UNIQUE)");
    db.run("CREATE TABLE IF NOT EXISTS upnodes (id INTEGER PRIMARY KEY AUTOINCREMENT, node TEXT UNIQUE)");
});

// Partie Fonctions
const checkNodes = async () => {
    db.all("SELECT node FROM nodes", async (err, table) => {
        if (err) {
            console.log(err);
        }
    const upNodes = [];
    for (const col of table) {
        try {
            // Si le noeud répond correctement à la requete get, alors on l'ajoute a la liste des noeuds up
            const response = await axios.get(`http://${col.node}/status`);
            if (response.status === 200) {
                upNodes.push(col.node);
            }
        } catch (error) {
        }
    }


    db.run("DELETE FROM upnodes", (err) => {
        if (err) {
            console.log(err);
        } else {
            if (upNodes.length > 0) {
                const placeholders = upNodes.map(() => "(?)").join(",");
                db.run(`INSERT INTO upnodes (node) VALUES ${placeholders}`, upNodes, (err) => {
                    if (err) {
                        console.log(err);
                    }
                });
            }
        }
    });
    console.log("Up Nodes:", upNodes);
});
}
checkNodes();
const checkNodesInterval = setInterval(checkNodes, 5 * 60 * 1000);


app.get("/status", (req, res) => {
    const status = {
        status: "Server is running",
        current_time: new Date().toLocaleString()
    };

res.send(status);

});

// Fonction pour récupérer la liste des noeuds enregistrés, a modifier / supprimer car inutile
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

        db.run(`INSERT INTO nodes (node) VALUES (?)`, [node], (err) => {
            if (err) {
                if (err.code === 'SQLITE_CONSTRAINT') {
                    return res.status(400).send({ error: "Node is already registered" });
                }
                return res.status(500).send({ error: "Failed to register node" });
            }
            res.send({ status: "success" });
        });
    });
});


// Récupérer la liste des noeuds up
app.get("/upNodes", async (req, res) => {
    db.all("SELECT node FROM upnodes", (err, table) => {
        if (err) {
            res.status(500).send({ error: "Failed to retrieve nodes" });
        } else {
            const nodes = table.map(col => col.node);
            res.send(nodes);
        }
    });
})

if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log("Server Listening on PORT:", PORT));
}

module.exports = { app, checkNodesInterval };