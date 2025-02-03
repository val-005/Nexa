const  express = require('express');
const app = express();
app.use(express.json());

const axios = require('axios');

const sqlite3 = require('sqlite3').verbose();
// A changer, mettre le path de l'environnement docker
const db = new sqlite3.Database('db.sqlite');
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, node TEXT UNIQUE)");
    db.run("CREATE TABLE IF NOT EXISTS upnodes (id INTEGER PRIMARY KEY AUTOINCREMENT, node TEXT UNIQUE)");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log("Server Listening on PORT:", PORT);
  });

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

// Enregistrer un noeud, A ajouter une verif pour voir si l'addresse est valide
app.post("/registerNode", (req, res) => {
    let { node } = req.body;
    // On enlève le http:// devant et le / à la fin si il y en a, pour que toutes les entrées dans la db soient sous la meme forme
    node = node.replace(/^http:\/\//, '');
    node = node.replace(/\/$/, '');

    if (typeof node === "string" && node.trim() !== "") {
        db.get(`SELECT node FROM nodes WHERE node = ?`, [node], (err, col) => {
            if (err) {
                res.status(500).send({ error: "Database error" });
            } else if (col) {
                res.status(400).send({ error: "Node is already registered" });
            } else {
                db.run(`INSERT INTO nodes (node) VALUES (?)`, [node], (err) => {
                    if (err) {
                        res.status(500).send({ error: "Failed to register node" });
                    } else {
                        res.send({ status: "success" });
                    }
                });
            }
        });
    } else {
        res.status(400).send({ error: "Invalid node. It must be a non-empty string." });
    }
});


// Récupérer la liste des noeuds up, à améliorer, risque de charge trop élevée sur le serveur si beaucoup de requetes
app.get("/checkNodes", async (req, res) => {
    db.all("SELECT node FROM nodes", async (err, table) => {
        if (err) {
            res.status(500).send({ error: "Failed to retrieve nodes" });
        } else {
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
                    res.status(500).send({ error: "Failed to clear upnodes table" });
                } else {
                    if (upNodes.length > 0) {
                        const placeholders = upNodes.map(() => "(?)").join(",");
                        db.run(`INSERT INTO upnodes (node) VALUES ${placeholders}`, upNodes, (err) => {
                            if (err) {
                                res.status(500).send({ error: "Error while updating the table" });
                                console.log(err);
                            } else {

                                res.send( upNodes );
                            }
                        });
                    } else {
                        res.send([]);
                    }
                }
            });
        }
    });
});