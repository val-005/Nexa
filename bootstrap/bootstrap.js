const express = require('express');
const app = express();
app.use(express.json());

const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('db.sqlite');
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, node TEXT UNIQUE)");
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


app.get("/nodes", (req, res) => {
    db.all("SELECT node FROM nodes", (err, rows) => {
        if (err) {
            res.status(500).send({ error: "Failed to retrieve nodes" });
        } else {
            const nodes = rows.map(row => row.node);
            res.send(nodes);
        }
    });
});

app.post("/registerNode", (req, res) => {
    const { node } = req.body;

    if (typeof node === "string" && node.trim() !== "") {
        db.get(`SELECT node FROM nodes WHERE node = ?`, [node], (err, row) => {
            if (err) {
                res.status(500).send({ error: "Database error" });
            } else if (row) {
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
