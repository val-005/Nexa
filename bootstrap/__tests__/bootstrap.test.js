const request = require("supertest");
const { app, checkNodesInterval } = require("../bootstrap.js");
const sqlite3 = require("sqlite3").verbose();

beforeEach((done) => {
    const db = new sqlite3.Database('db.sqlite');
    db.serialize(() => {
        db.run("CREATE TABLE IF NOT EXISTS nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, node TEXT UNIQUE)");
        db.run("CREATE TABLE IF NOT EXISTS upnodes (id INTEGER PRIMARY KEY AUTOINCREMENT, node TEXT)");
        db.run("DELETE FROM nodes");
        db.run("DELETE FROM upnodes");
        done();
    });
});

describe("🚀 API Tests", () => {
    
    test("✅ GET /status doit retourner le statut du serveur", async () => {
        const res = await request(app).get("/status");
        expect(res.statusCode).toBe(200);
        expect(res.body).toHaveProperty("status", "Server is running");
    });

    test("✅ POST /registerNode doit enregistrer un nœud valide", async () => {
        const res = await request(app)
            .post("/registerNode")
            .send({ node: "127.0.0.1:5001" });  // Utilise un autre port pour éviter les conflits
    
        expect(res.statusCode).toBe(200);
        expect(res.body).toHaveProperty("status", "success");
    });

    test("✅ GET /nodes doit retourner les nœuds enregistrés", async () => {
        const db = new sqlite3.Database('db.sqlite');
        db.run("INSERT INTO nodes (node) VALUES (?)", ["127.0.0.1:5000"], async () => {
            const res = await request(app).get("/nodes");
            expect(res.statusCode).toBe(200);
            expect(res.body).toContain("127.0.0.1:5000");
        });
    });

    test("❌ POST /registerNode ne doit pas enregistrer un nœud dupliqué", async () => {
        const db = new sqlite3.Database('db.sqlite');
        db.run("INSERT INTO nodes (node) VALUES (?)", ["127.0.0.1:5000"], async () => {
            const res = await request(app)
                .post("/registerNode")
                .send({ node: "127.0.0.1:5000" });

            expect(res.statusCode).toBe(400);
            expect(res.body).toHaveProperty("error", "Node is already registered");
        });
    });

    test("❌ POST /registerNode ne doit pas enregistrer un nœud invalide", async () => {
        const res = await request(app)
            .post("/registerNode")
            .send({ node: "invalid-node" });

        expect(res.statusCode).toBe(400);
        expect(res.body).toHaveProperty("error", "Invalid node format. Use 'host:port'.");
    });

});

afterAll(() => {
    clearInterval(checkNodesInterval);
});