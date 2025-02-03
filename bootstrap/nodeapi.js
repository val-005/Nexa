const  express = require('express');
const app = express();
app.use(express.json());

const PORT = process.env.PORT || 4000;
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