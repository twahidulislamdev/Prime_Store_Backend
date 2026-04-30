require("node:dns/promises").setServers(["1.1.1.1", "8.8.8.8"]);
const express = require("express");
const app = express();
const port = 3000;
require("dotenv").config();
const { dbConfig } = require("./config/config");
const { jwtConfig } = require("./config/config");
const routes = require("./routes");

// Middleware to parse JSON requests
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Hello World!");
});

// Database Connection
dbConfig();

// jwtConfig
jwtConfig();

// Routing
app.use("/api", routes);

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
