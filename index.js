require("node:dns/promises").setServers(["1.1.1.1", "8.8.8.8"]);
const express = require("express");
const app = express();
const port = 3000;
require("dotenv").config();
const dbConnection = require("./database/dbConnection");
const routes = require("./routes");
const session = require("express-session");

// Middleware to parse JSON requests
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Hello World!");
});

// Use This for session management Start
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
  }),
);
// Use this for session management End

// Database Connection
dbConnection();

// Routing
app.use("/api", routes);

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
