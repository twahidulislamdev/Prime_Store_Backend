const express = require("express");
const cookieParser = require("cookie-parser");
const routes = require("./routes");

const app = express();

// Middleware to parse JSON requests
app.use(express.json());
app.use(cookieParser());

app.get("/", (req, res) => {
  res.send("Hello World!");
});

// Routing
app.use("/api", routes);

module.exports = app;
