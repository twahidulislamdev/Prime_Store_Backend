require("node:dns/promises").setServers(["1.1.1.1", "8.8.8.8"]);
require("dotenv").config();
const app = require("./src/app");
const { connectDB } = require("./src/config/db");
const { jwtConfig } = require("./src/config/jwt");

const PORT = process.env.PORT || 3000;

// Database Connection
connectDB();

// JWT Config Init
jwtConfig();

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
