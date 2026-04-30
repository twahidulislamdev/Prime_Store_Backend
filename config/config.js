const mongoose = require("mongoose");


const dbConfig = () => {
  mongoose
    .connect(`${process.env.DB_URL}`)
    .then(() => console.log("Database Connected!"));
};

const jwtConfig  = () => {
  return {
    secret: process.env.JWT_SECRET,
    expiresIn: "1h",
  };
};


module.exports = { dbConfig, jwtConfig };
