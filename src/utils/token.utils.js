const jwt = require("jsonwebtoken");
const { jwtConfig } = require("../config/jwt");

// Generate Access Token
const generateAccessToken = (user) => {
  const { secret } = jwtConfig();
  return jwt.sign(
    {
      id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
    },
    secret,
    { expiresIn: "15m" },
  );
};

// Generate Refresh Token
const generateRefreshToken = (user) => {
  const { secret } = jwtConfig();
  return jwt.sign({ id: user._id }, secret, { expiresIn: "7d" });
};
module.exports = {
  generateAccessToken,
  generateRefreshToken,
};
