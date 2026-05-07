const jwt = require("jsonwebtoken");
const { jwtConfig } = require("../config/jwt");

const VerifyToken = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Unauthorized" });
    const decoded = jwt.verify(token, jwtConfig().secret);
    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Token Expired" });
    }
    return res.status(401).json({ message: "Invalid Or Expired Access Token" });
  }
};
module.exports = {
  VerifyToken,
};
