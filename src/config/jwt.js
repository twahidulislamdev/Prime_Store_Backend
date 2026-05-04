const jwtConfig = () => {
  return {
    secret: process.env.JWT_SECRET,
  };
};

module.exports = { jwtConfig };
