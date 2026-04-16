const express = require("express");
const router = express.Router();
const {
  SignUpController,
  LoginController,
  LogOutController,
  DashboardController,
} = require("../../controllers/authController");

const {
  InitialOtpController,
  ResendOtpController,
} = require("../../controllers/otpController");

router.post("/signup", SignUpController);
router.post("/login", LoginController);
router.post("/logout", LogOutController);
router.get("/dashboard", DashboardController);
router.post("/otpverification", InitialOtpController);
router.post("/resendotp", ResendOtpController);

// router.get("/login", (req, res) => {
//   res.send("Data Ache");
// });

module.exports = router;
