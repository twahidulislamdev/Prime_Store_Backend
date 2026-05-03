const express = require("express");
const router = express.Router();
const {
  SignUpController,
  LoginController,
  LogOutController,
  LogOutAllController,
  DashboardController,
  VerifyTokenController,
  RefreshTokenController,
} = require("../../controllers/authController");

const {
  VerifyOtpController,
  ResendOtpController,
} = require("../../controllers/otpController");

// ================== Sign Up Route ==================
router.post("/signup", SignUpController);

// ================== Verify OTP Route ==================
router.post("/verifyotp", VerifyOtpController);

// ================== Resend OTP Route ==================
router.post("/resendotp", ResendOtpController);

// ================== Login Route ==================
router.post("/login", LoginController);

// ================== Dashboard Route ==================
router.get("/dashboard", DashboardController);

// ================== Verify Token Route ==================
router.get("/verifytoken", VerifyTokenController);

// ================== Refresh Token Route ==================
router.get("/refreshtoken", RefreshTokenController);

// ================== Log Out Route ==================
router.post("/logout", LogOutController);

// ================== Log Out All Route ==================
router.post("/logoutall", LogOutAllController);

module.exports = router;
