const express = require("express");
const router = express.Router();
const {
  SignUp,
  Login,
  LogOut,
  LogOutAll,
  Dashboard,
  VerifyToken,
  RefreshToken,
} = require("../../controllers/auth.controller");

const {
  VerifyOtp,
  ResendOtp,
} = require("../../services/auth.service");

// ================== Sign Up Route ==================
router.post("/signup", SignUp);

// ================== Verify OTP Route ==================
router.post("/verifyotp", VerifyOtp);

// ================== Resend OTP Route ==================
router.post("/resendotp", ResendOtp);

// ================== Login Route =======================
router.post("/login", Login);

// ================== Dashboard Route ===================
router.get("/dashboard", Dashboard);

// ================== Verify Token Route ==================
router.get("/verifytoken", VerifyToken);

// ================== Refresh Token Route ==================
router.get("/refreshtoken", RefreshToken);

// ================== Log Out Route ==================
router.post("/logout", LogOut);

// ================== Log Out All Route ==================
router.post("/logoutall", LogOutAll);

module.exports = router;
