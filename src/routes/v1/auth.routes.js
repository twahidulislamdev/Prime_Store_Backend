const express = require("express");
const router = express.Router();
const {
  SignUp,
  Login,
  LogOut,
  LogOutAll,
  VerifyOtp,
  ResendOtp,
  RefreshToken,
} = require("../../controllers/auth.controller");

const { VerifyToken } = require("../../middleware/auth.middleware");

// ================== Sign Up Route ==================
router.post("/signup", SignUp);

// ================== Verify OTP Route ==================
router.post("/verifyotp", VerifyOtp);

// ================== Resend OTP Route ==================
router.post("/resendotp", ResendOtp);

// ================== Login Route =======================
router.post("/login", Login);

// ================== Verify Token Route ==================
router.get("/verifytoken", VerifyToken, (req, res) => {
  return res.json({
    message: "User Data Retrieved Successfully",
    user: req.user,
  });
});

// ================== Refresh Token Route ==================
router.get("/refreshtoken", RefreshToken);

// ================== Log Out Route ==================
router.post("/logout", LogOut);

// ================== Log Out All Route ==================
router.post("/logoutall", LogOutAll);

module.exports = router;
