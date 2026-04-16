const express = require("express");
const authSchema = require("../model/authSchema");
const router = express.Router();
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const emailVerification = require("../helpers/emailVerification");
const emailValidation = require("../helpers/emailValidation");

// ============ SignUp Controller =================
const SignUpController = async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;
    if (!firstName) {
      return res.json({
        message: "Error: First Name Required",
      });
    }
    if (!lastName) {
      return res.json({
        message: "Error: Last Name Required",
      });
    }
    if (!email) {
      return res.json({
        message: "Error: Email Required",
      });
    }
    if (!password) {
      return res.json({
        message: "Error: Password Required",
      });
    }
    const duplicateEmail = await authSchema.findOne({ email });
    if (duplicateEmail) {
      return res.json({
        message: "Email Already Exists ",
      });
    }
    // Crypto for Hash password
    const otp = crypto.randomInt(100000, 999999).toString();

    // Get current time
    const now = new Date();

    // Add 5 minutes
    const expireOtp = new Date(now.getTime() + 5 * 60 * 1000);

    // Format in Bangladesh time
    const bangladeshExpireTime = expireOtp.toLocaleString("en-US", {
      timeZone: "Asia/Dhaka",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: true,
    });
    console.log("OTP expires at:", bangladeshExpireTime);

    bcrypt.hash(password, 10, function (err, hash) {
      const user = new authSchema({
        firstName,
        lastName,
        email,
        password: hash,
        otp: otp,
        expireOtp: expireOtp,
      });
      emailVerification(email, otp);
      user.save();
      res.json({ message: "User registered successfully", user });
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// ============ Login Controller =================
const LoginController = async (req, res) => {
  const { email, password } = req.body;
  // Check email
  if (!email) {
    return res.json({ message: "Error: Email Required" });
  }
  // Check password
  if (!password) {
    return res.json({ message: "Error: Password Required" });
  }
  if (!emailValidation(email)) {
    return res.json({
      message: "Error: Email Formate Is not Correct ",
    });
  }

  // Find User
  const existingUser = await authSchema.findOne({ email });
  if (!existingUser) {
    return res.json({ message: "Error: User Not Found" });
  }

  // Check verification
  if (!existingUser.isVerified) {
    return res.json({ message: "Error: User Not Verified" });
  }
  // Match password with Hash Created Hash Password 
  const matchPassword = await bcrypt.compare(password, existingUser.password);
  if (!matchPassword) {
    return res.json({ message: "Error: Incorrect Password" });
  }

  // Create session
  req.session.isAuth = true;
  req.session.userSchema = {
    firstName: existingUser.firstName,
    lastName: existingUser.lastName,
    id: existingUser.id,
    email: existingUser.email,
  };
  return res.json({
    message: "Login in Successfully",
    // user: req.session.userSchema,
  });
};

// ============ LogOut Controller =================
const LogOutController = (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.json({ message: "Error: Unable to logout" });
    }

    res.clearCookie("connect.sid");
    return res.json({ message: "Logged out successfully" });
  });
};

// ============ Dashboard Controller Controller =================
const DashboardController = (req, res) => {
  if (req.session.isAuth && req.session.userSchema) {
    return res.json({
      message: "Welcome to Dashboard",
      // user: req.session.userSchema,
    });
  }
  return res.json({ message: "Access Denied" });
};

module.exports = {
  SignUpController,
  LoginController,
  LogOutController,
  DashboardController,
};
