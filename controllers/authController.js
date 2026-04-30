const authSchema = require("../model/authSchema");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const emailVerification = require("../helpers/emailVerification");
const emailValidation = require("../helpers/emailValidation");
const jwt = require("jsonwebtoken");
const { jwtConfig } = require("../config/config");

// ============ SignUp Controller =================
const SignUpController = async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;
    if (!firstName) {
      return res.json({ message: "Error: First Name Required" });
    }
    if (!lastName) {
      return res.json({ message: "Error: Last Name Required" });
    }
    if (!email) {
      return res.json({ message: "Error: Email Required" });
    }
    if (!password) {
      return res.json({ message: "Error: Password Required" });
    }

    const duplicateEmail = await authSchema.findOne({ email });
    if (duplicateEmail) {
      return res.json({ message: "Email Already Exists" });
    }

    const otp = crypto.randomInt(100000, 999999).toString();
    const now = new Date();
    const expireOtp = new Date(now.getTime() + 5 * 60 * 1000);

    const bangladeshExpireTime = expireOtp.toLocaleString("en-US", {
      timeZone: "Asia/Dhaka",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: true,
    });
    console.log("OTP expires at:", bangladeshExpireTime);

    const hash = await bcrypt.hash(password, 10);
    const user = new authSchema({
      firstName,
      lastName,
      email,
      password: hash,
      otp,
      expireOtp,
    });

    const { secret, expiresIn } = jwtConfig();
    const token = jwt.sign(
      {
        id: user._id,
        email: user.email,
      },
      secret,
      { expiresIn },
    );
    user.token = token;
    await user.save();
    emailVerification(email, otp);

    return res.json({ message: "User registered successfully", user });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

// ============ Login Controller =================
const LoginController = async (req, res) => {
  const { email, password } = req.body;

  if (!email) {
    return res.json({ message: "Error: Email Required" });
  }

  if (!password) {
    return res.json({ message: "Error: Password Required" });
  }

  if (!emailValidation(email)) {
    return res.json({
      message: "Error: Email Formate Is not Correct ",
    });
  }

  const existingUser = await authSchema.findOne({ email });
  if (!existingUser) {
    return res.json({ message: "Error: User Not Found" });
  }

  if (!existingUser.isVerified) {
    return res.json({ message: "Error: User Not Verified" });
  }

  const matchPassword = await bcrypt.compare(password, existingUser.password);
  if (!matchPassword) {
    return res.json({ message: "Error: Incorrect Password" });
  }

  return res.json({
    message: "Login in Successfully",
  });
};

// ============ LogOut Controller =================
const LogOutController = (req, res) => {
  return res.json({ message: "Logged out successfully" });
};

// ============ Dashboard Controller =================
const DashboardController = (req, res) => {
  return res.json({ message: "Access Denied" });
};

module.exports = {
  SignUpController,
  LoginController,
  LogOutController,
  DashboardController,
};
