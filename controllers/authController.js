const authSchema = require("../model/authSchema");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const emailVerification = require("../helpers/emailVerification");
const emailValidation = require("../helpers/emailValidation");
const jwt = require("jsonwebtoken");
const { jwtConfig } = require("../config/config");
const Session = require("../model/sessionSchema");

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
    // Generate OTP
    const otp = crypto.randomInt(100000, 999999).toString();
    const now = new Date();
    const expireOtp = new Date(now.getTime() + 5 * 60 * 1000);

    // Convert OTP Expiration Time to Bangladesh Time
    const bangladeshExpireTime = expireOtp.toLocaleString("en-US", {
      timeZone: "Asia/Dhaka",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: true,
    });
    console.log("OTP expires at:", bangladeshExpireTime);

    // Hash Password using bcrypt
    const hash = await bcrypt.hash(password, 10);
    const user = new authSchema({
      firstName,
      lastName,
      email,
      password: hash,
      otp,
      expireOtp,
    });

    // Generate Access Token
    const { secret } = jwtConfig();
    const accessToken = jwt.sign(
      {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
      },
      secret,
      { expiresIn: "15m" },
    );

    // Generate Refresh Token
    const refreshToken = jwt.sign({ id: user._id }, secret, {
      expiresIn: "7d",
    });

    // Store Refresh Token In Database
    const refreshTokenHash = await bcrypt.hash(refreshToken, 10);
    // Create Session when User Sign Up
    const session = new Session({
      user: user._id,
      ip: req.ip,
      refreshToken: refreshTokenHash,
      userAgent: req.get("User-Agent"),
    });
    await session.save();
    // Store Refresh Token In Cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    // Send Verification Email With OTP
    emailVerification(email, otp);
    user.token = accessToken;
    await user.save();
    return res
      .status(201)
      .json({ message: "User registered successfully", user });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

// =========== Verify AccessToken Controller  =================
const VerifyTokenController = (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, jwtConfig().secret);
    return res.json({
      message: "User Data Retrieved Successfully",
      user: decoded,
    });
  } catch (error) {
    return res.status(401).json({ message: "Invalid Or Expired Token" });
  }
};

// ======= Ganerate Anothe  Access Token  Using  Refresh Token ======
const RefreshTokenController = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ message: "Refresh Token Is Not Found" });
    }

    const decoded = jwt.verify(refreshToken, jwtConfig().secret);
    const user = await authSchema.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    // Generate Another Access Token
    const accessToken = jwt.sign(
      {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
      },
      jwtConfig().secret,
      { expiresIn: "15m" },
    );

    //Generate a new Refresh Token whenever a user requests a new Access Token. Each Refresh Token can be used only once; after it is used, it becomes invalid. A new Refresh Token is Create with every Access Token.
    const newRefreshToken = jwt.sign({ id: user._id }, jwtConfig().secret, {
      expiresIn: "7d",
    });
    // Store New Refresh Token In Cookie
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // Update User Access Token
    user.token = accessToken;
    await user.save();
    return res.status(200).json({
      message: "Access Token Refreshed Successfully",
      accessToken,
    });
  } catch (error) {
    return res
      .status(401)
      .json({ message: "Invalid Or Expired Refresh Token" });
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

  const { secret } = jwtConfig();
  const accessToken = jwt.sign(
    {
      id: existingUser._id,
      firstName: existingUser.firstName,
      lastName: existingUser.lastName,
      email: existingUser.email,
      password: existingUser.password,
    },
    secret,
    { expiresIn: "15m" },
  );

  const refreshToken = jwt.sign({ id: existingUser._id }, secret, {
    expiresIn: "7d",
  });

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Strict",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  existingUser.token = accessToken;
  await existingUser.save();

  return res.status(200).json({
    message: "Login Successfully",
    accessToken,
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
  VerifyTokenController,
  RefreshTokenController,
  LoginController,
  LogOutController,
  DashboardController,
};
