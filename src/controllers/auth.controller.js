const User = require("../models/auth.model");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { jwtConfig } = require("../config/jwt");
const Session = require("../models/session.model");
const emailVerification = require("../services/email.service");


// ============ SignUp Controller =================
const SignUp = async (req, res) => {
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

    const duplicateEmail = await User.findOne({ email });
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
    // Create New User
    const user = new User({
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
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // Send Verification Email With OTP
    emailVerification(email, otp);
    user.refreshToken = refreshTokenHash;
    user.accessToken = accessToken;
    await user.save();
    return res
      .status(201)
      .json({ message: "User registered successfully", user });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

// =========== Verify AccessToken Controller  =================
const VerifyToken = (req, res) => {
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
const RefreshToken = async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ message: "Refresh Token Is Not Found" });
    }
    //  Decode Refresh Token
    const decoded = jwt.verify(refreshToken, jwtConfig().secret);
    // Find User By Id
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check Refresh Token Status Before Create Another Access Token
    const sessions = await Session.find({
      user: user._id,
      revoked: false,
    });

    let session = null;
    for (const s of sessions) {
      const match = await bcrypt.compare(refreshToken, s.refreshToken);
      if (match) {
        session = s;
        break;
      }
    }

    if (!session) {
      return res
        .status(404)
        .json({ message: "Invalid Or Expired Refresh Token" });
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

    //Generate a new Refresh Token whenever a user requests a new Access Token. Each Refresh Token
    //  can be used only once; after it is used, it becomes invalid. A new Refresh Token is Create
    //  with every Access Token.
    const newRefreshToken = jwt.sign({ id: user._id }, jwtConfig().secret, {
      expiresIn: "7d",
    });

    // Hash New Refresh Token
    const newRefreshTokenHash = await bcrypt.hash(newRefreshToken, 10);
    // Store New Refresh Token In Database
    session.refreshToken = newRefreshTokenHash;
    await session.save();

    // Store New Refresh Token In Cookie
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // Update User Access Token and Refresh Token
    user.accessToken = accessToken;
    user.refreshToken = newRefreshTokenHash;
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
const Login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ message: "Wrong password" });
    }

    // Generate Access Token when user login
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

    // Generate Refresh Token Immediately when user login to Create Refresh Token
    const refreshToken = jwt.sign({ id: user._id }, secret, {
      expiresIn: "7d",
    });

    // Store Refresh Token In Database
    const refreshTokenHash = await bcrypt.hash(refreshToken, 10);
    // Create Session when User Sign In
    const session = new Session({
      user: user._id,
      ip: req.ip,
      revoked: false,
      refreshToken: refreshTokenHash,
      userAgent: req.get("User-Agent"),
    });
    await session.save();

    // Update User Access Token and Refresh Token
    user.accessToken = accessToken;
    user.refreshToken = refreshTokenHash;
    await user.save();

    // Store Refresh Token In Cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      message: "Login successful",
      user,
    });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
};

// ============ LogOut Controller =================
const LogOut = async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({
        message: "Refresh Token Is Required",
      });
    }

    let decoded;
    try {
      decoded = jwt.verify(refreshToken, jwtConfig().secret);
    } catch (err) {
      return res.status(401).json({
        message: "Invalid Refresh Token",
      });
    }

    if (!decoded || !decoded.id) {
      return res.status(401).json({
        message: "Unauthorized",
      });
    }

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).json({
        message: "User Not Found",
      });
    }

    // Find matching session (hashed token)
    const sessions = await Session.find({
      user: decoded.id,
      revoked: false,
    });

    let currentSession = null;
    for (const session of sessions) {
      const match = await bcrypt.compare(refreshToken, session.refreshToken);
      if (match) {
        currentSession = session;
        break;
      }
    }

    if (!currentSession) {
      return res.status(404).json({
        message: "Session Not Found",
      });
    }

    // Revoke only this session
    currentSession.revoked = true;
    await currentSession.save();

    // Clear cookie
    res.clearCookie("refreshToken");

    return res.status(200).json({
      message: "Logout Successful",
    });
  } catch (error) {
    return res.status(500).json({
      error: error.message,
    });
  }
};

// ============ LogOut All Devices Controller =================
const LogOutAll = async (req, res) => {
  try {
    const secret = jwtConfig().secret;
    let userId = null;

    // Try refresh token from cookie first (long-lived, reliable)
    const cookieRefreshToken = req.cookies?.refreshToken;
    if (cookieRefreshToken) {
      try {
        const decoded = jwt.verify(cookieRefreshToken, secret);
        if (decoded?.id) {
          userId = decoded.id;
        }
      } catch (_) {}
    }

    // Fallback: try access token from Authorization header
    if (!userId) {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
          message:
            "Authentication Required. Provide a valid Bearer token or refresh token cookie.",
        });
      }

      const token = authHeader.split(" ")[1];
      try {
        const decoded = jwt.verify(token, secret);
        if (!decoded?.id) {
          return res.status(401).json({ message: "Unauthorized" });
        }
        userId = decoded.id;
      } catch (err) {
        return res.status(401).json({
          message: "Invalid Or Expired Access Token",
        });
      }
    }

    // Revoke ALL sessions for this user
    await Session.updateMany(
      { user: userId, revoked: false },
      { $set: { revoked: true } },
    );

    // Clear tokens stored in DB
    await User.findByIdAndUpdate(userId, {
      $set: {
        accessToken: "",
        refreshToken: "",
      },
    });

    // Clear refresh token cookie
    res.clearCookie("refreshToken");

    return res.status(200).json({
      message: "Logout From All Devices Successful",
    });
  } catch (error) {
    return res.status(500).json({
      error: error.message,
    });
  }
};

// ============ Dashboard Controller =================
const Dashboard = (req, res) => {
  return res.json({ message: "Access Denied" });
};

module.exports = {
  SignUp,
  VerifyToken,
  RefreshToken,
  Login,
  LogOut,
  LogOutAll,
  Dashboard,
};
