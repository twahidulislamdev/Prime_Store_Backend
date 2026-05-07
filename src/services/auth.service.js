const crypto = require("crypto");
const bcrypt = require("bcrypt");
const { jwtConfig } = require("../config/jwt");
const UserSchema = require("../models/auth.model");
const Session = require("../models/session.model");
const emailVerification = require("../services/email.service");
const {
  generateAccessToken,
  generateRefreshToken,
} = require("../utils/token.utils");

// ================= SIGNUP =================
const SignUpService = async ({ firstName, lastName, email, password }) => {
  // Check Required Fields
  if (!firstName)
    return { error: true, status: 400, message: "Error: First Name Required" };
  if (!lastName)
    return { error: true, status: 400, message: "Error: Last Name Required" };
  if (!email)
    return { error: true, status: 400, message: "Error: Email Required" };
  if (!password)
    return { error: true, status: 400, message: "Error: Password Required" };

  // Check Duplicate Email In Database
  const duplicateEmail = await UserSchema.findOne({ email });
  if (duplicateEmail)
    return { error: true, status: 409, message: "Email Already Exists" };

  // Generate OTP Using Crypto
  const otp = crypto.randomInt(100000, 999999).toString();
  const expireOtp = new Date(Date.now() + 5 * 60 * 1000);

  // Hash Password Using Bcrypt
  const hash = await bcrypt.hash(password, 10);
  const user = new UserSchema({
    firstName,
    lastName,
    email,
    password: hash,
    otp,
    expireOtp,
  });

  // Generate New Tokens For SignUp User
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  // Hash Refresh Token For Security
  const refreshTokenHash = await bcrypt.hash(refreshToken, 10);

  // Send OTP to User Email
  emailVerification(email, otp);

  // Set Token To User
  user.accessToken = accessToken;
  user.refreshToken = refreshTokenHash;

  // Save User
  await user.save();
  return { error: false, user, refreshToken };
};

// ================= LOGIN =================
const LoginService = async ({ email, password }, { ip, userAgent }) => {
  const user = await UserSchema.findOne({ email });
  if (!user) return { error: true, status: 404, message: "User not found" };

  // Compare Password
  const match = await bcrypt.compare(password, user.password);
  if (!match) return { error: true, status: 400, message: "Wrong password" };

  // Revoke old sessions (so old tokens become invalid)
  await Session.updateMany(
    { user: user._id, revoked: false },
    { $set: { revoked: true } },
  );

  // Generate New Tokens For Login User
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  // Hash Refresh Token For Security
  const refreshTokenHash = await bcrypt.hash(refreshToken, 10);

  // Create Session For User Login
  const session = new Session({
    user: user._id,
    ip,
    revoked: false,
    refreshToken: refreshTokenHash,
    userAgent,
  });
  await session.save();

  // Set New Tokens To User
  user.accessToken = accessToken;
  user.refreshToken = refreshTokenHash;

  // Save User
  await user.save();
  return { error: false, user, refreshToken };
};

// ================= REFRESH TOKEN =================
const RefreshTokenService = async ({ req, res }) => {
  const refreshToken = req.headers.authorization?.split(" ")[1];
  if (!refreshToken)
    return { error: true, status: 401, message: "Refresh Token Is Not Found" };

  let decoded;
  try {
    decoded = jwt.verify(refreshToken, jwtConfig().secret);
  } catch {
    return {
      error: true,
      status: 401,
      message: "Invalid Or Expired Refresh Token",
    };
  }

  const user = await UserSchema.findById(decoded.id);
  if (!user) return { error: true, status: 404, message: "User not found" };

  // Find all active login sessions for this user
  const sessions = await Session.find({ user: user._id, revoked: false });

  // Check which session matches this specific refresh token
  let session = null;
  for (const s of sessions) {
    const match = await bcrypt.compare(refreshToken, s.refreshToken);
    if (match) {
      session = s;
      break;
    }
  }

  // If no matching session is found, they were logged out or the token was revoked
  if (!session)
    return {
      error: true,
      status: 404,
      message: "Invalid Or Expired Refresh Token",
    };

  // Token Rotation
  const accessToken = generateAccessToken(user);
  const newRefreshToken = generateRefreshToken(user);

  // Hash the new refresh token
  const newRefreshTokenHash = await bcrypt.hash(newRefreshToken, 10);

  // Update the session in the database with the new refresh token
  session.refreshToken = newRefreshTokenHash;
  await session.save();

  // Update the user's latest tokens in their database record
  user.accessToken = accessToken;
  user.refreshToken = newRefreshTokenHash;
  await user.save();

  // Return the new tokens back to the user
  return { error: false, accessToken, newRefreshToken };
};

// ================= LOGOUT =================
const LogOutService = async (refreshToken) => {
  if (!refreshToken)
    return { error: true, status: 401, message: "Refresh Token Is Required" };

  let decoded;
  try {
    decoded = jwt.verify(refreshToken, jwtConfig().secret);
  } catch {
    return { error: true, status: 401, message: "Invalid Refresh Token" };
  }

  const sessions = await Session.find({ user: decoded.id, revoked: false });

  let currentSession = null;

  for (const session of sessions) {
    const match = await bcrypt.compare(refreshToken, session.refreshToken);
    if (match) {
      currentSession = session;
      break;
    }
  }

  if (!currentSession)
    return { error: true, status: 404, message: "Session Not Found" };

  currentSession.revoked = true;
  await currentSession.save();

  return { error: false, message: "Logout Successful" };
};

// ================= LOGOUT From All Devices =================
const LogOutAllService = async ({ cookieRefreshToken, authHeader }) => {
  let userId = null;

  if (cookieRefreshToken) {
    try {
      const decoded = jwt.verify(cookieRefreshToken, jwtConfig().secret);
      if (decoded?.id) userId = decoded.id;
    } catch (_) {}
  }

  if (!userId) {
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return {
        error: true,
        status: 401,
        message: "Authentication Required",
      };
    }

    const token = authHeader.split(" ")[1];

    try {
      const decoded = jwt.verify(token, jwtConfig().secret);
      userId = decoded.id;
    } catch {
      return {
        error: true,
        status: 401,
        message: "Invalid Or Expired Access Token",
      };
    }
  }

  await Session.updateMany(
    { user: userId, revoked: false },
    { $set: { revoked: true } },
  );

  await UserSchema.findByIdAndUpdate(userId, {
    $set: { accessToken: "", refreshToken: "" },
  });

  return { error: false, message: "Logout From All Devices Successful" };
};

// ================= VERIFY OTP =================
const VerifyOtpService = async ({ email, otp }) => {
  const user = await UserSchema.findOne({ email });

  if (!user) return { error: true, status: 400, message: "User Not Found" };

  if (user.isVerified)
    return { error: true, status: 400, message: "User Already Verified" };

  if (user.otp !== otp || user.expireOtp < Date.now()) {
    return {
      error: true,
      status: 400,
      message: "Incorrect OTP or Expired OTP",
    };
  }

  user.isVerified = true;
  user.otp = undefined;
  user.expireOtp = undefined;

  await user.save();

  return { error: false, message: "Email Verified Successfully" };
};

// ================= RESEND OTP =================
const ResendOtpService = async ({ email }) => {
  const user = await UserSchema.findOne({ email });

  if (!user) return { error: true, status: 400, message: "User Not Found" };

  if (user.isVerified)
    return { error: true, status: 400, message: "Email Already Verified" };

  if (user.expireOtp && user.expireOtp > Date.now()) {
    return {
      error: true,
      status: 400,
      message: "Wait 5 minutes before requesting new OTP",
    };
  }

  const otp = crypto.randomInt(100000, 999999).toString();

  user.otp = otp;
  user.expireOtp = Date.now() + 5 * 60 * 1000;

  await user.save();

  await emailVerification(email, otp, true);

  return {
    error: false,
    message: "New OTP Sent Successfully",
  };
};

module.exports = {
  SignUpService,
  LoginService,
  RefreshTokenService,
  LogOutService,
  LogOutAllService,
  VerifyOtpService,
  ResendOtpService,
};
