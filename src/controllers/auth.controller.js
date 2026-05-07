const {
  SignUpService,
  VerifyOtpService,
  ResendOtpService,
  LoginService,
  RefreshTokenService,
  LogOutService,
  LogOutAllService,
} = require("../services/auth.service");

// ============ SignUp Controller =================
const SignUp = async (req, res) => {
  try {
    const result = await SignUpService(req.body);
    if (result.error) {
      return res.status(result.status).json({ message: result.message });
    }
    res.cookie("refreshToken", result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return res
      .status(201)
      .json({ message: "User registered successfully", user: result.user });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

// ============ Login Controller =================
const Login = async (req, res) => {
  try {
    const result = await LoginService(req.body, {
      ip: req.ip,
      userAgent: req.get("User-Agent"),
    });
    if (result.error) {
      return res.status(result.status).json({ message: result.message });
    }
    res.cookie("refreshToken", result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return res
      .status(200)
      .json({ message: "Login successful", user: result.user });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
};

// ============ Refresh Token Controller =================
const RefreshToken = async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
    const result = await RefreshTokenService(refreshToken);
    if (result.error) {
      return res.status(result.status).json({ message: result.message });
    }
    res.cookie("refreshToken", result.newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return res.status(200).json({
      message: "Access Token Refreshed Successfully",
      accessToken: result.accessToken,
    });
  } catch (error) {
    return res
      .status(401)
      .json({ message: "Invalid Or Expired Refresh Token" });
  }
};

// ============ LogOut Controller =================
const LogOut = async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
    const result = await LogOutService(refreshToken);
    if (result.error) {
      return res.status(result.status).json({ message: result.message });
    }
    res.clearCookie("refreshToken");
    return res.status(200).json({ message: result.message });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

// ============ LogOut All Devices Controller =================
const LogOutAll = async (req, res) => {
  try {
    const result = await LogOutAllService({
      cookieRefreshToken: req.cookies?.refreshToken,
      authHeader: req.headers.authorization,
    });
    if (result.error) {
      return res.status(result.status).json({ message: result.message });
    }
    res.clearCookie("refreshToken");
    return res.status(200).json({ message: result.message });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};
// ============ Verify OTP Controller =================
const VerifyOtp = async (req, res) => {
  try {
    const result = await VerifyOtpService(req.body);
    if (result.error) {
      return res.status(result.status).json({ message: result.message });
    }
    return res.status(200).json({ message: result.message });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

// ============ Resend OTP Controller =================
const ResendOtp = async (req, res) => {
  try {
    const result = await ResendOtpService(req.body);
    if (result.error) {
      return res.status(result.status).json({ message: result.message });
    }
    return res.status(200).json({ message: result.message });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

module.exports = {
  SignUp,
  Login,
  RefreshToken,
  LogOut,
  LogOutAll,
  VerifyOtp,
  ResendOtp,
};
