const authSchema = require("../model/authSchema");
const crypto = require("crypto");

const InitialOtpController = async (req, res) => {
  const { email, otp } = req.body;
  const user = await authSchema.findOne({ email });
  if (!user) {
    return res.status(400).json({
      message: "User Not Found",
    });
  }
  if (user.isVerified) {
    return res.json({
      message: "User Is Verified",
    });
  }
  if (user.otp !== otp || user.expireOtp < Date.now()) {
    return res
      .status(400)
      .json({ message: "Invalid OTP. Please Input Correct OTP" });
  }
  user.isVerified = true;
  user.otp = undefined;
  user.expireOtp = undefined;
  await user.save();
  res.status(200).json({
    message: "Email Verification Done",
  });
};

const ResendOtpController = async (req, res) => {
  const { email } = req.body;
  const user = await authSchema.findOne({ email });
  // Check if user exists
  if (!user) {
    return res.status(400).json({ message: "Error: User Not Found" });
  }
  // Check if user is already verified
  if (user.isVerified) {
    return res.status(400).json({ message: "Error: Email already verified" });
  }
  // Check if OTP is not Expired Yet. Then Don't Generate New OTP
  if (user.expireOtp && user.expireOtp > Date.now()) {
    return res.status(400).json({
      message:
        "Error: OTP is still valid. Please wait for it to expire before requesting a new one.",
    });
  }
  // Only send new OTP if user is not verified and OTP is expired
  const otp = crypto.randomInt(100000, 999999).toString();
  const expireOtp = Date.now() + 5 * 60 * 1000; // 5 minutes
  user.otp = otp;
  user.expireOtp = expireOtp;
  await user.save();
  await emailVerification(email, otp, true);
  res.status(200).json({
    message: "OTP Resend Successfully",
  });
};

module.exports = { InitialOtpController, ResendOtpController };
