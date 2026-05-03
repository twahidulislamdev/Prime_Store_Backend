const authSchema = require("../model/authSchema");
const crypto = require("crypto");
const emailVerification = require("../helpers/emailVerification");

const VerifyOtpController = async (req, res) => {
  const { email, otp } = req.body;
  const user = await authSchema.findOne({ email });
  if (!user) {
    return res.status(400).json({
      message: "User Not Found",
    });
  }
  if (user.isVerified) {
    return res.json({
      message: "User Already Verified",
    });
  }
  if (user.otp !== otp || user.expireOtp < Date.now()) {
    return res.status(400).json({ message: "Incorrect OTP or Expired OTP" });
  }
  user.isVerified = true;
  user.otp = undefined;
  user.expireOtp = undefined;
  await user.save();
  res.status(200).json({
    message: "Email Verified Successfully",
  });
};

const ResendOtpController = async (req, res) => {
  const { email } = req.body;
  const user = await authSchema.findOne({ email });
  // Check if user exists
  if (!user) {
    return res.status(400).json({ message: "User Not Found" });
  }
  // Check if user is already verified
  if (user.isVerified) {
    return res.status(400).json({ message: "Email Already Verified" });
  }
  // Check if OTP is not Expired Yet. Then Don't Generate New OTP
  if (user.expireOtp && user.expireOtp > Date.now()) {
    return res.status(400).json({
      message:
        "Error: We already sent you an OTP. Please wait 5 minutes before resending another one.",
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
    message: "New OTP Has Been Sent To Your Email Successfully",
  });
};
module.exports = { VerifyOtpController, ResendOtpController };
