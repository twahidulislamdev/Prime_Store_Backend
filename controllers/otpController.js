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
    return res.status(400).json({ message: "Invalid OTP. Please Input Correct OTP" });
  }
  user.isVerified = true;
  user.otp = undefined;
  user.expireOtp = undefined;
  await user.save();
  res.status(200).json({
    message: "Email Verification Done",
  });
};

const ResendOtpController = () =>{

}

module.exports = {InitialOtpController}