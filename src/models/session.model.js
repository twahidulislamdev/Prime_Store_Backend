const mongoose = require("mongoose");

const sessionSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "user",
      required: [true, "User ID Required"],
    },
    ip: {
      type: String,
      required: [true, "Ip Address Is Required"],
    },
    revoked: {
      type: Boolean,
      default: false,
    },
    userAgent: {
      type: String,
      required: [true, "User Agent Is Required"],
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
    refreshToken: {
      type: String,
      required: [true, "Refresh Token Hash Is Required"],
    },
  },
  { timestamps: true },
);
module.exports = mongoose.model("session", sessionSchema);
