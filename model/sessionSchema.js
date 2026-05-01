const express = require("express");
const mongoose = require("mongoose");

const sessionSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "user",
      required: [true, "User ID Required"],
    },
    refreshToken: {
      type: String,
      required: [true, "Refresh Token Hash Is Required"],
    },
    ip: {
      type: String,
      required: [true, "Ip Address Is Required"],
    },
    userAgent: {
      type: String,
      required: [true, "User Agent Is Required"],
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
    revoked: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true },
);
module.exports = mongoose.model("session", sessionSchema);
