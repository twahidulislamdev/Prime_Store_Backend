const express = require("express");
const { SignUpController, LoginController, LogOutController, DashboardController } = require("../../controllers/authController");
const { InitialOtpController } = require("../../controllers/otpController");
const router = express.Router();

router.post("/signup", SignUpController);
router.post("/login", LoginController);
router.post("/logout", LogOutController);
router.get("/dashboard", DashboardController);
router.post("/otpverification", InitialOtpController);


// router.get("/login", (req, res) => {
//   res.send("Data Ache");
// });

module.exports = router;
