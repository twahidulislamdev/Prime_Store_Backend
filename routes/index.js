const express = require("express");
const router = express.Router();
const apiRoute = require("./api");

router.use("/v1", apiRoute);

module.exports = router;
