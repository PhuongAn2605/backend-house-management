const express = require("express");
const { check } = require("express-validator");

const userControllers = require("../controllers/user.controllers");

const router = express.Router();

router.post(
  "/signup",
  [
    check("userName").not().isEmpty(),
    check("password")
      .isLength({ min: 8, max: 15 })
      // .custom(
      //   /^(?=.*?[A-Z])(?=(.*[a-z]){1,})(?=(.*[\d]){1,})(?=(.*[\W]){1,})(?!.*\s).{8,}$/
      // ),
  ],
  userControllers.signup
);

router.post(
  "/login",
  [
    check("userName").not().isEmpty(),
    check("password").not().isEmpty(),
  ],
  userControllers.login
);

router.get("/logout", userControllers.logout);

router.post('/check-password', userControllers.checkPasswordUnique);

module.exports = router;
