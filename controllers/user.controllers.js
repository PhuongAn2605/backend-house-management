const { validationResult } = require("express-validator");
const isEmpty = require("is-empty");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const HttpError = require("../models/http-error");
const User = require("../models/User");
const House = require("../models/House");
const Product = require("../models/Product");
const { houseLike } = require("./houseLike.controllers");
const LoginHistory = require("../models/LoginHistory");

const signup = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log(errors);
    return next(
      res.status(422).json({message: "Invalid inputs passed, please check your data!"})
      // new HttpError("Invalid inputs passed, please check your data!", 422)
    );
  }

  const { userName, password } = req.body;
  let existingUser;
  let newUser;
  let saveUser;
  let token;
  let hashedPassword;

  try {
    existingUserName = await User.findOne({ userName: userName });
    if (!isEmpty(existingUserName)) {
      return res.status(422).json({message: "User exists already, please login instead"});
    }

    const existingPassword = await User.findOne({ password: password });
    if (!isEmpty(existingPassword)) {
      return res.status(403).json({message: "Password is taken, please try another password"});
    }

    if (
      password.match(
        /^(?=.*?[A-Z])(?=(.*[a-z]){1,})(?=(.*[\d]){1,})(?=(.*[\W]){1,})(?!.*\s).{8,15}$/
      )
    ) {
      hashedPassword = await bcrypt.hash(password, 12);
      if (isEmpty(hashedPassword)) {
        return next(new HttpError("Could not encrypt the password", 422));
      }

      newUser = new User({
        userName,
        // password: password,
        password: hashedPassword
      });
      saveUser = await newUser.save();
    } else {
      return res.status(422).json({message: "Wrong password!"});
      // return next(new HttpError("Wrong password!", 422));
    }

    if (isEmpty(saveUser)) {
      return res.status(500).json({message: "Can not save the user!"});

      // return next(new HttpError("Can not save the user", 500));
    }

    const newHouse = new House({
      name: userName + "'s house",
      userId: saveUser._id,
      products: [],
      comments: []
    });

    const saveHouse = newHouse.save();
    if (isEmpty(saveHouse)) {
      // return next(new HttpError("Can not create a house for the user!", 500));
      return res.status(500).json({message: "Can not create a house for the user!"});

    }

    token = jwt.sign(
      {
        userName: newUser.userName,
      },
      "supersecret_dont_share",
      { expiresIn: "1h" }
    );
    if (isEmpty(token)) {
      return res.status(500).json({message: "Could not set token!"});

      // return next(new HttpError("Could not set token", 500));
    }
  } catch (err) {
    console.log(err);
    // const error = new HttpError("Sign up failed, please try again!", 500);
    return res.status(500).json({message: "Sign up failed, please try again!"})
    // return next(error);
  }

  res.status(201).json({ userName: newUser.userName, token: token, message: 'Signed you up!' });
};

const login = async (req, res, next) => {
  const errors = validationResult(req);
  let token;

  if (!errors.isEmpty()) {
    // return next(
    //   new HttpError("Invalid inputs passed, please check your data!", 422)
    // );
    return res.status(422).json({message: "Invalid inputs passed, please check your data!"})

  }

  const { userName, password } = req.body;

  let existingUser;
  let houseOfUser;
  let productsOfHouse = [];
  let houseLikes = [];
  let comments = [];
  let loginTracker;

  try {
    existingUser = await User.findOne({
      userName: userName,
      // password: password,
    });
    if (isEmpty(existingUser)) {
      return res.status(404).send({message: "Could not find the user"});
    }


    const isValidPassword = await bcrypt.compare(password, existingUser.password);
    if(!isValidPassword){
      return res.status(403).send({message: "Invalid credentials, could not log you in."});
    }

    const userId = existingUser._id;
    houseOfUser = await House.findOne({ userId: userId });
    const productOfHouseIds = houseOfUser.products;
    for (p of productOfHouseIds) {
      const product = await Product.findById(p);
      productsOfHouse.push(product);
    }

    houseLikes = await houseOfUser.populate('houseLikes');
    comments = await houseOfUser.populate('comments');
    const loginHistories = await LoginHistory.find({ userId: userId });

    loginTracker = new LoginHistory({
      userId,
      loginNo: loginHistories.length + 1
    });

    await loginTracker.save();

    token = jwt.sign(
      { userName: existingUser.userName },
      "supersecret_dont_share",
      { expiresIn: "1h" }
    );
  } catch (err) {
    console.log(err);
    // return next(new HttpError("Logging in failed, please try again", 500));
    return res.status(500).send({message: "Logging in failed, please try again"});

  }

  res
    .cookie("access_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
    })
    .status(200)
    .json({
      userName: existingUser.userName,
      userId: existingUser._id,
      password: existingUser.password,
      token: token,
      houseId: houseOfUser._id,
      products: productsOfHouse,
      houseLikes: houseLikes.houseLikes,
      comments: comments.comments,
      loginTracker,
      message: 'Logined you in!'
    });
};

const logout = async (req, res, next) => {
  return res
    .clearCookie("access_token")
    .status(200)
    .json({ message: "Successfully logged out!" });
};

const checkPasswordUnique = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(new HttpError("Invalid data passed", 422));
  }

  const { password } = req.body;
  if (isEmpty(password)) {
    return next(new HttpError("Empty password", 422));
  }

  try {
    const existingPassword = User.findOne({ password: password });
    if (!isEmpty(existingPassword)) {
      return next(new HttpError("Password is taken", 422));
    }
  } catch (err) {
    return next(new HttpError("Something went wrong", 500));
  }
  res.status(200).json({ password });
};

exports.signup = signup;
exports.login = login;
exports.logout = logout;
exports.checkPasswordUnique = checkPasswordUnique;
