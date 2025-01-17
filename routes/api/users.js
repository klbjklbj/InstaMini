const express = require("express");
const router = express.Router();
// bring in User model
const User = require("../../models/User");
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const keys = require("../../config/keys");
const passport = require("passport");
const validateRegisterInput = require("../../validation/register");
const validateLoginInput = require("../../validation/login");


// @route   POST api/users/register
// @desc    Register a user
// @access  Public

// This route below is called when user hits submit button
// Express is already set up in server.js to use bodyParser in json format so req will already be parsed as key value pair
// findOne is built in function of MongoDb
// User refers to User table, email is column in schema
// req is what user is sending
// Then and catch are promise statement, not like if and else
router.post("/register", (req, res) => {
  // first validate user input
  const { errors, isValid } = validateRegisterInput(req.body);
  if (!isValid) {
    return res.status(400).json(errors);
  }
  User.findOne({ email: req.body.email })
    .then(user => {
      if (user) {
        errors.email = "Email already exists"
        return res.status(400).json(errors);
      } else {
        // based on gravatar's api (url function, s,r,d, etc.)
        // gravatar uses user email to provide gravatar image
        const profilePicture = gravatar.url(req.body.email, {
          s: "200",
          r: "pg",
          d: "mm"
        });
        // building new user object to write to database
        const newUser = new User({
          name: req.body.name,
          email: req.body.email,
          // profilePicture uses deconstruction since column and variable name are same
          profilePicture,
          password: req.body.password
        });
        // bcrypt has genSalt function
        // 10 (default) is for rounds, err & salt are parameters for callback function
        bcrypt.genSalt(10, (err, salt) => {
          if (err) throw err;
          // bcrypt hash takes in two parameters (password and salt) and callback (asynchronous function)
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) throw err;
            // put new hashed password as user password in database
            newUser.password = hash;
            newUser
              .save() //mongoose feature
              .then(user => res.json(user))
              .catch(err => console.log(err));
          });
        });
      }
    })
    .catch(err => console.log(err));
});

// @route   POST api/users/login
// @desc    Login as user
// @access  Public

router.post("/login", (req, res) => {
  const { errors, isValid } = validateLoginInput(req.body);
  if (!isValid) {
    return res.status(400).json(errors);
  }

  const email = req.body.email;
  const password = req.body.password;

  User.findOne({ email })
    .then(user => {
      if (!user) {
        errors.email = "User not found";
        return res.status(404).json(errors);
      }

      // bcrypt helps in encryption pf password in login and
      // compare the password in login with the password(encrypted password) in User table.
      bcrypt
        .compare(password, user.password)
        //compare function gives a boolean which comes to isMatch.
        .then(isMatch => {
          if (!isMatch) {
            errors.password = "password doesnot match";
            return res.status(400).json(errors);
          }

          const payload = {
            id: user.id,
            name: user.name,
            profilePicture: user.profilePicture
          };
          //token is in the form of garbage set of characters.
          //each token is unique based on the combinations of data(id,name and avatar) in payload.
          // token helps in authentication without compromising the PII.
          jwt.sign(
            payload,
            keys.secretOrKey,
            { expiresIn: 3600 },
            (err, token) => {
              if (err) throw err;
              return res.json({
                success: true,
                token: "Bearer " + token
              });
            }
          );
        })
        .catch(err => console.log(err));
    })
    .catch(err => console.log(err));
});

// Passport is Builtin library that helps to authenticate  whether the token is valid and decrypt the token.
//passport is intialized in server.js
// @route   GET api/users/current
// @desc    return current user
// @access  Private

router.get(
  "/current",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    res.json({
      //passport sends back the following info from MongoDb:
      id: req.user.id,
      email: req.user.email,
      name: req.user.name
    });
  }
);

module.exports = router;