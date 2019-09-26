const express = require("express");
const router = express.Router();
// bring in User model
const User = require("../../models/User");
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const keys = require("../../config/keys");
const passport=require('passport');

// @route   POST api/users/register
// @desc    Register a user
// @access  Public

// This route below is called when user hits submit button
// Express is already set up in server.js to use bodyParser in json format
// So, req will already be parsed as key value pair
// findOne is built in function of MongoDb
// User refers to User table, email is column in schema
// req is what user is sending
// Then and catch are promise statement, not like if and else
router.post("/register", (req, res) => {
  User.findOne({ email: req.body.email })
    .then(user => {
      if (user) {
        return res.status(400).json({
          email: "Email already exists"
        });
      } else {
        // based on gravatar's api (url function, s,r,d, etc.)
        // gravatar uses user email to provide gravatar image
        const avatar = gravatar.url(req.body.email, {
          s: "200",
          r: "pg",
          d: "mm"
        });
        // building new user object to write to database
        const newUser = new User({
          name: req.body.name,
          email: req.body.email,
          // avatar uses deconstruction since column and variable name are same
          avatar,
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
// @desc    Login user / return JWT token
// @access  Public

router.post("/login", (req, res) => {
  //parameters are email and password
  const email = req.body.email;
  const password = req.body.password;

  // Find user by email
  User.findOne({ email })
    // what is returned from findOne is put in variable called user
    .then(user => {
      if (!user) {
        return res.status(404).json({
          email: "User not found"
        });
      }
      // compare plain text password to encrypted password using bcrypt's compare function
      bcrypt
        .compare(password, user.password)
        // whatever is output of previous function is put in variable
        // create variable isMatch for boolean that bcrypt.compare function returns
        .then(isMatch => {
          if (!isMatch) {
            return res.status(400).json({
              // msg is for password field
              password: "Password does not match"
            });
          }
          // for user match
          const payload = {
            id: user.id,
            name: user.name,
            avatar: user.avatar
          };
          // create token
          // sign function takes in payload and key to generate token
          // also takes in expiry time in seconds
          // more options in payload make stronger token
          // secretOrKey is from config/keys
          // jwt.sign is older function that doesn't support promise statements so we're doing a callback (4th parameter below)
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

// @route   GET api/users/current
// @desc    return current user's info
// @access  Private

router.get(
  '/current',
  //private route so bring in passport as 2nd parameter
  passport.authenticate('jwt',{session: false}),
  (req, res)=>{
    res.json({msg: "Success"});
  });

module.exports = router;
