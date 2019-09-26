// library that identifies jwt tokens
const JwtStrategy = require("passport-jwt").Strategy;
// libary that extracts token from request (decodes token)
const ExtractJwt = require("passport-jwt").ExtractJwt;
const mongoose = require("mongoose");
// passport is to decrypt token and extract payload (user info) which is found in User model so bring in User model
const User = mongoose.model("users");
// get secret key that passport needs to use
const keys = require("./keys");

const opts = {};
// way of adding key to opts object
// method that finds bearer token from request header and extracts it
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = keys.secretOrKey;

module.exports = passport => {
  // tell passport to use following
  passport.use(
    // need to tell JwtStrategy 1)where to get token from (Auth Header) and 2)where to find the key
    //then pass in callback
    new JwtStrategy(opts, (payload, done) => {
      console.log(payload);
    })
  );
};
