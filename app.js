require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const app = express();
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')
// const md5 = require("md5");
// const encrpyt= require("mongoose-encryption");
// const bcrypt= require("bcrypt");
// const saltRounds=10;

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({
  secret: "This is a long secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false, useCreateIndex: true });

const userSchema=new mongoose.Schema({
  email:String,
  password:String,
  googleId: String,
  secret: String
});


// userSchema.plugin(encrpyt,{secret:process.env.SECRET, encryptedFields: ["password"]});
//always add plugin state before creating mongoose model

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("user",userSchema);
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req,res){
  res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

  app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect to secrets.
      res.redirect('/secrets');
    });

app.get("/login", function(req,res){
  res.render("login");
});

app.post("/login", function(req,res){

  const newUser= new User({
    username:req.body.username,
    passport:req.body.password
  });

  req.login(newUser, function(err){
    if(!err){
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
      }

    });
});

app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
});

app.get("/register", function(req,res){
  res.render("register");
});

app.get("/secrets", function(req,res){
  User.find({"secret":{$ne:null}}, function(err,foundUser){
    if(!err){
      if(foundUser){
        res.render("secrets", {userWithSecrets: foundUser});
      }
    }
  });
});

app.post("/register", function(req,res){
  User.register({username: req.body.username, active: false}, req.body.password, function(err, user) {
  if (err) {
    console.log(err);
    res.redirect("/register");
  }else{
    passport.authenticate("local")(req,res,function(){
      res.redirect("/secrets");
    });
  }

  // var authenticate = User.authenticate();
  // authenticate('username', 'password', function(err, result) {
  //   if (err) { ... }
  //
  //   // Value 'result' is set to false. The user could not be authenticated since the user is not active
  // });
});
});

app.get("/submit", function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
});


app.post("/submit", function(req,res){
  const submittedSecret= req.body.secret;
  User.findById(req.user.id,function(err, foundUser){
    if(!err){
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});
// app.post("/submit",functin(req,res){
//   const submittedSecret= req.body.secret;
// });

///////////////////////////////////////////////////////////////////////////////


app.listen(3000, function() {
  console.log("Server started on port 3000");
});
