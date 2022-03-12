require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded( {extended: true} ));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect(process.env.URL_DB);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: [String]
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//mongoose will encrypt when we save to DB. and decrypt when read from DB.

const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username, name: user.name });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    //console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/",(req,res)=>{
  res.render('home');
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication.
    res.redirect('/secrets');
  });

app.get("/login",(req,res)=>{
  res.render('login');
});

app.get("/register",(req,res)=>{
  res.render('register');
});

app.get("/secrets", (req,res)=> {
  if(req.isAuthenticated()){
    User.find({"secret": {$ne: null}},(err,foundUsers)=>{
      if (err){
        console.log(err);
      }else {
        if(foundUsers){
          res.render("secrets",{usersWithSecrets: foundUsers});
        }
      }
    });
  } else {
    res.redirect("/login");
  }


});

app.get("/submit", (req,res)=> {
  if (req.isAuthenticated()){
    res.render("submit");
  }else {
    res.redirect("/login");
  }
});

app.get("/logout", (req,res)=> {
  req.logout();
  res.redirect("/");
});


app.post("/register", (req,res)=> {
  User.register({username: req.body.username}, req.body.password, (err,user)=>{
    if (err) {
      console.log(err);
      res.redirect("/register");
    }else {
      passport.authenticate("local")(req, res, ()=> {
        res.redirect("/secrets");
      })
    }
  })

});


app.post('/login', passport.authenticate('local', {
  successRedirect: '/secrets',
  failureRedirect: '/login'
}));


app.post("/submit", (req,res)=> {
  const submittedSecret = req.body.secret;

  //console.log(req.user.id);

  User.findById(req.user.id, (err, foundUser)=> {
    if (err){
      console.log(err);
    }else {
      if (foundUser){
        foundUser.secret.push(submittedSecret);
        foundUser.save().then(()=>{
          res.redirect("/secrets");
        });
      }
    }
  });
});


let port = process.env.PORT;
if(port== null || port==""){
  port=3000;
}

app.listen(port,()=> {
  console.log("Server has started successfully");
});
