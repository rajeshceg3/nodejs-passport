const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser')
const passport = require('passport');
const session = require('express-session');
const JwtStrategy = require('passport-jwt').Strategy;
const PORT = 3000;
const jwtSecret = 'secret-key';
// Set up a temporary store for user data
// Later we'll hook it up to db
const users = new Map();

const app = express();
app.use(bodyParser.urlencoded({extended:false}))
app.use(session({
  secret : 'session-secret',
  resave : false,
  saveUninitialized : false
}))

const jwtStrategy = new JwtStrategy(
  {
    jwtFromRequest: (req) => req.headers.authorization,
    secretOrKey: jwtSecret,
  },
  (jwtPaylod, done) => {
    return done(null, {
      email: jwtPaylod.email,
      name: jwtPaylod.name,
    });
  }
);
passport.use(jwtStrategy);

app.use(passport.initialize());
app.use(passport.session());

function getUserDetails(email) {
  return users.get(email);
}

function credentialsValid(email, password, res) {
  if (!users.has(email)) {
    res.status(401).send(`Email ${email} is not registered`);
    return;
  }
  const userdetails = getUserDetails(email);
  return bcrypt.compareSync(password, userdetails.password);
}

passport.serializeUser((user, done) => {
  done(null, user.email);
});

passport.deserializeUser((email, done) => {
  return done(null, getUserDetails(email));
});

app.get('/login', (req, res) => {
  if (credentialsValid(req.body.email, req.body.password, res)) {
    // Create and provide jwt to user
    const jwt = jwt.sign(
      {
        email: req.body.email,
      },
      jwtSecret
    );
    return res.json({ jwt });
  }
  res.status(401).send('Invalid Credentials');
});



// Use Passport for authentication
app.get('/', passport.authenticate('jwt', { session: false }), (req, res) => {
  // If Authentication is successful, content from Jwt claims will be 
  // available in req.user property
  res.send(`Hi ${req.user.email}`);
});

app.listen(PORT, () => {
  console.log(`Example app listening at http://localhost:${PORT}`);
});
