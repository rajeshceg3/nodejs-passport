const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser')
const passport = require('passport');
const session = require('express-session');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const bcrypt = require('bcryptjs');
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

const jwtOptions =  {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: jwtSecret,
};

const jwtStrategy = new JwtStrategy( jwtOptions,
  (jwtPayload, done) => {
    return done(null, {
      username: jwtPayload.username
    });
  }
);

passport.use(jwtStrategy);

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.username);
});

passport.deserializeUser((username, done) => {
  return done(null, getUserDetails(username));
});

// Collect username and password and validate it
app.get('/login', (req, res) => {
  res.send(`
    <h1>Super Fast chat </h1>
    <form action="/loginAPI" method="post">
      <input type="text" name="username" placeholder="Username" required />
      <input type="password" name="password" placeholder="Password" required />
      <button type="submit">Login</button>
    </form>
  `);
});

// Provide a form for user registration 
app.get('/register', (req, res) => {
  res.send(`
    <h1>Super Fast chat </h1>
    <form action="/registerAPI" method="post">
      <input type="text" name="username" placeholder="Username" required />
      <input type="password" name="password" placeholder="Password" required />
      <button type="submit">Create Account</button>
    </form>
  `);
});

app.post('/registerAPI',(req,res)=>{

  const username = req.body.username;
  const password = req.body.password;

  if(users.has(username)){
    res.status(409).send("Provided username is already taken");
    return;
  }

  bcrypt.hash(password, 10, ( err, hash)=>{
    if( err ){
      res.status(500).send("Issue with hashing the password");
      return;
    }

    users.set(username, {
      username: username,
      password: hash
    });

    res.send("User Registration is Successful");

  })
})

function getUserDetails(username){
  return users.get(username);
}

function credentialsvalid(username, password,res){
  if ( !users.has(username)){
    res.status(401).send(`User ${username} is not registered`);
    return;
  }

  // Get the stored details, in prod it will be read from db 
  const userdetails = getUserDetails(username);
  return bcrypt.compareSync(password, userdetails.password);
}


app.post('/loginAPI',(req,res)=>{
  if(!credentialsvalid(req.body.username, req.body.password,res)){
    res.json({
      success: false,
      message : " Incorrect credentials"
    })
  }
  else{
    const token = jwt.sign({username:getUserDetails(req.body.username).username}, jwtSecret);

    res.json({
      success: true,
      token : token
    }); 
  }
  })


// Use Passport for authentication to a protected route
app.get('/protected', passport.authenticate('jwt', { session: false }), (req, res) => {
  // If Authentication is successful, content from Jwt claims will be 
  // available in req.user property
  console.log("Received correct token")
  res.send(`Hi ${req.user.username}`);

});

app.listen(PORT, () => {
  console.log(`Example app listening at PORT ${PORT}`);
});
