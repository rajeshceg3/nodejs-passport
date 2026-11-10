const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser')
const passport = require('passport');
const session = require('express-session');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const bcrypt = require('bcryptjs');
const http = require('http');
const { Server } = require("socket.io");

const PORT = 3000;
const jwtSecret = 'secret-key';
// Set up a temporary store for user data
// Later we'll hook it up to db
const users = new Map();

const app = express();
const server = http.createServer(app);
const io = new Server(server);

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

function credentialsvalid(username, password){
  if ( !users.has(username)){
    return 'unregistered';
  }

  // Get the stored details, in prod it will be read from db 
  const userdetails = getUserDetails(username);
  return bcrypt.compareSync(password, userdetails.password) ? 'ok' : 'bad-password';
}


app.post('/loginAPI',(req,res)=>{
  const verdict = credentialsvalid(req.body.username, req.body.password);
  if(verdict === 'unregistered'){
    res.status(401).send(`User ${req.body.username} is not registered`);
    return;
  }
  if(verdict !== 'ok'){
    res.json({
      success: false,
      message : " Incorrect credentials"
    })
  }
  else{
    const token = jwt.sign({username:getUserDetails(req.body.username).username}, jwtSecret);

    res.send(`
      <script>
        localStorage.setItem('token', 'Bearer ${token}');
        window.location.href = '/chat';
      </script>
    `);
  }
  })


app.use('/static', express.static('static'));

// The chat page is a static shell; the sensitive surface is the socket,
// which is JWT-gated below. Gating the page itself broke the real browser
// journey: after login the token lives in localStorage and a navigation
// sends no Authorization header, so users landed on 401.
app.get('/chat', (req, res) => {
  res.sendFile(__dirname + '/pages/chat.html');
});

// Use Passport for authentication to a protected route
app.get('/protected', passport.authenticate('jwt', { session: false }), (req, res) => {
  // If Authentication is successful, content from Jwt claims will be 
  // available in req.user property
  console.log("Received correct token")
  res.send(`Hi ${req.user.username}`);

});

app.get('/', (req, res) => {
  res.redirect('/login');
});

// Gate the socket with the same JWT the API uses. passport.socketio was
// wired with options it does not support and no session store, so every
// connection crashed the process; it is removed.
io.use((socket, next) => {
  const raw = socket.handshake.auth && socket.handshake.auth.token;
  const token = raw && raw.replace(/^Bearer\s+/i, '');
  if (!token) {
    return next(new Error('unauthorized'));
  }
  jwt.verify(token, jwtSecret, (err, payload) => {
    if (err) {
      return next(new Error('unauthorized'));
    }
    socket.request.user = { username: payload.username };
    next();
  });
});

io.on('connection', (socket) => {
  console.log('a user connected');
  socket.on('disconnect', () => {
    console.log('user disconnected');
  });

  socket.on('chat message', (msg) => {
    io.emit('chat message', { username: socket.request.user.username, message: msg });
  });
});

server.listen(PORT, () => {
  console.log(`Example app listening at PORT ${PORT}`);
});
