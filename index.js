const express = require('express');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const app = express();
const PORT = 3000;

const jwtStrategy = new JwtStrategy({
 jwtFromRequest : req => req.headers.authorization,
 secretOrKey : 'jwt-secret'},
(jwtPaylod, done) => {
  return done( null,
    {
      email : jwtPaylod.email,
      name :  jwtPaylod.name,
    })
}
)

passport.use(jwtStrategy);

app.use(express.static('static'));

app.get('/', (req, res) => {

});

app.listen(PORT, () => {
  console.log(`Example app listening at http://localhost:${PORT}`);
});
