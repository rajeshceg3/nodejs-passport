# Feature map: nodejs-passport

Purpose (from source interview): a minimal Socket.IO chat behind JWT auth -
register, log in, get a JWT, reach a chat page, and exchange messages that
carry the sender's username. Users live in an in-memory Map; restarting the
app clears all accounts.

## Exercised by verify.cjs (HTTP)

| Entry point | What is proven |
|---|---|
| GET / | 302 redirect to /login |
| GET /login | 200, login form present |
| GET /register | 200, registration form present |
| POST /registerAPI | new user registered; duplicate username rejected 409 |
| POST /loginAPI | wrong password -> success:false JSON; unknown user -> 401 once, server stays healthy (regression: this path used to double-send and reset the connection); correct credentials -> 200 with a Bearer JWT in the page script |
| GET /protected | 401 without a token; 200 greeting the username with one |
| GET /chat | 200 chat shell (static page, intentionally public) |

## Exercised by verify.cjs (socket, Engine.IO polling)

| Behavior | What is proven |
|---|---|
| Unauthenticated socket | connection rejected (connect_error) |
| Authenticated socket | JWT in the connect payload accepted |
| chat message | broadcast round-trips with the sender username attached |

## Known boundaries (honest scope)

- No database: accounts vanish on restart. The Map is the store.
- jwtSecret and session secret are hardcoded in index.js; this is a demo,
  not a production auth reference.
- The chat page shell is public by design; the gated surface is the socket.
- Browser visual check (pixels) is not part of the default run; the HTTP and
  socket contracts are what this map proves.
