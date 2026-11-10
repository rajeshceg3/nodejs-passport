# nodejs-passport

A minimal Socket.IO chat behind JWT auth, in one Express server.

- Register and log in (users are stored in memory and vanish on restart).
- Logging in issues a JWT; `GET /protected` shows the token-gated API pattern.
- The chat page (`/chat`) is a static shell; the chat socket is gated by the
  same JWT, and messages are broadcast with the sender's username.

## Run

```
npm ci
npm start   # serves on http://localhost:3000 (port is hardcoded)
```

## Verify

```
node .cursor/skills/verify-passport-chat/verify.cjs
```

Spawns the app, exercises the auth and chat surface with real requests, and
writes an evidence report. See `.cursor/skills/verify-passport-chat/`.

## Honest scope

This is a learning demo: hardcoded secrets, in-memory accounts, no rate
limiting. It is not a production auth template.

[Edit on StackBlitz ⚡️](https://stackblitz.com/edit/express-simple-jfev39)
