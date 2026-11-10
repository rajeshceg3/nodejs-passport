---
name: verify-passport-chat
description: "Verify nodejs-passport's real user surface (register, login, JWT, chat socket) with isolated local processes and recorded evidence. Use before reporting behavior changes complete."
---

# Verify nodejs-passport

Generated from source interview following pstack create-verification-skill. Read features/README.md first.

## Launch

From the repository root run `npm ci --ignore-scripts`, then
`node .cursor/skills/verify-passport-chat/verify.cjs`. Node 18+ required
(developed on Node 22). The app hardcodes port 3000; the helper refuses to
start if that port is already taken rather than attaching to an unknown
listener. It spawns its own child process and polls /login until usable.

## Doctor

The helper confirms its own child is alive and GET /login returns 200 before
driving anything. A TCP listener alone is not success. After a surprising
failure, clean up and rerun from a fresh instance.

## Drive

Run `node .cursor/skills/verify-passport-chat/verify.cjs`. It registers a
throwaway user, exercises the auth API, the JWT-protected route, the chat
shell, and the Socket.IO chat over Engine.IO polling with and without a
token. No internal setters or test-only endpoints are used; all traffic is
what a real client sends.

## Evidence

Default location is a unique /tmp/verify-passport-chat- directory, printed
at exit. Set VERIFY_EVIDENCE_DIR to a new private persistent path to retain
proof. evidence.json records each request action, response/status,
assertions, findings and cleanup; server.log captures the child output.
One passing path never means the whole map passed; check FAILURES=0.

## Cleanup

The helper signals only the process it created, waits, escalates to SIGKILL
only on its own child, and preserves evidence. Confirm cleaned:true. The
in-memory user store is disposable. Never kill by process name.

## Helpers

`node .cursor/skills/verify-passport-chat/verify.cjs` is executable and
self-contained (stdlib only). A dependency or launch failure is a blocker,
not a skipped pass.

## Maintenance

After behavior changes use /maintain-verification-skill: reconcile every
mapped feature with source and exercise each live; report unreachable
prerequisites and product regressions rather than editing the map to hide
them.
