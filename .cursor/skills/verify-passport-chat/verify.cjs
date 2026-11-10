// verify-passport-chat: isolated local verification for nodejs-passport.
// Stdlib only. Spawns the real app, drives its HTTP + Socket.IO surface,
// records evidence, cleans up only its own child.
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');
const net = require('net');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const PORT = 3000; // app hardcodes this port
const EVIDENCE_DIR = process.env.VERIFY_EVIDENCE_DIR ||
  fs.mkdtempSync('/tmp/verify-passport-chat-');
const evidence = { repo: 'nodejs-passport', started_at: new Date().toISOString(),
  actions: [], findings: [], boundaries: ['local processes only', 'in-memory user store, disposable', 'no external services'],
  cleaned: false };
let failures = 0;

function record(action, ok, detail) {
  evidence.actions.push({ at: new Date().toISOString(), action, ok, detail });
  if (!ok) failures++;
  console.log((ok ? 'PASS ' : 'FAIL ') + action + (detail ? ' :: ' + detail : ''));
}
function finding(note) { evidence.findings.push(note); console.log('FINDING ' + note); }

function req(method, p, { body, headers, follow } = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? (typeof body === 'string' ? body : JSON.stringify(body)) : null;
    const r = http.request({ host: '127.0.0.1', port: PORT, path: p, method,
      headers: Object.assign({}, headers || {}, data ? { 'Content-Length': Buffer.byteLength(data) } : {}) },
      (res) => {
        let buf = '';
        res.on('data', (c) => buf += c);
        res.on('end', () => {
          if (follow && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            resolve(req(method, res.headers.location, { headers, follow: true }));
          } else resolve({ status: res.statusCode, headers: res.headers, body: buf });
        });
      });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}
const post = (p, form, headers) => req('POST', p, { body: new URLSearchParams(form).toString(),
  headers: Object.assign({ 'Content-Type': 'application/x-www-form-urlencoded' }, headers || {}) });

function portFree(port) {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.once('listening', () => s.close(() => resolve(true)));
    s.listen(port, '127.0.0.1');
  });
}

async function waitReady(child, tries = 60) {
  for (let i = 0; i < tries; i++) {
    if (child.exitCode !== null) return false;
    try { const r = await req('GET', '/login'); if (r.status === 200) return true; } catch (e) {}
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}

// Minimal Engine.IO v4 polling client for the Socket.IO surface.
async function eioHandshake() {
  const r = await req('GET', '/socket.io/?EIO=4&transport=polling');
  if (r.status !== 200 || r.body[0] !== '0') return { ok: false, detail: 'handshake status ' + r.status };
  const sid = JSON.parse(r.body.slice(1)).sid;
  return { ok: true, sid };
}
async function eioSend(sid, packet) {
  return req('POST', '/socket.io/?EIO=4&transport=polling&sid=' + sid, { body: packet,
    headers: { 'Content-Type': 'text/plain;charset=UTF-8' } });
}
async function eioPoll(sid, waitMs = 4000) {
  const r = await req('GET', '/socket.io/?EIO=4&transport=polling&sid=' + sid);
  return r.body; // may contain multiple packets separated by \x1e
}

(async () => {
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
  if (!(await portFree(PORT))) {
    record('precheck: app port ' + PORT + ' free', false, 'port occupied; refusing to attach to an unknown listener');
    finish(null); return;
  }
  record('precheck: app port ' + PORT + ' free', true);

  const logStream = fs.createWriteStream(path.join(EVIDENCE_DIR, 'server.log'));
  const child = spawn('node', ['index.js'], { cwd: ROOT, env: Object.assign({}, process.env), stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.pipe(logStream); child.stderr.pipe(logStream);

  try {
    const ready = await waitReady(child);
    record('launch: own child serving /login', ready);
    if (!ready) { finish(child); return; }

    // HTTP surface
    let r = await req('GET', '/');
    record('GET / redirects to /login', r.status === 302 && (r.headers.location || '').includes('/login'), 'status ' + r.status);
    r = await req('GET', '/login');
    record('GET /login serves form', r.status === 200 && r.body.includes('loginAPI'));
    r = await req('GET', '/register');
    record('GET /register serves form', r.status === 200 && r.body.includes('registerAPI'));

    const user = 'verifyuser' + Date.now();
    r = await post('/registerAPI', { username: user, password: 'verify-pass-1' });
    record('POST /registerAPI new user', r.status === 200 && r.body.includes('Successful'), 'status ' + r.status);
    r = await post('/registerAPI', { username: user, password: 'verify-pass-1' });
    record('POST /registerAPI duplicate rejected 409', r.status === 409, 'status ' + r.status);
    r = await post('/loginAPI', { username: user, password: 'wrong-pass' });
    record('POST /loginAPI wrong password fails', r.status === 200 && /"success"\s*:\s*false/.test(r.body), 'status ' + r.status);
    r = await post('/loginAPI', { username: 'nouser' + Date.now(), password: 'x' });
    record('POST /loginAPI unknown user 401', r.status === 401 && r.body.includes('not registered'), 'status ' + r.status);
    // Regression guard: the unknown-user path used to double-send a response and
    // reset the connection (ERR_HTTP_HEADERS_SENT). The server must stay healthy.
    r = await req('GET', '/login');
    record('server healthy after unknown-user login attempt', r.status === 200, 'status ' + r.status);
    r = await post('/loginAPI', { username: user, password: 'verify-pass-1' });
    const m = r.body.match(/localStorage\.setItem\('token', 'Bearer ([^']+)'\)/);
    record('POST /loginAPI issues JWT', r.status === 200 && !!m);
    const token = m ? m[1] : null;

    r = await req('GET', '/protected');
    record('GET /protected without token is 401', r.status === 401, 'status ' + r.status);
    if (token) {
      r = await req('GET', '/protected', { headers: { Authorization: 'Bearer ' + token } });
      record('GET /protected with token greets user', r.status === 200 && r.body.includes(user), 'status ' + r.status + ' body ' + r.body.slice(0, 60));
    }
    // The chat page is a public static shell; the socket is the gated surface.
    r = await req('GET', '/chat');
    record('GET /chat serves the chat shell', r.status === 200 && r.body.includes('/static/chat.js'), 'status ' + r.status);

    // Socket.IO surface over Engine.IO polling: unauthenticated socket must be rejected.
    {
      const hs0 = await eioHandshake();
      if (hs0.ok) {
        await eioSend(hs0.sid, '40{}');
        await new Promise((r2) => setTimeout(r2, 800));
        const polled0 = await eioPoll(hs0.sid);
        const rejected = polled0.indexOf('44') !== -1 || polled0.indexOf('4{"message"') !== -1 || polled0.indexOf('40') === -1;
        record('socket without token is rejected', rejected, polled0.slice(0, 120).replace(/\x1e/g, '|'));
      } else {
        record('socket without token is rejected', false, 'handshake failed: ' + (hs0.detail || ''));
      }
    }
    if (token) {
      const hs = await eioHandshake();
      record('socket.io EIO4 handshake', hs.ok, hs.detail || 'sid ' + hs.sid);
      if (hs.ok) {
        const conn = await eioSend(hs.sid, '40{"token":"Bearer ' + token + '"}');
        await new Promise((r2) => setTimeout(r2, 800));
        let polled = await eioPoll(hs.sid);
        const authed = polled.indexOf('40') !== -1;
        record('socket auth with JWT accepted', authed, polled.slice(0, 120).replace(/\x1e/g, '|'));
        if (authed) {
          await eioSend(hs.sid, '42["chat message","verify-round-trip"]');
          await new Promise((r2) => setTimeout(r2, 800));
          polled = await eioPoll(hs.sid);
          const got = polled.includes('verify-round-trip') && polled.includes(user);
          record('chat message round-trip carries username', got, polled.slice(0, 160).replace(/\x1e/g, '|'));
          if (got === false && polled.includes('verify-round-trip') && !polled.includes(user)) {
            finding('Chat broadcast lacks the sender username - passport.socketio did not attach req.user with this JWT flow.');
          }
        } else {
          finding('Socket.IO auth rejects the localStorage Bearer token sent as connect payload - even a browser that reached /chat could not open the chat socket.');
        }
      }
    }
  } catch (e) {
    record('unhandled verification error', false, String(e && e.message || e));
  } finally {
    finish(child);
  }

  function finish(child2) {
    if (child2 && child2.exitCode === null) {
      child2.kill('SIGTERM');
      setTimeout(() => { if (child2.exitCode === null) child2.kill('SIGKILL'); }, 1500);
    }
    setTimeout(() => {
      evidence.cleaned = !child2 || child2.exitCode !== null;
      evidence.finished_at = new Date().toISOString();
      evidence.failures = failures;
      fs.writeFileSync(path.join(EVIDENCE_DIR, 'evidence.json'), JSON.stringify(evidence, null, 1));
      console.log('EVIDENCE_DIR=' + EVIDENCE_DIR);
      console.log('FAILURES=' + failures);
      process.exit(failures ? 1 : 0);
    }, 2200);
  }
})();
