// ---- Password gate (shared by tests.beane.ca and test2.beane.ca) ----
// Expects `HTML` (the demo page) and `SITE` ({ name, sub, bg }) defined above.
// Optional `PAGES` ({ "/old": "<html>…" }) adds more pages, each served at /old, /old/ and /old/index.html behind the same gate and lock.
// Optional `ASSETS` binding (Workers static assets, run_worker_first): any other path is served from it, behind the same gate and lock.
// KV binding: AUTH. Config record key: "auth:config" (delete it to reset the password).
const CFG_KEY = "auth:config";
const ITER = 100000;            // PBKDF2-SHA256 iterations (Workers WebCrypto max is 100k)
const SESSION_SECS = 30 * 24 * 3600;
const RL_MAX = 10, RL_WINDOW = 600; // 10 wrong tries per 10 minutes per IP
const COOKIE = "__Host-beane_session";
const NO_STORE = "no-store, no-cache, must-revalidate, private";

const enc = new TextEncoder();
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s) => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); };
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function pbkdf2(password, salt, iter) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter }, key, 256));
}
function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
const hmacKey = (secret) => crypto.subtle.importKey("raw", unb64u(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);

async function makeToken(cfg, host) {
  const payload = b64u(enc.encode(JSON.stringify({ h: host, e: Math.floor(Date.now() / 1000) + SESSION_SECS, n: b64u(rand(9)) })));
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(cfg.secret), enc.encode(payload));
  return payload + "." + b64u(sig);
}
async function checkToken(cfg, host, token) {
  try {
    const [payload, sig] = String(token || "").split(".");
    if (!payload || !sig) return false;
    const ok = await crypto.subtle.verify("HMAC", await hmacKey(cfg.secret), unb64u(sig), enc.encode(payload));
    if (!ok) return false;
    const p = JSON.parse(new TextDecoder().decode(unb64u(payload)));
    return p.h === host && typeof p.e === "number" && p.e > Date.now() / 1000;
  } catch { return false; }
}
function getCookie(request, name) {
  const h = request.headers.get("cookie") || "";
  for (const part of h.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}
async function getConfig(env) {
  const raw = await env.AUTH.get(CFG_KEY);
  if (!raw) return null;
  try { const c = JSON.parse(raw); return c && c.hash && c.salt && c.secret ? c : null; } catch { return null; }
}

// Same look as the beane.ca password page (new-site/worker.js in thetruebeane/tests).
function page(kind, { error = "", status = 200, next = "/" } = {}) {
  const setup = kind === "setup";
  const title = setup ? "Set a password" : "Password";
  const note = setup ? "First visit. Choose the password for the beane.ca test sites. It can only be set once." : "This site is private.";
  const fields = setup
    ? `<label for="pw">Password</label>
  <input id="pw" name="password" type="password" minlength="6" maxlength="256" autocomplete="new-password" required autofocus>
  <label for="pw2" style="margin-top:.75rem">Confirm password</label>
  <input id="pw2" name="confirm" type="password" minlength="6" maxlength="256" autocomplete="new-password" required>`
    : `<label for="pw">Password</label>
  <input id="pw" name="password" type="password" maxlength="256" autocomplete="current-password" required autofocus>`;
  const body = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow"><title>${esc(title)}</title>
<style>
  :root{color-scheme:light dark;--fg:#111;--muted:#666;--bg:#fff;--field:#fff;--line:#cfcfcf;--accent:#111;--accent-fg:#fff;--err:#b3261e}
  @media (prefers-color-scheme:dark){:root{--fg:#eee;--muted:#999;--bg:#111;--field:#181818;--line:#3a3a3a;--accent:#eee;--accent-fg:#111;--err:#ff8a80}}
  *{box-sizing:border-box}
  html,body{margin:0;height:100%}
  body{display:flex;align-items:center;justify-content:center;padding:16px;background:var(--bg);color:var(--fg);
    font-family:helvetica,arial,sans-serif;font-size:1rem;line-height:1.6}
  form{width:100%;max-width:300px}
  h1{font-size:1.5rem;line-height:1.2;margin:0 0 .25rem}
  p{margin:0 0 1.25rem;color:var(--muted)}
  label{display:block;font-size:.875rem;margin-bottom:.35rem}
  input{width:100%;height:2.5rem;padding:0 .7rem;font:inherit;color:var(--fg);background:var(--field);border:1px solid var(--line);border-radius:4px}
  input:focus{outline:2px solid var(--fg);outline-offset:1px;border-color:var(--fg)}
  button{margin-top:1rem;width:100%;height:2.5rem;font:inherit;font-weight:bold;color:var(--accent-fg);background:var(--accent);border:0;border-radius:4px;cursor:pointer}
  button:hover{opacity:.85}
  .err{color:var(--err);margin:0 0 1rem}
</style></head>
<body><form method="post" action="/__auth/${setup ? "setup" : "login"}">
  <h1>${esc(title)}</h1><p>${esc(note)}</p>
  ${error ? `<p class="err" role="alert">${esc(error)}</p>` : ""}
  ${fields}
  <input type="hidden" name="next" value="${esc(next)}">
  <button type="submit">${setup ? "Set password" : "Enter"}</button>
</form></body></html>`;
  return new Response(body, { status, headers: gateHeaders() });
}
function gateHeaders(extra = {}) {
  return { "content-type": "text/html; charset=utf-8", "cache-control": NO_STORE, "x-content-type-options": "nosniff",
    "x-frame-options": "DENY", "referrer-policy": "same-origin", ...extra };
}
const EXTRA = typeof PAGES === "object" && PAGES ? PAGES : {};
const pageKey = (p) => { const k = String(p || "").replace(/\/(index\.html)?$/, ""); return k && Object.prototype.hasOwnProperty.call(EXTRA, k) ? k : null; };
const safeNext = (n) => (n === "/index.html" || pageKey(n) ? n : "/");   // only our own pages, never anything else
const redirect = (to, cookie) => new Response(null, { status: 303, headers: { location: to, "cache-control": NO_STORE, ...(cookie ? { "set-cookie": cookie } : {}) } });
const sessionCookie = (token) => `${COOKIE}=${token}; Path=/; Max-Age=${SESSION_SECS}; HttpOnly; Secure; SameSite=Lax`;
const sameOrigin = (request, url) => { const o = request.headers.get("origin"); return !o || o === url.origin; };

async function rateInfo(env, ip) {
  const raw = await env.AUTH.get("rl:" + ip);
  const now = Math.floor(Date.now() / 1000);
  try { const r = JSON.parse(raw); if (r && r.reset > now) return { ...r, had: true }; } catch {}
  return { n: 0, reset: now + RL_WINDOW, had: raw !== null };
}

async function handleSetup(request, env, url) {
  if (!sameOrigin(request, url)) return new Response("Forbidden", { status: 403, headers: { "cache-control": NO_STORE } });
  const f = await request.formData().catch(() => null);
  const pw = f ? String(f.get("password") || "") : "", pw2 = f ? String(f.get("confirm") || "") : "";
  if (pw.length < 6) return page("setup", { error: "Use at least 6 characters.", status: 400 });
  if (pw.length > 256) return page("setup", { error: "That password is too long.", status: 400 });
  if (pw !== pw2) return page("setup", { error: "The two passwords don't match.", status: 400 });
  const salt = rand(16);
  const hash = await pbkdf2(pw, salt, ITER);
  const cfg = { v: 1, alg: "PBKDF2-SHA256", iter: ITER, salt: b64u(salt), hash: b64u(hash), secret: b64u(rand(32)),
    id: b64u(rand(12)), created: new Date().toISOString(), by: url.host };
  // KV has no compare-and-set, so check again immediately before writing and never write if anything is stored.
  if (await env.AUTH.get(CFG_KEY) !== null) return redirect("/");
  await env.AUTH.put(CFG_KEY, JSON.stringify(cfg), { metadata: { created: cfg.created, by: cfg.by } });
  const stored = await getConfig(env);
  if (!stored || stored.id !== cfg.id) return redirect("/"); // someone else won the race: their password stands
  return redirect("/", sessionCookie(await makeToken(cfg, url.host)));
}

async function handleLogin(request, env, url, cfg) {
  if (!sameOrigin(request, url)) return new Response("Forbidden", { status: 403, headers: { "cache-control": NO_STORE } });
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const f = await request.formData().catch(() => null);
  const next = safeNext(f && f.get("next"));
  const rl = await rateInfo(env, ip);
  if (rl.n >= RL_MAX) {
    const mins = Math.max(1, Math.ceil((rl.reset - Date.now() / 1000) / 60));
    return page("login", { error: `Too many wrong tries. Try again in ${mins} min.`, status: 429, next });
  }
  const pw = f ? String(f.get("password") || "") : "";
  const ok = pw.length > 0 && pw.length <= 256 && sameBytes(await pbkdf2(pw, unb64u(cfg.salt), cfg.iter || ITER), unb64u(cfg.hash));
  if (ok) {
    if (rl.had) await env.AUTH.delete("rl:" + ip).catch(() => {});
    return redirect(next, sessionCookie(await makeToken(cfg, url.host)));
  }
  rl.n += 1;
  await env.AUTH.put("rl:" + ip, JSON.stringify({ n: rl.n, reset: rl.reset }), { expiration: Math.max(rl.reset, Math.floor(Date.now() / 1000) + 61) }).catch(() => {});
  await sleep(800);
  const left = RL_MAX - rl.n;
  return page("login", { error: left > 0 ? "Wrong password." : "Wrong password. Too many tries, wait 10 min.", status: 401, next });
}

// ---- Lockout switch (requested by hand, never automatic) ----
// Two sources, either one locks (the Durable Object wins when both have a message):
//  1. LIVE: the Durable Object LockState (binding LOCK, one instance named "lock" per Worker). Strongly consistent,
//     read on every request, and it pushes changes to open tabs over a WebSocket. Flip it with SQL (docs/lockout.md).
//     Row k='lock' in table state; v is the lock record below. No row (or an "off" value) means unlocked.
//  2. KV (the original switch, kept as a fallback and for the dashboard): "lock:all" locks every site, "lock:<host>" one
//     (e.g. "lock:test2.beane.ca") on the AUTH namespace. KV changes take up to ~60 s to spread, and each isolate memoises 5 s.
// A record is JSON {"title":"...","msg":"..."} or plain text (used as the message). A locked site answers every request
// except /__status and /__lock/ws with 503, whatever the visitor's cookie says. Pages that are already open hold a
// WebSocket to /__lock/ws (fallback: poll /__status about every 1.5 s), cover themselves, and reload when the lock lifts.
// Fail-safe: if the Durable Object cannot be reached the gate falls back to KV alone, which fails OPEN (the site serves
// normally) rather than bricking it.
const LOCK_MEMO_MS = 5000;      // per-isolate cache of the two KV lock keys (bounds KV reads). The live check is never cached.
const LIVE_TIMEOUT_MS = 1500;   // give the Durable Object this long before falling back to KV alone
const LIVE_TICK_MS = 2000;      // while tabs are connected, the Durable Object re-reads its state this often (catches SQL edits that no request nudged).
                                // 2 s keeps one always-open tab under ~43k alarm requests/day (free plan: 100k/day for all Durable Object traffic).
const LOCK_NAME = "lock", LOCK_WS = "/__lock/ws";
const LOCK_TITLE_MAX = 80, LOCK_MSG_MAX = 400;
const LOCK_TITLE_DEFAULT = "Down for maintenance";
const LOCK_MSG_DEFAULT = "Back soon. This page will reopen on its own.";
const lockMemo = new Map();

function lockText(v, max, fallback) {
  const s = (typeof v === "string" ? v : "").replace(/\r\n?/g, "\n").replace(/[\u0000-\u0009\u000b-\u001f\u007f]/g, " ").replace(/\n{3,}/g, "\n\n").trim();
  const out = Array.from(s).slice(0, max).join("").trim();
  return out || fallback;
}
function parseLock(raw) {
  if (raw === null || raw === undefined) return null;
  const s = String(raw).trim();
  if (!s || /^(0|off|false|unlock|unlocked)$/i.test(s)) return null;
  let title = "", msg = /^(1|on|true|lock|locked)$/i.test(s) ? "" : s; // a bare "1" locks with the default message
  if (s[0] === "{") {
    try {
      const o = JSON.parse(s);
      if (o && typeof o === "object") {
        if (o.locked === false) return null;
        title = o.title; msg = o.msg !== undefined ? o.msg : o.message;
      }
    } catch { /* not JSON: treat the whole value as the message */ }
  }
  return { title: lockText(title, LOCK_TITLE_MAX, LOCK_TITLE_DEFAULT), msg: lockText(msg, LOCK_MSG_MAX, LOCK_MSG_DEFAULT) };
}

// The Durable Object. A plain class (no import) so dist/worker.js stays a single import-free module.
export class LockState {
  constructor(state, env) {
    this.state = state;
    this.sql = state.storage.sql;
    this.last = null; // last state pushed to sockets (memory only; null after a wake-up, which just re-sends once)
    this.sql.exec("CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v TEXT)");
  }
  read() {
    const row = this.sql.exec("SELECT v FROM state WHERE k = 'lock'").toArray()[0];
    const rec = row ? parseLock(row.v) : null; // same parser, caps and defaults as the KV records
    return rec ? { locked: true, title: rec.title, msg: rec.msg } : { locked: false };
  }
  push() { // re-read and, if it changed, tell every connected tab
    const cur = JSON.stringify(this.read());
    if (cur !== this.last) {
      this.last = cur;
      for (const ws of this.state.getWebSockets()) { try { ws.send(cur); } catch { /* socket already gone */ } }
    }
    return cur;
  }
  async arm() { // keep ticking only while at least one tab is connected, so an idle site costs nothing
    if (this.state.getWebSockets().length > 0 && (await this.state.storage.getAlarm()) === null) await this.state.storage.setAlarm(Date.now() + LIVE_TICK_MS);
  }
  async fetch(request) {
    if ((request.headers.get("upgrade") || "").toLowerCase() === "websocket") {
      const pair = new WebSocketPair();
      this.state.acceptWebSocket(pair[1]);
      pair[1].send(JSON.stringify(this.read()));
      this.push();
      await this.arm();
      return new Response(null, { status: 101, webSocket: pair[0] });
    }
    return new Response(this.push(), { headers: { "content-type": "application/json", "cache-control": "no-store" } });
  }
  async webSocketMessage(ws) { // the page pings every ~20 s; answer with the current state
    let cur; try { cur = JSON.stringify(this.read()); ws.send(cur); } catch { /* ignore */ }
    this.push();
    await this.arm();
  }
  async webSocketClose(ws) { try { ws.close(1000); } catch { /* already closed */ } }
  async webSocketError() {}
  async alarm() { this.push(); await this.arm(); }
}

async function getKvLock(env, host) {
  const hit = lockMemo.get(host);
  if (hit && Date.now() - hit.t < LOCK_MEMO_MS) return hit.v;
  let v;
  try {
    const [one, all] = await Promise.all([env.AUTH.get("lock:" + host), env.AUTH.get("lock:all")]);
    v = parseLock(one) || parseLock(all); // the site's own record wins over lock:all
  } catch { return hit ? hit.v : null; }  // KV hiccup: keep the last known state, retry on the next request
  lockMemo.set(host, { t: Date.now(), v }); // only plain data is cached, never a promise (requests must not share I/O)
  return v;
}
// {ok:false} when there is no binding or the Durable Object did not answer in time; otherwise {ok:true, lock: record|null}.
async function getLiveLock(env) {
  if (!env.LOCK) return { ok: false };
  let timer;
  try {
    const stub = env.LOCK.get(env.LOCK.idFromName(LOCK_NAME));
    const res = await Promise.race([stub.fetch("https://lock/state"), new Promise((_, no) => { timer = setTimeout(() => no(new Error("timeout")), LIVE_TIMEOUT_MS); })]);
    if (!res.ok) return { ok: false };
    const j = await res.json();
    if (!j || j.locked !== true) return { ok: true, lock: null };
    return { ok: true, lock: { title: lockText(j.title, LOCK_TITLE_MAX, LOCK_TITLE_DEFAULT), msg: lockText(j.msg, LOCK_MSG_MAX, LOCK_MSG_DEFAULT) } };
  } catch { return { ok: false }; } finally { clearTimeout(timer); }
}
async function getLock(env, host) {
  const [live, kv] = await Promise.all([getLiveLock(env), getKvLock(env, host)]);
  return (live.ok && live.lock) || kv; // locked if either says so; if the live check failed, KV decides
}

// Runs inside every open page (injected into the demo HTML) and inside the 503 page.
const LOCK_CLIENT = `(function(){
if(window.__beaneLock)return;window.__beaneLock=1;
var STATUS="/__status",WS_PATH="${LOCK_WS}",FAST=1500,SLOW=20000,locked=!!window.__beaneLockStatic,busy=false,box=null,ws=null,wsOk=false,back_off=1000,tm=0,raf=window.requestAnimationFrame;
window.requestAnimationFrame=function(cb){return locked?0:raf.call(window,cb)};
function stop(e){if(locked&&!window.__beaneLockStatic){e.stopImmediatePropagation();if(e.cancelable)e.preventDefault()}}
["keydown","keyup","keypress","pointerdown","pointerup","pointermove","mousedown","mouseup","mousemove","click","dblclick","contextmenu","wheel","touchstart","touchmove","touchend"].forEach(function(n){window.addEventListener(n,stop,{capture:true,passive:false})});
function build(){
var b=document.createElement("div");b.id="beane-lock";b.setAttribute("role","alertdialog");b.setAttribute("aria-live","assertive");
b.style.cssText="position:fixed;left:0;top:0;right:0;bottom:0;z-index:2147483647;display:flex;align-items:center;justify-content:center;padding:24px;overflow:auto;background:#121212;color:#9a9a9a;color-scheme:dark;text-align:center;-webkit-text-size-adjust:100%;font:15px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;-webkit-font-smoothing:antialiased";
b.innerHTML='<div style="max-width:420px;width:100%;margin:auto"><svg width="44" height="44" viewBox="0 0 48 48" fill="none" stroke="#808080" stroke-width="2.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false" style="display:block;margin:0 auto 24px"><rect x="10" y="21" width="28" height="21" rx="5.5"/><path d="M16.5 21v-6a7.5 7.5 0 0 1 15 0v6"/><path d="M24 31.5v.01" stroke-width="4.8"/></svg><h1 id="beane-lock-t" style="font-family:inherit;font-weight:500;font-size:20px;line-height:1.3;letter-spacing:0;color:#b0b0b0;margin:0 0 10px;overflow-wrap:anywhere"></h1><p id="beane-lock-m" style="margin:0;color:#9a9a9a;white-space:pre-line;overflow-wrap:anywhere"></p></div>';
return b}
function show(s){
if(!locked){locked=true;try{if(document.activeElement&&document.activeElement.blur)document.activeElement.blur()}catch(e){}}
box=document.getElementById("beane-lock");
if(!box){box=build();(document.body||document.documentElement).appendChild(box)}
var t=document.getElementById("beane-lock-t"),m=document.getElementById("beane-lock-m");
if(t.textContent!==s.title)t.textContent=s.title;if(m.textContent!==s.msg)m.textContent=s.msg}
function back(){location.replace(location.pathname.indexOf("/__auth/")===0?"/":location.href)}
var GUARD="beane-lock-reloaded",reloading=false;
function guard(op){try{if(op==="get")return window.sessionStorage.getItem(GUARD)==="1";if(op==="set")window.sessionStorage.setItem(GUARD,"1");else window.sessionStorage.removeItem(GUARD);return true}catch(e){return op==="get"}}
function reloadOnce(){
if(reloading||window.__beaneLockStatic||guard("get"))return;
if(!guard("set"))return;
reloading=true;back()}
if(window.__beaneLockStatic)guard("clear");
function apply(s){
if(!s||typeof s.locked!=="boolean")return;
if(s.locked){show(s);reloadOnce()}else if(locked){guard("clear");back()}}
function poll(){
if(busy||document.hidden)return;busy=true;
fetch(STATUS,{cache:"no-store",credentials:"same-origin"}).then(function(r){return r.ok?r.json():null}).then(apply).catch(function(){}).then(function(){busy=false})}
function connect(){
if(ws||document.hidden||typeof WebSocket!=="function")return;
var w;try{w=new WebSocket((location.protocol==="https:"?"wss://":"ws://")+location.host+WS_PATH)}catch(e){return}
ws=w;
w.onopen=function(){wsOk=true;back_off=1000;poll()};
w.onmessage=function(e){try{apply(JSON.parse(e.data))}catch(x){}};
w.onclose=w.onerror=function(){if(ws!==w)return;ws=null;wsOk=false;if(!document.hidden){setTimeout(connect,back_off);back_off=Math.min(back_off*2,15000)}};
}
function loop(){clearTimeout(tm);poll();if(ws&&ws.readyState===1){try{ws.send("?")}catch(e){}}tm=setTimeout(loop,wsOk?SLOW:FAST)}
function wake(){
if(document.hidden){if(ws){var w=ws;ws=null;wsOk=false;try{w.close()}catch(e){}}return}
connect();loop()}
document.addEventListener("visibilitychange",wake);window.addEventListener("focus",wake);window.addEventListener("online",wake);
connect();tm=setTimeout(loop,FAST);
})();`;
const LOCK_TAG = `<script id="beane-lock-js">${LOCK_CLIENT}</script>`;
const withLockClient = (html) => {
  const m = /<head[^>]*>/i.exec(html);
  return m ? html.slice(0, m.index + m[0].length) + LOCK_TAG + html.slice(m.index + m[0].length) : LOCK_TAG + html;
};
let DEMO_HTML = null; // HTML plus the lock client, built once per isolate
const EXTRA_HTML = {}; // the same for the extra pages

function lockedPage(lock, method) {
  const body = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex"><title>${esc(lock.title)} · ${esc(SITE.name)}</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 viewBox=%270 0 48 48%27 fill=%27none%27 stroke=%27%23808080%27 stroke-width=%273.5%27 stroke-linecap=%27round%27 stroke-linejoin=%27round%27%3E%3Crect x=%2710%27 y=%2721%27 width=%2728%27 height=%2721%27 rx=%275.5%27/%3E%3Cpath d=%27M16.5 21v-6a7.5 7.5 0 0 1 15 0v6%27/%3E%3Cpath d=%27M24 31.5v.01%27 stroke-width=%274.8%27/%3E%3C/svg%3E">
<meta name="color-scheme" content="dark">
<meta name="theme-color" content="#121212">
<style>
  *{box-sizing:border-box}
  html,body{margin:0;min-height:100%}
  html{background:#121212}
  body{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;background:#121212;color:#9a9a9a;text-align:center;
    font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;-webkit-font-smoothing:antialiased;-webkit-text-size-adjust:100%}
  main{width:100%;max-width:420px;margin:auto}
  svg{display:block;margin:0 auto 24px}
  h1{font-size:20px;font-weight:500;line-height:1.3;color:#b0b0b0;margin:0 0 10px;overflow-wrap:anywhere}
  p{margin:0;color:#9a9a9a;white-space:pre-line;overflow-wrap:anywhere}
  small{display:block;margin-top:40px;font-size:12px;color:#858585}
</style></head>
<body><main id="beane-lock"><svg width="44" height="44" viewBox="0 0 48 48" fill="none" stroke="#808080" stroke-width="2.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><rect x="10" y="21" width="28" height="21" rx="5.5"/><path d="M16.5 21v-6a7.5 7.5 0 0 1 15 0v6"/><path d="M24 31.5v.01" stroke-width="4.8"/></svg><h1 id="beane-lock-t">${esc(lock.title)}</h1><p id="beane-lock-m">${esc(lock.msg)}</p><small>${esc(SITE.name)} · ${esc(SITE.sub)}</small></main>
<script>window.__beaneLockStatic=1;</script><script>${LOCK_CLIENT}</script></body></html>`;
  return new Response(method === "HEAD" ? null : body, { status: 503, headers: gateHeaders({ "retry-after": "60" }) });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const extra = pageKey(path);
    const isDemo = path === "/" || path === "/index.html" || extra !== null;

    // Live push channel for open tabs. It only carries the lock state (same as /__status), so it needs no cookie.
    if (path === LOCK_WS) {
      const origin = request.headers.get("origin");
      if (!env.LOCK || (request.headers.get("upgrade") || "").toLowerCase() !== "websocket") return new Response("Not found", { status: 404, headers: { "content-type": "text/plain", "cache-control": NO_STORE } });
      if (origin && origin !== url.origin) return new Response("Forbidden", { status: 403, headers: { "content-type": "text/plain", "cache-control": NO_STORE } });
      try { return await env.LOCK.get(env.LOCK.idFromName(LOCK_NAME)).fetch(request); }
      catch { return new Response("Unavailable", { status: 503, headers: { "content-type": "text/plain", "cache-control": NO_STORE } }); }
    }

    // Lockout switch: checked first, so it holds for everyone, cookie or not. /__status is how open tabs learn about it.
    const lock = await getLock(env, url.host);
    if (path === "/__status" && (request.method === "GET" || request.method === "HEAD")) {
      return new Response(request.method === "HEAD" ? null : JSON.stringify(lock ? { locked: true, title: lock.title, msg: lock.msg } : { locked: false }),
        { headers: { "content-type": "application/json; charset=utf-8", "cache-control": NO_STORE, "x-content-type-options": "nosniff" } });
    }
    if (lock) return lockedPage(lock, request.method);

    if (path === "/logout") return redirect("/", `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);

    const cfg = await getConfig(env);
    if (!cfg) {
      if (path === "/__auth/setup" && request.method === "POST") return handleSetup(request, env, url);
      const r = page("setup", { next: safeNext(path) });
      return request.method === "HEAD" ? new Response(null, r) : r;
    }
    if (path === "/__auth/login" && request.method === "POST") return handleLogin(request, env, url, cfg);
    if (path === "/__auth/setup") return redirect("/"); // setup is locked once a password exists

    if (!(await checkToken(cfg, url.host, getCookie(request, COOKIE)))) {
      const r = page("login", { next: safeNext(path) });
      return request.method === "HEAD" ? new Response(null, r) : r;
    }
    if (!isDemo) {
      if (env.ASSETS) return env.ASSETS.fetch(request);
      return new Response("Not found", { status: 404, headers: { "content-type": "text/plain", "cache-control": NO_STORE } });
    }
    if (DEMO_HTML === null) DEMO_HTML = withLockClient(HTML);
    if (extra !== null && !EXTRA_HTML[extra]) EXTRA_HTML[extra] = withLockClient(EXTRA[extra]);
    return new Response(request.method === "HEAD" ? null : extra !== null ? EXTRA_HTML[extra] : DEMO_HTML, {
      headers: { "content-type": "text/html; charset=utf-8", "cache-control": NO_STORE, "x-content-type-options": "nosniff" },
    });
  },
};
