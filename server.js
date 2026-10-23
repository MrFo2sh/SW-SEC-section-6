#!/usr/bin/env node
/*
 * ===================================================================
 *  DeadDrop — secure notes, with support.   (Software Security lab)
 * ===================================================================
 *
 *  Run:  npm install && npm start   ->  http://localhost:5000
 *
 *  !!  DELIBERATELY VULNERABLE.  RUN ON localhost ONLY.  NEVER DEPLOY.  !!
 *
 *  A privilege-escalation CHAIN. The app looks like a real product; it never
 *  announces the bugs. Players discover the trail from in-world breadcrumbs.
 *
 *  Hidden chain (maintainers only):
 *    1. Recon  — dir fuzz (/api/*) + VHOST fuzz (internal.deaddrop.local)
 *    2. Register a normal customer account.
 *    3. IDOR ×2 — query-param (/ticket?id=) reveals the support agent's id;
 *                 REST (/api/users/:id) leaks that agent's PASSWORD.
 *    4. Log in as customer_support -> escalate a ticket to admin.
 *    5. Blind XSS — the escalation renders raw in the admin queue; the admin
 *                   bot opens it -> steal the ADMIN cookie.
 *    6. SQLi — admin panel's member search is unsanitized -> UNION the flag.
 *
 *  Admin/founder passwords are redacted in the API on purpose, so you cannot
 *  shortcut step 5 — admin must be reached by STEALING the cookie.
 * -------------------------------------------------------------------
 */

const express = require("express");
const crypto = require("crypto");
const http = require("http");
const fs = require("fs");
const path = require("path");
const { buildDatabase, runQuery } = require("./db");

const app = express();
const PORT = process.env.PORT || 5000;
const BASE_DOMAIN = "deaddrop.local";
const APP_VHOST = "app." + BASE_DOMAIN;        // the canonical main-app vhost
const SECRET_VHOST = "internal." + BASE_DOMAIN; // the one you find by fuzzing
app.use(express.urlencoded({ extended: false }));

/* ---- secrets / data ---------------------------------------------- */
const FINAL_FLAG = "FLAG{ch41n3d_rec0n_id0r_xss_sqli}";
const ADMIN_SID = "adm_" + crypto.randomBytes(10).toString("hex"); // must be stolen via XSS
let DB;

/* accounts. REST IDOR leaks these; admin/founder passwords are redacted. */
let accounts = [
  { id: 1, handle: "admin",            password: "n/a (SSO)",            role: "admin",    email: "admin@deaddrop.local" },
  { id: 2, handle: "customer_support", password: "Amira!Cairo#2024",    role: "support",  email: "support@deaddrop.local" },
  { id: 3, handle: "founder",          password: "n/a (SSO)",            role: "admin",    email: "founder@deaddrop.local" },
  { id: 4, handle: "alice",            password: "alice-loves-koshary",  role: "customer", email: "alice@deaddrop.local" },
  { id: 5, handle: "bob",              password: "pigeonHater99",        role: "customer", email: "bob@deaddrop.local" },
];
let acctSeq = 6;
const acctById = (id) => accounts.find((a) => a.id === id);
const acctByHandle = (h) => accounts.find((a) => a.handle.toLowerCase() === String(h).toLowerCase());
const REDACTED = new Set(["admin"]); // roles whose password never leaves the API
const apiRecord = (a) => ({ id: a.id, handle: a.handle, role: a.role, email: a.email,
  password: REDACTED.has(a.role) ? "[redacted — managed via SSO]" : a.password });

/* support tickets (query-param IDOR target). Ticket #1 outs the support agent. */
function seedTickets() {
  return [
    { id: 1, owner: "alice", subject: "can't open my shared note", body: "the share link just spins forever :(",
      reply: "Hi alice — sorted on our side, try again 🙏. And please never put passwords in a ticket. If we need to check an account we look it up in the staff user directory, never in chat. — Amira · Customer Support · this is a staff login, account #2" },
    { id: 2, owner: "bob",   subject: "the pigeons got into my notes", body: "I don't know how. they're IN the app now.", reply: "" },
    { id: 3, owner: "alice", subject: "was I double charged?", body: "two invoices this month, please check.", reply: "" },
  ];
}
let tickets = seedTickets();
let ticketSeq = 4;
const ticketById = (id) => tickets.find((t) => t.id === id);

let escalations = []; // support -> admin queue (blind XSS sink)
let escSeq = 1;
let intercepts = [];
let wall = [];

/* sessions: sid -> accountId  (admin bot is preset) */
const sessions = Object.create(null);
sessions[ADMIN_SID] = 1;

const progress = Object.create(null);
function prog(pid) {
  if (!progress[pid]) progress[pid] = { recon: false, idor: false, xss: false, sqli: false };
  return progress[pid];
}

/* Persist registered users (+ their tickets) so they survive restarts.
   Seed accounts (id < 6) and seed tickets (id < 4) are always rebuilt in code. */
const DATA_FILE = path.join(__dirname, "deaddrop-data.json");
function saveData() {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify({
      acctSeq, ticketSeq,
      accounts: accounts.filter((a) => a.id >= 6),
      tickets: tickets.filter((t) => t.id >= 4),
    }));
  } catch (e) {}
}
function loadData() {
  try {
    if (!fs.existsSync(DATA_FILE)) return;
    const d = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    if (Array.isArray(d.accounts)) for (const a of d.accounts) if (!acctByHandle(a.handle)) accounts.push(a);
    if (Array.isArray(d.tickets)) for (const t of d.tickets) if (!ticketById(t.id)) tickets.push(t);
    if (d.acctSeq) acctSeq = Math.max(acctSeq, d.acctSeq);
    if (d.ticketSeq) ticketSeq = Math.max(ticketSeq, d.ticketSeq);
  } catch (e) {}
}

/* ---- helpers ------------------------------------------------------ */
const esc = (s = "") =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function getCookie(req, name) {
  const hit = (req.headers.cookie || "").split(";").map((c) => c.trim()).find((c) => c.startsWith(name + "="));
  return hit ? decodeURIComponent(hit.slice(name.length + 1)) : undefined;
}
app.use((req, res, next) => {
  let pid = getCookie(req, "pid");
  if (!pid) {
    pid = crypto.randomBytes(8).toString("hex");
    res.cookie("pid", pid, { path: "/", maxAge: 31536000000, sameSite: "lax" });
  }
  req.pid = pid;
  const acctId = sessions[getCookie(req, "sid")];
  const acct = acctId && acctById(acctId);
  req.acct = acct || null;
  req.user = acct ? acct.handle : null;
  req.role = acct ? acct.role : null;
  req.vhost = String(req.headers.host || "").split(":")[0].toLowerCase();
  // The backend names itself. Hit it by raw IP / localhost and this header
  // reveals the canonical vhost -> infer it's vhost-based -> fuzz for siblings.
  res.setHeader("Server", "DeadDrop");
  res.setHeader("X-Served-By", req.vhost === SECRET_VHOST ? SECRET_VHOST : APP_VHOST);
  next();
});

/* ================================================================== *
 *  LAYOUT — light, projector-friendly, minimal, badge strip
 * ================================================================== */
function hudData(pid) {
  const p = prog(pid);
  return { ...p, done: [p.recon, p.idor, p.xss, p.sqli].filter(Boolean).length, total: 4 };
}
function layout(title, body, req, { wide = false } = {}) {
  const who = req.user
    ? `<a href="/logout" title="log out" class="${req.role === "admin" ? "text-rose-600" : req.role === "support" ? "text-fuchsia-600" : "text-emerald-600"} font-medium">${esc(req.user)}</a>`
    : `<a href="/login" class="text-indigo-600 hover:underline">Sign in</a>`;
  const isStaff = req.role === "support" || req.role === "admin";
  const navTickets = isStaff ? "" : `<a class="px-2.5 py-1.5 rounded-md hover:bg-slate-100 hover:text-slate-900" href="/tickets">Tickets</a>`;
  const navExtra = (req.role === "support") ? `<a class="px-2.5 py-1.5 rounded-md hover:bg-slate-100 hover:text-slate-900" href="/support">Support</a>` : "";
  const navAdmin = (req.role === "admin") ? `<a class="px-2.5 py-1.5 rounded-md hover:bg-slate-100 text-rose-600" href="/admin">Admin</a>` : "";
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · DeadDrop</title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
  body{font-family:'Space Grotesk',system-ui,sans-serif;background:#f3f5fa;color:#0f172a;}
  code,kbd,.mono{font-family:'JetBrains Mono',ui-monospace,monospace;}
  details>summary{list-style:none;cursor:pointer;} details>summary::-webkit-details-marker{display:none;}
  .toast{animation:pop .3s cubic-bezier(.2,.9,.3,1.3);}
  @keyframes pop{from{transform:translateY(10px) scale(.95);opacity:0}to{transform:none;opacity:1}}
  @keyframes pulse{0%,100%{opacity:.4}50%{opacity:1}} .listening{animation:pulse 1.4s infinite;}
  .pill{transition:transform .15s} .pill:hover{transform:translateY(-2px)}
</style></head>
<body class="min-h-screen antialiased">
<div class="bg-amber-50 border-b border-amber-200 text-amber-700 text-[11px] text-center py-1 mono">lab environment · localhost only</div>
<header class="sticky top-0 z-30 bg-white/90 backdrop-blur border-b border-slate-200">
  <div class="max-w-4xl mx-auto px-4 h-14 flex items-center gap-3">
    <a href="/" class="flex items-center gap-2 font-bold"><span class="grid place-items-center w-8 h-8 rounded-lg bg-gradient-to-br from-indigo-500 to-emerald-500 text-white">◈</span>Dead<span class="-ml-2 text-indigo-600">Drop</span></a>
    <nav class="hidden sm:flex items-center gap-1 text-sm text-slate-500 ml-1">
      <a class="px-2.5 py-1.5 rounded-md hover:bg-slate-100 hover:text-slate-900" href="/account">Account</a>
      ${navTickets}${navExtra}${navAdmin}
      <a class="px-2.5 py-1.5 rounded-md hover:bg-slate-100 hover:text-slate-900" href="/wall">Wall</a>
    </nav>
    <div class="ml-auto flex items-center gap-2 text-sm">
      <span id="badges" class="flex gap-1"></span>${who}
      <span id="score" title="secrets recovered" class="rounded-full border border-slate-200 bg-slate-50 text-slate-500 px-2.5 py-0.5 text-xs mono">⚑ 0/4</span>
    </div>
  </div>
</header>
<main class="max-w-${wide ? "4xl" : "2xl"} mx-auto px-4 py-10">${body}</main>
<footer class="max-w-4xl mx-auto px-4 py-8 text-xs text-slate-400 border-t border-slate-200 mt-8"><span class="mono">DeadDrop</span> · Lighthouse Collective · <span class="mono">hello@${BASE_DOMAIN}</span></footer>
<div id="toast" class="fixed bottom-5 right-5 z-50"></div>
<script>
  const KEYS=['recon','idor','xss','sqli'];const BADGE={recon:'🗺️',idor:'👀',xss:'🎣',sqli:'💉'};
  const QUIP={recon:'🗺️ <b>Cartographer</b> — you mapped what they tried to hide',
    idor:'👀 <b>Nosy Parker</b> — that account was not yours',
    xss:'🎣 <b>Big Catch</b> — that cookie wasn\\'t yours either',
    sqli:'💉 <b>Smooth Talker</b> — you sweet-talked the database'};
  function toast(m){const t=document.getElementById('toast');const e=document.createElement('div');
    e.className='toast mb-2 rounded-lg border border-emerald-300 bg-emerald-50 px-4 py-2.5 text-sm text-emerald-800 shadow max-w-xs';
    e.innerHTML=m;t.appendChild(e);setTimeout(()=>{e.style.transition='opacity .4s';e.style.opacity=0;setTimeout(()=>e.remove(),400);},4500);}
  // one fetch per page load (no polling). localStorage remembers the last
  // state so newly-completed links still pop a toast after a navigation.
  async function sync(){try{const p=await (await fetch('/api/progress',{cache:'no-store'})).json();
    const s=document.getElementById('score');if(s)s.textContent='⚑ '+p.done+'/4';
    const b=document.getElementById('badges');if(b)b.innerHTML=KEYS.filter(k=>p[k]).map(k=>'<span class="pill" title="'+k+'">'+BADGE[k]+'</span>').join('');
    let prev={};try{prev=JSON.parse(localStorage.getItem('dd_prog')||'{}');}catch(e){}
    for(const k of KEYS)if(p[k]&&!prev[k])toast('Achievement unlocked!<br>'+QUIP[k]);
    try{localStorage.setItem('dd_prog',JSON.stringify(p));}catch(e){}}catch(e){}}
  sync();
</script></body></html>`;
}
const card = (inner, cls = "") => `<section class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm ${cls}">${inner}</section>`;
const hint = (line) => `<details class="mt-5 text-sm text-slate-400"><summary class="inline-flex items-center gap-1.5 hover:text-slate-600">💡 <span>stuck?</span></summary><p class="mt-2 pl-5 border-l-2 border-slate-200 text-slate-500">${line}</p></details>`;
const needLogin = (req, res) => { if (!req.user) { res.redirect("/login"); return true; } return false; };

/* ================================================================== *
 *  VHOST fuzzing target (recon)
 * ================================================================== */
app.use((req, res, next) => {
  if (req.vhost === SECRET_VHOST) prog(req.pid).recon = true; // reaching internal = recon
  next();
});
// Staff/admin tools exist ONLY on internal.deaddrop.local; everywhere else they 404.
function internalOnly(req, res) {
  if (req.vhost === SECRET_VHOST) return false;
  res.status(404).send(layout("404", card(`<h1 class="text-lg font-bold">404</h1><p class="mt-1 text-sm text-slate-500">🤷 nothing here… that <i>you</i> can see. keep fuzzing.</p><a href="/" class="mt-3 inline-block text-indigo-600 hover:underline text-sm">← home</a>`), req));
  return true;
}

/* ---- recon artifacts + easter eggs -------------------------------- */
app.get("/robots.txt", (req, res) => res.type("text/plain").send(`User-agent: *\nDisallow: /api\nDisallow: /ticket\nDisallow: /admin\n`));
app.get("/api", (req, res) => { prog(req.pid).recon = true; res.json({ service: "deaddrop", endpoints: ["/api/users", "/api/users/:id"] }); });
app.get("/api/users", (req, res) => { prog(req.pid).recon = true; res.json({ members: accounts.map((a) => ({ id: a.id, handle: a.handle })) }); });

const egg = (req, res, msg) => res.status(200).send(layout("…", card(`<p class="text-slate-600">${msg}</p><a href="/" class="mt-3 inline-block text-indigo-600 hover:underline text-sm">← home</a>`), req));
app.get(["/wp-login.php", "/wp-admin"], (req, res) => egg(req, res, "this isn't WordPress. nice muscle memory though. 👏"));
app.get(["/.env", "/config.php", "/.git/config"], (req, res) => egg(req, res, "no secrets lying around the webroot today. the good stuff is deeper. 😉"));

/* ================================================================== *
 *  REST IDOR — /api/users/:id  (leaks the password)
 * ================================================================== */
app.get("/api/users/:id", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "sign in first" });
  const a = acctById(parseInt(req.params.id, 10));
  if (!a) return res.status(404).json({ error: "no such user" });
  if (a.id !== req.acct.id) prog(req.pid).idor = true; // missing ownership check
  res.json(apiRecord(a)); // includes password (redacted only for admins)
});

/* ================================================================== *
 *  Home / register / login
 * ================================================================== */
app.get("/", (req, res) => {
  // internal.deaddrop.local -> staff portal (login / tool links). main host -> customer site.
  if (req.vhost === SECRET_VHOST) {
    const staff = req.role === "support" || req.role === "admin";
    return res.send(layout("Staff portal", card(`
      <p class="mono text-xs text-slate-400">// internal · staff only</p>
      <h1 class="mt-1 text-xl font-bold">DeadDrop Staff Portal</h1>
      ${staff
        ? `<p class="mt-2 text-sm text-slate-500">Signed in as <b>${esc(req.user)}</b> (${esc(req.role)}).</p>
           <div class="mt-4 flex gap-3">
             <a href="/support" class="rounded-lg bg-fuchsia-600 hover:bg-fuchsia-500 text-white font-semibold px-5 py-2.5">Support console</a>
             ${req.role === "admin" ? `<a href="/admin" class="rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold px-5 py-2.5">Admin panel</a>` : ""}
           </div>`
        : `<p class="mt-2 text-sm text-slate-500">Restricted to DeadDrop staff. Sign in with your staff account.</p>
           <a href="/login" class="mt-4 inline-block rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-5 py-2.5">Staff sign in</a>`}
    `), req));
  }
  res.send(layout("DeadDrop", `
  <!-- ops: canonical host is app.deaddrop.local · staff tools run on their own vhost -->
  ${card(`
    <h1 class="text-2xl font-bold">Secure notes, with a human on support.</h1>
    <p class="mt-2 text-slate-500">Create an account, keep your notes, open a ticket if anything breaks.</p>
    <div class="mt-5 flex gap-3">
      <a href="/register" class="rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-5 py-2.5">Create account</a>
      <a href="/login" class="rounded-lg border border-slate-300 hover:border-indigo-400 px-5 py-2.5">Sign in</a>
    </div>`)}
`, req));
});

function authForm(kind, req, err = "") {
  const reg = kind === "register";
  return layout(reg ? "Create account" : "Sign in", card(`
    <h1 class="text-lg font-bold">${reg ? "Create your account" : "Sign in"}</h1>
    ${err ? `<p class="mt-2 text-sm text-rose-600">${esc(err)}</p>` : ""}
    <form method="post" action="/${kind}" class="mt-4 grid gap-3">
      <input name="handle" placeholder="username" autofocus class="rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-indigo-500">
      <input name="password" type="password" placeholder="password" class="rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-indigo-500">
      <button class="justify-self-start rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-5 py-2">${reg ? "Sign up" : "Sign in"}</button>
    </form>
    <p class="mt-4 text-xs text-slate-400">${reg ? `have an account? <a href="/login" class="text-indigo-600 hover:underline">sign in</a>` : `new here? <a href="/register" class="text-indigo-600 hover:underline">create one</a>`}</p>
  `), req);
}
app.get("/register", (req, res) => res.send(authForm("register", req)));
app.post("/register", (req, res) => {
  const handle = (req.body.handle || "").trim();
  const password = req.body.password || "";
  if (!handle || !password) return res.status(400).send(authForm("register", req, "Pick a username and password."));
  if (acctByHandle(handle)) return res.status(409).send(authForm("register", req, "That username is taken."));
  const a = { id: acctSeq++, handle, password, role: "customer", email: `${handle}@example.com` };
  accounts.push(a);
  tickets.push({ id: ticketSeq++, owner: handle, subject: "Welcome to DeadDrop 👋", body: "This is your first ticket. Our team can see it too.", reply: "Thanks for joining! — DeadDrop Support" });
  const sid = crypto.randomBytes(16).toString("hex");
  sessions[sid] = a.id;
  saveData();
  res.cookie("sid", sid, { path: "/", sameSite: "lax" });
  res.redirect("/tickets");
});
app.get("/login", (req, res) => res.send(authForm("login", req)));
app.post("/login", (req, res) => {
  const a = acctByHandle(req.body.handle);
  if (!a || a.password !== (req.body.password || "")) return res.status(401).send(authForm("login", req, "Invalid credentials."));
  const sid = crypto.randomBytes(16).toString("hex");
  sessions[sid] = a.id;
  res.cookie("sid", sid, { path: "/", sameSite: "lax" });
  // staff tools live on the internal vhost; send staff there only when they're on it.
  if (req.vhost === SECRET_VHOST && (a.role === "support" || a.role === "admin"))
    return res.redirect(a.role === "admin" ? "/admin" : "/support");
  res.redirect("/tickets");
});
app.get("/logout", (req, res) => { res.clearCookie("sid", { path: "/" }); res.redirect("/"); });

/* ================================================================== *
 *  Tickets + query-param IDOR  (/ticket?id=)
 * ================================================================== */
// My account — the profile card is loaded client-side from the user directory
// API, so the GET /api/users/<my-id> request is visible in DevTools/Burp.
app.get("/account", (req, res) => {
  if (needLogin(req, res)) return;
  res.send(layout("Account", card(`
    <h1 class="text-lg font-bold">My account</h1>
    <dl class="mt-4 grid grid-cols-[6rem_1fr] gap-y-2 text-sm">
      <dt class="text-slate-400">username</dt><dd id="h" class="font-medium">…</dd>
      <dt class="text-slate-400">email</dt><dd id="e" class="font-medium">…</dd>
      <dt class="text-slate-400">role</dt><dd id="r" class="font-medium">…</dd>
    </dl>
    ${hint("Open your browser's Network tab and reload. Where does this card's data come from — and what's in that request's URL?")}
    <script>
      fetch('/api/users/${req.acct.id}').then(function(x){return x.json();}).then(function(u){
        var set=function(id,v){var el=document.getElementById(id);if(el)el.textContent=v;};
        set('h',u.handle); set('e',u.email); set('r',u.role);
      }).catch(function(){});
    </script>
  `), req));
});
app.get("/tickets", (req, res) => {
  if (needLogin(req, res)) return;
  const mine = tickets.filter((t) => t.owner === req.user);
  const myRows = mine.map((t) => `<a href="/ticket?id=${t.id}" class="block rounded-lg border border-slate-200 bg-white px-4 py-3 hover:border-indigo-400"><span class="font-medium">${esc(t.subject)}</span></a>`).join("");
  const feed = tickets.filter((t) => t.owner !== req.user).map((t) => `<li class="flex items-center gap-2 py-1.5"><span class="w-6 h-6 grid place-items-center rounded-full bg-slate-100 text-xs">${esc(t.owner[0].toUpperCase())}</span><span class="text-slate-600"><b>${esc(t.owner)}</b> · 🔒 “${esc(t.subject)}”</span></li>`).join("");
  res.send(layout("Tickets", `
    ${card(`<h1 class="text-lg font-bold">My tickets</h1>
      <div class="mt-4 grid gap-2">${myRows || '<p class="text-slate-400 text-sm">No tickets yet — open one below.</p>'}</div>
      <form method="post" action="/tickets" class="mt-4 grid gap-2 sm:grid-cols-[1fr_1.6fr_auto]">
        <input name="subject" maxlength="120" placeholder="subject" required class="rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-indigo-500">
        <input name="body" maxlength="2000" placeholder="describe your issue…" required class="rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-indigo-500">
        <button class="rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-4 py-2 text-sm">New ticket</button>
      </form>`)}
    ${card(`<h2 class="text-sm font-semibold text-slate-500">Recent across DeadDrop</h2>
      <ul class="mt-2 divide-y divide-slate-100 text-sm">${feed}</ul>
      ${hint("These aren't yours — but the app only checks that you're <i>logged in</i>, not whose ticket it is.")}`, "mt-4")}
  `, req));
});
// Create a ticket (owner is set server-side; output is escaped on display -> not vulnerable).
app.post("/tickets", (req, res) => {
  if (needLogin(req, res)) return;
  const subject = (req.body.subject || "").trim().slice(0, 120) || "(no subject)";
  const body = (req.body.body || "").trim().slice(0, 2000);
  tickets.push({ id: ticketSeq++, owner: req.user, subject, body, reply: "" });
  saveData();
  res.redirect("/tickets");
});
app.get("/ticket", (req, res) => {
  if (needLogin(req, res)) return;
  const t = ticketById(parseInt(req.query.id, 10));
  if (!t) return res.status(404).send(layout("Not found", card(`<h1 class="text-lg font-bold">No ticket</h1><p class="mt-1 text-sm text-slate-400">🤷 empty slot. ids are small — keep trying.</p><a href="/tickets" class="mt-3 inline-block text-indigo-600 hover:underline text-sm">← my tickets</a>`), req));
  const isMine = t.owner === req.user;
  if (!isMine) prog(req.pid).idor = true; // missing ownership check
  res.send(layout(`Ticket #${t.id}`, card(`
    <div class="flex items-center justify-between"><h1 class="text-lg font-bold">${esc(t.subject)}</h1><span class="mono text-xs ${isMine ? "text-slate-400" : "text-rose-500"}">${isMine ? "yours" : "🔒 " + esc(t.owner) + "’s ticket"}</span></div>
    <pre class="mt-3 whitespace-pre-wrap font-sans text-slate-700 leading-relaxed">${esc(t.body)}</pre>
    ${t.reply ? `<div class="mt-4 rounded-lg bg-slate-50 border border-slate-200 p-3 text-sm text-slate-600"><span class="text-xs font-semibold text-fuchsia-600">support reply</span><p class="mt-1">${esc(t.reply)}</p></div>` : ""}
    <a href="/tickets" class="mt-5 inline-block text-slate-400 hover:text-slate-600 text-sm">← my tickets</a>
  `), req));
});

/* ================================================================== *
 *  Support dashboard -> escalate to admin  (blind XSS sink)
 * ================================================================== */
app.get("/support", (req, res) => {
  if (internalOnly(req, res)) return;
  if (needLogin(req, res)) return;
  if (req.role !== "support" && req.role !== "admin")
    return res.status(403).send(layout("Forbidden", card(`<h1 class="text-lg font-bold">403 — support only</h1><p class="mt-2 text-sm text-slate-500">This area is for customer support staff.</p>`), req));
  // Support sees EVERY customer's tickets (escaped — ticket content is not the XSS sink).
  const queue = tickets.map((t) => `<div class="rounded-lg border border-slate-200 bg-white p-3">
      <div class="flex items-center justify-between"><span class="font-medium">${esc(t.subject)}</span><span class="mono text-xs text-slate-400">${esc(t.owner)} · #${t.id}</span></div>
      <p class="mt-1 text-sm text-slate-600 whitespace-pre-wrap">${esc(t.body)}</p>
      ${t.reply ? `<p class="mt-2 text-xs text-slate-500 border-l-2 border-fuchsia-300 pl-2">↳ ${esc(t.reply)}</p>` : ""}
    </div>`).join("");
  res.send(layout("Support", `
    ${card(`
      <p class="mono text-xs text-fuchsia-600">// support · ${esc(req.user)}</p>
      <h1 class="mt-1 text-lg font-bold">Customer tickets</h1>
      <p class="mt-1 text-sm text-slate-500">All open tickets across DeadDrop.</p>
      <div class="mt-4 grid gap-2">${queue || '<p class="text-slate-400 text-sm">No tickets.</p>'}</div>
    `)}
    ${card(`
      <h2 class="text-lg font-bold">Escalate to admin</h2>
      <p class="mt-1 text-sm text-slate-500">Flag a case for the admin. They review the queue immediately.</p>
      <form method="post" action="/support/escalate" class="mt-4 grid gap-3">
        <input name="subject" placeholder="case subject" class="rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-fuchsia-500">
        <textarea name="body" rows="4" placeholder="details for the admin…" class="rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-fuchsia-500"></textarea>
        <button class="justify-self-start rounded-lg bg-fuchsia-600 hover:bg-fuchsia-500 text-white font-semibold px-5 py-2">Escalate</button>
      </form>
      ${hint("The admin's queue shows your note <i>exactly</i> as written. You won't see anything happen — their browser will.")}
    `, "mt-4")}
  `, req));
});
app.post("/support/escalate", (req, res) => {
  if (internalOnly(req, res)) return;
  if (!req.user || (req.role !== "support" && req.role !== "admin")) return res.status(403).send("forbidden");
  escalations.push({ id: escSeq++, pid: req.pid, by: req.user, subject: req.body.subject || "", body: req.body.body || "", seen: false });
  setTimeout(adminReviewQueue, 1200);
  res.send(layout("Escalated", card(`<div class="text-center py-4"><div class="text-3xl">📨</div><h1 class="mt-2 font-bold">Escalated to admin.</h1><p class="mt-1 text-sm text-slate-500">They'll review it shortly…</p><a href="/intercept" class="mt-3 inline-block text-indigo-600 hover:underline text-sm">watch your Intercept inbox →</a></div>`), req));
});

/* admin bot: reviews the escalation queue (emulated browser — see INSTRUCTOR.md) */
function adminReviewQueue() {
  for (const e of escalations) {
    if (e.seen) continue;
    e.seen = true;
    const html = String(e.body || "");
    const urls = html.match(/https?:\/\/[^\s"'`<>()]+/gi) || [];
    const usesCookie = /document\.cookie/i.test(html);
    const usesLoc = /location(?:\.href|\.search)?/i.test(html);
    if (!urls.length || (!usesCookie && !usesLoc)) continue;
    if (usesCookie && e.pid) prog(e.pid).xss = true;
    for (let base of urls) {
      let out = base;
      if (usesCookie) out += encodeURIComponent("sid=" + ADMIN_SID);
      else if (usesLoc) out += encodeURIComponent(`http://localhost:${PORT}/admin`);
      fireGet(out);
    }
  }
}
setInterval(adminReviewQueue, 4000);
function fireGet(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return;
    const r2 = http.get({ hostname: u.hostname, port: u.port || 80, path: u.pathname + u.search, timeout: 2500,
      headers: { "User-Agent": "DeadDrop-admin-browser/1.0" } }, (resp) => resp.on("data", () => {}).on("end", () => {}));
    r2.on("error", () => {}); r2.on("timeout", () => r2.destroy());
  } catch (e) {}
}

app.get("/collect", (req, res) => {
  const qs = req.url.includes("?") ? req.url.slice(req.url.indexOf("?") + 1) : "";
  intercepts.unshift({ at: new Date().toLocaleTimeString(), raw: decodeURIComponent(qs) });
  intercepts = intercepts.slice(0, 50);
  res.type("text/plain").send("ok");
});
app.get("/intercept", (req, res) => {
  const rows = intercepts.length === 0
    ? `<div class="text-center py-10 text-slate-400"><div class="text-4xl listening">📡</div><p class="mt-3 text-sm mono listening">listening for callbacks…</p></div>`
    : intercepts.map((c) => {
        const m = c.raw.match(/sid=([a-z0-9_]+)/i);
        const btn = m ? `<button onclick="document.cookie='sid=${m[1]}; Path=/';location='/admin'" class="mt-2 rounded-md bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold px-3 py-1.5">🪪 become them → admin panel</button>` : "";
        return `<div class="rounded-lg border border-emerald-200 bg-emerald-50/50 p-3"><div class="flex items-center gap-2"><span class="text-xs font-bold text-emerald-700">📥 CAUGHT ONE</span><span class="mono text-[11px] text-slate-400 ml-auto">${esc(c.at)}</span></div><div class="mt-1 mono text-sm text-emerald-800 break-all">${esc(c.raw) || "(empty)"}</div>${btn}</div>`;
      }).join("");
  res.send(layout("Intercept", card(`<h1 class="text-lg font-bold">Intercept</h1><p class="mt-1 text-sm text-slate-500">Your listener at <code class="mono">/collect</code>. Whatever a victim's browser sends lands here. Live.</p><div class="mt-4 grid gap-2">${rows}</div>`), req));
});

/* ================================================================== *
 *  Admin panel — unsanitized search -> SQLi  (role admin only)
 * ================================================================== */
app.get("/admin", (req, res) => {
  if (req.vhost !== SECRET_VHOST)
    return egg(req, res, "😏 of course you went for <code class='mono'>/admin</code>. everyone does — but the admin tools aren't on <i>this</i> host anyway.");
  if (req.role !== "admin")
    return res.status(403).send(layout("Forbidden", card(`<h1 class="text-lg font-bold">403 — admins only</h1><p class="mt-2 text-sm text-slate-500">A staff admin session is required.</p>`), req));
  const q = req.query.q;
  let block = "";
  if (typeof q === "string") {
    try {
      const sql = "SELECT id, handle, role, joined FROM members WHERE handle LIKE '%" + q + "%'";
      const result = runQuery(DB, sql);
      if (result.rows.map((r) => r.join(" ")).join(" ").includes(FINAL_FLAG)) prog(req.pid).sqli = true;
      const cards = result.rows.length
        ? result.rows.map((row) => `<div class="rounded-lg border border-slate-200 bg-white p-3"><div class="flex items-center justify-between"><span class="font-medium">${esc(row[1])}</span><span class="mono text-xs text-slate-400">#${esc(row[0])}</span></div><div class="mt-0.5 text-xs text-slate-500">${esc(row[2])} · ${esc(row[3])}</div></div>`).join("")
        : `<p class="text-slate-400 text-sm">No matches.</p>`;
      block = `<div class="mt-4 grid sm:grid-cols-2 gap-2">${cards}</div>`;
    } catch (e) {
      block = `<div class="mt-4 rounded-lg bg-amber-50 border border-amber-200 text-amber-700 p-3 text-sm">search failed — the database didn't like that.</div>`;
    }
  }
  res.send(layout("Admin", card(`
    <p class="mono text-xs text-rose-600">// admin · ${esc(req.user)}</p>
    <h1 class="mt-1 text-lg font-bold">Member search</h1>
    <form method="get" class="mt-3 flex gap-2"><input name="q" value="${esc(q || "")}" placeholder="search members" class="flex-1 rounded-lg border border-slate-300 px-3 py-2 outline-none focus:border-rose-500 mono text-sm"><button class="rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold px-4 py-2">Search</button></form>
    ${block}
    ${hint("This search believes <i>everything</i> you type. The flag isn't in the members table — it's in a table this search never means to read.")}
  `), req, { wide: true }));
});

/* ================================================================== *
 *  Flag + Wall of Fame
 * ================================================================== */
app.get("/flag", (req, res) => res.send(layout("Flag", card(`<h1 class="text-lg font-bold">Submit flag</h1><form method="post" action="/flag" class="mt-4 flex gap-2"><input name="flag" placeholder="FLAG{...}" class="flex-1 rounded-lg border border-slate-300 px-3 py-2 mono text-sm outline-none focus:border-emerald-500"><button class="rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold px-5 py-2">Verify</button></form>`), req)));
app.post("/flag", (req, res) => {
  const ok = (req.body.flag || "").trim() === FINAL_FLAG;
  if (!ok) return res.send(layout("Nope", card(`<div class="text-center py-6"><div class="text-4xl">🤏</div><h1 class="mt-2 font-bold">Not quite.</h1><p class="mt-1 text-sm text-slate-500">The flag's sealed in the database. Go get it.</p><a href="/flag" class="mt-3 inline-block text-indigo-600 hover:underline text-sm">try again</a></div>`), req));
  res.send(layout("Win", card(`<div class="text-center py-6"><div class="text-5xl">🏆</div><h1 class="mt-3 text-2xl font-bold text-emerald-600">You chained it.</h1>
    <p class="mt-2 text-slate-500 max-w-md mx-auto text-sm">register → snoop → steal support's login → phish the admin → sweet-talk the database. A nobody customer account became full admin. That's the whole lesson. 🎉</p>
    <form method="post" action="/wall" class="mt-6 flex gap-2 max-w-xs mx-auto"><input name="handle" maxlength="24" placeholder="your handle" class="flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-500"><button class="rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold px-4 py-2 text-sm">sign the wall ✍️</button></form>
  </div>`), req));
});
app.post("/wall", (req, res) => { wall.push({ handle: (req.body.handle || "").trim().slice(0, 24) || "anon", at: new Date().toLocaleString() }); res.redirect("/wall"); });
app.get("/wall", (req, res) => {
  const rows = wall.length === 0 ? `<p class="text-slate-400 text-sm">Empty. Be the first to finish the chain. 🥇</p>`
    : wall.map((w, i) => `<li class="flex items-center gap-3 py-2 border-b border-slate-100 last:border-0"><span class="w-7 text-center font-bold ${i === 0 ? "text-amber-500" : "text-slate-400"}">${i === 0 ? "🥇" : i === 1 ? "🥈" : i === 2 ? "🥉" : "#" + (i + 1)}</span><span class="font-medium">${esc(w.handle)}</span><span class="ml-auto text-xs text-slate-400 mono">${esc(w.at)}</span></li>`).join("");
  res.send(layout("Wall of Fame", card(`<h1 class="text-lg font-bold">🏆 Wall of Fame</h1><p class="mt-1 text-sm text-slate-500">Recruits who chained it all the way through.</p><ol class="mt-4">${rows}</ol>`), req));
});

app.get("/api/progress", (req, res) => res.json(hudData(req.pid)));
app.get("/reset", (req, res) => {
  progress[req.pid] = { recon: false, idor: false, xss: false, sqli: false };
  accounts = accounts.filter((a) => a.id < 6); acctSeq = 6;
  tickets = seedTickets(); ticketSeq = 4; escalations = []; intercepts = [];
  saveData();
  res.clearCookie("sid", { path: "/" });
  res.redirect("/");
});

app.use((req, res) => res.status(404).send(layout("404", card(`<h1 class="text-lg font-bold">404</h1><p class="mt-1 text-sm text-slate-500">🤷 nothing here… that <i>you</i> can see. keep fuzzing.</p><a href="/" class="mt-3 inline-block text-indigo-600 hover:underline text-sm">← home</a>`), req)));

/* ---- boot --------------------------------------------------------- */
buildDatabase(FINAL_FLAG).then((db) => {
  DB = db;
  loadData(); // restore registered users + their tickets from last run
  app.listen(PORT, "0.0.0.0", () => {
    console.log("=".repeat(62));
    console.log(`  DeadDrop:   http://localhost:${PORT}   (serves on any host)`);
    console.log(`  canonical:  ${APP_VHOST}      (advertised via X-Served-By)`);
    console.log(`  secret:     ${SECRET_VHOST}  (fuzz the Host header to find it)`);
    console.log("  Deliberately vulnerable · localhost only · do not deploy.");
    console.log("=".repeat(62));
  });
});
