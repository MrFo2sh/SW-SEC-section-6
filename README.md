# DeadDrop — Capstone CTF 🔗

A single target that hides a short **privilege-escalation chain**: you start as
a nobody and talk your way up to full admin, one small bug opening the next. It
looks like a real app on purpose — no walkthrough, no phase list. You map it,
you poke it, you climb.

Everything you need is something you've already practiced: **recon + fuzzing**,
**XSS**, **SQL injection** — plus the one idea tying it together, **IDOR**, which
shows up here in two different shapes.

> ⚠️ **Lab only.** Deliberately vulnerable. Run it on your own machine / the
> class network. Never deploy it. Attack only this copy.

---

## Run it

```bash
npm install
npm start
# -> http://localhost:5000
```

Reset anytime from `/reset`. Nothing you do can break it for good.

---

## Your mission

Make your own account, then climb from customer to **admin** and pull the sealed
`FLAG{...}` out of the database. Submit it at `/flag` and sign the Wall of Fame.
The `⚑` counter ticks each time you recover a secret, and you'll collect a few
achievements on the way. 🗺️👀🎣💉

That's the brief. The rest is yours to discover. 🫡

---

## Recon toolkit (how to look — not what you'll find)

Map the target first.

**Read the response headers.** Before anything else, look at what the server
says about itself:
```bash
curl -I http://localhost:5000/
```
A backend often names itself in a header. What hostname does it report? What
does that tell you about how it's served — and what *else* might be served the
same way?

**Directories** — guess paths nothing links to:
```bash
ffuf -u http://localhost:5000/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -ic -c
```

**Virtual hosts** — guess hostnames the server quietly answers to. You already
learned the domain from the headers (and it's in the footer). Fuzz the `Host`
header and drop the boring same-sized responses:
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://127.0.0.1:5000/ -H "Host: FUZZ.<the-domain>" -ac
```
To open a vhost you find, send the header yourself:
```bash
curl -H "Host: <sub>.<the-domain>" http://localhost:5000/
```
or add `127.0.0.1  <sub>.<the-domain>` to your hosts file and browse it.

Also always check `view-source:` and `/robots.txt`.

---

## When you're really stuck

- Each tricky page has a small **💡 stuck?** line — it nudges your thinking, it
  never gives the answer.
- Read *everything* you can reach, even things that aren't "yours." People and
  APIs here are far too trusting. 👀
- Recognise a move? You did it in `attack-vectors/`, `xss-lab/`, or
  `sql-inj/`. Go redo it there, then bring it back.

---

## After you win (the part that's graded)

For each weakness you used, write a sentence or two:

1. **What** it was and **why** it worked.
2. The **one change** that would have stopped it.
3. The big one: each bug alone was minor — so **why was the chain critical**?
   (A self-registered nobody became admin. That's the point of the capstone.)

Welcome to the field.
