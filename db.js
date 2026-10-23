// db.js --------------------------------------------------------------
//  Tiny in-memory SQLite (sql.js — pure WASM, no native build) used by
//  the LAST link of the chain: the staff console's "Member lookup".
//
//  The lookup query is built by string concatenation on purpose, so the
//  classic UNION-based SQL injection from the Week 5 lab works here too.
//
//  Two tables:
//    members  — ordinary data the lookup is meant to search (4 columns)
//    vault    — the sealed secret, reachable ONLY by injecting a UNION
//               (nothing in the app ever selects from it legitimately).
//
//  Re-seeded on every server start. Break it freely; restart to reset.
// --------------------------------------------------------------------

const initSqlJs = require("sql.js");

const MEMBERS = [
  // id, handle,   role,        joined
  [1, "guest",   "member",    "2026-01-05"],
  [2, "alice",   "member",    "2025-11-20"],
  [3, "bob",     "member",    "2025-10-02"],
  [4, "mod_sam", "staff",     "2025-03-15"],
  [5, "founder", "admin",     "2024-09-01"],
];

async function buildDatabase(finalFlag) {
  const SQL = await initSqlJs();
  const db = new SQL.Database();

  db.run(`
    CREATE TABLE members (
      id     INTEGER PRIMARY KEY,
      handle TEXT,
      role   TEXT,
      joined TEXT
    );
    CREATE TABLE vault (
      id     INTEGER PRIMARY KEY,
      label  TEXT,
      secret TEXT,
      note   TEXT
    );
  `);

  const insM = db.prepare("INSERT INTO members VALUES (?,?,?,?)");
  MEMBERS.forEach((r) => insM.run(r));
  insM.free();

  // The jackpot. Four columns so a UNION lines up with the members query.
  db.run("INSERT INTO vault VALUES (?,?,?,?)", [
    1,
    "OPERATION BLACKOUT",
    finalFlag,
    "if you can read this, your chain held all the way through. respect.",
  ]);

  return db;
}

// Run raw SQL, return { columns, rows } or throw the DB error.
function runQuery(db, sql) {
  const res = db.exec(sql);
  if (res.length === 0) return { columns: [], rows: [] };
  return { columns: res[0].columns, rows: res[0].values };
}

module.exports = { buildDatabase, runQuery };
