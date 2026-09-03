require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { createClient } = require('@libsql/client');

const {
  TURSO_DATABASE_URL,
  TURSO_AUTH_TOKEN,
  SETUP_KEY,      // required header value to create new login users via /api/auth/register
  PORT = 3000
} = process.env;

if (!TURSO_DATABASE_URL || !TURSO_AUTH_TOKEN) {
  console.error('Missing TURSO_DATABASE_URL or TURSO_AUTH_TOKEN in environment.');
  process.exit(1);
}

const db = createClient({
  url: TURSO_DATABASE_URL,
  authToken: TURSO_AUTH_TOKEN
});

const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// ---------- in-memory session store ----------
// Simple bearer tokens, held in memory only. They reset if the server restarts
// (e.g. Render free-tier spin-down), which just means users log in again.
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours
const sessions = new Map(); // token -> { email, expires }

function issueToken(email) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, { email, expires: Date.now() + SESSION_TTL_MS });
  return token;
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const session = token && sessions.get(token);
  if (!session || session.expires < Date.now()) {
    if (session) sessions.delete(token);
    return res.status(401).json({ error: 'Not authenticated.' });
  }
  req.user = session.email;
  next();
}

// ---------- table setup (runs on boot, safe to re-run) ----------
async function ensureTables() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS users (
      email TEXT PRIMARY KEY,
      password TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  await db.execute(`
    CREATE TABLE IF NOT EXISTS issues (
      id TEXT PRIMARY KEY,
      ts TEXT NOT NULL,
      consignment TEXT,
      channel TEXT,
      zone TEXT,
      hub TEXT,
      status TEXT,
      category TEXT,
      subcategory TEXT,
      details TEXT,
      logged_by TEXT
    )
  `);
}

// ---------- auth routes ----------

// One-time bootstrap route to create a login. Protected by SETUP_KEY so a
// stranger with the URL can't create accounts. Call it once per person, then
// you're done — nothing else needs this header.
app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (req.headers['x-setup-key'] !== SETUP_KEY) {
    return res.status(403).json({ error: 'Invalid setup key.' });
  }
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required.' });
  }
  try {
    await db.execute({
      sql: 'INSERT INTO users (email, password) VALUES (?, ?)',
      args: [email.trim().toLowerCase(), password]
    });
    res.json({ ok: true });
  } catch (err) {
    if (String(err.message || '').includes('UNIQUE')) {
      return res.status(409).json({ error: 'That email is already registered.' });
    }
    console.error(err);
    res.status(500).json({ error: 'Could not create user.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required.' });
  }
  try {
    const result = await db.execute({
      sql: 'SELECT email, password FROM users WHERE email = ?',
      args: [email.trim().toLowerCase()]
    });
    const row = result.rows[0];
    if (!row || row.password !== password) {
      return res.status(401).json({ error: 'Wrong email or password.' });
    }
    const token = issueToken(row.email);
    res.json({ token, email: row.email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed.' });
  }
});

// ---------- issue routes ----------

app.post('/api/issues', requireAuth, async (req, res) => {
  const i = req.body || {};
  const required = ['consignment', 'channel', 'zone', 'hub', 'status', 'category', 'subcategory', 'details'];
  const missing = required.filter(k => !i[k]);
  if (missing.length) {
    return res.status(400).json({ error: `Missing fields: ${missing.join(', ')}` });
  }
  const id = Date.now() + '-' + crypto.randomBytes(4).toString('hex');
  const ts = new Date().toISOString();
  try {
    await db.execute({
      sql: `INSERT INTO issues (id, ts, consignment, channel, zone, hub, status, category, subcategory, details, logged_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [id, ts, i.consignment, i.channel, i.zone, i.hub, i.status, i.category, i.subcategory, i.details, req.user]
    });
    res.json({ ok: true, id, ts });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not save issue.' });
  }
});

app.get('/api/issues', requireAuth, async (req, res) => {
  try {
    const result = await db.execute('SELECT * FROM issues ORDER BY ts DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not fetch issues.' });
  }
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

ensureTables()
  .then(() => {
    app.listen(PORT, () => console.log(`Escalation backend listening on port ${PORT}`));
  })
  .catch(err => {
    console.error('Failed to set up tables:', err);
    process.exit(1);
  });
