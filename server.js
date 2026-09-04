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
      name TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  // Add `name` to a users table created before this column existed.
  // SQLite/libSQL has no "ADD COLUMN IF NOT EXISTS", so we try and
  // swallow the "duplicate column" error on databases that already have it.
  try {
    await db.execute('ALTER TABLE users ADD COLUMN name TEXT');
  } catch (err) {
    if (!String(err.message || '').includes('duplicate column')) throw err;
  }
  // Which app this login is allowed to use: 'main' (Central Issues Log +
  // Escalation Dashboard) or 'ops' (Ops Console). NULL is treated as 'main'
  // for accounts created before this column existed.
  try {
    await db.execute('ALTER TABLE users ADD COLUMN app_access TEXT');
  } catch (err) {
    if (!String(err.message || '').includes('duplicate column')) throw err;
  }
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
  // Ops/Regional/Cluster remarks + last-updated tracking on existing issues tables.
  for (const stmt of [
    'ALTER TABLE issues ADD COLUMN remarks TEXT',
    'ALTER TABLE issues ADD COLUMN remarks_by TEXT',
    'ALTER TABLE issues ADD COLUMN updated_at TEXT'
  ]) {
    try {
      await db.execute(stmt);
    } catch (err) {
      if (!String(err.message || '').includes('duplicate column')) throw err;
    }
  }

  await db.execute(`
    CREATE TABLE IF NOT EXISTS hub_assignments (
      hub_name TEXT PRIMARY KEY,
      division TEXT,
      ops_manager_name TEXT,
      ops_manager_email TEXT,
      regional_manager_name TEXT,
      regional_manager_email TEXT,
      cluster_lead_name TEXT,
      cluster_lead_email TEXT
    )
  `);
}

// Given a signed-in email, find every hub they're allowed to see —
// as Ops Manager, Regional Manager, or Cluster Lead — plus which role(s)
// gave them access to each. Returns [] if the email is unassigned.
async function resolveOpsScope(email) {
  const result = await db.execute({
    sql: `
      SELECT hub_name,
             CASE WHEN ops_manager_email = ?1 THEN 1 ELSE 0 END AS is_ops_manager,
             CASE WHEN regional_manager_email = ?1 THEN 1 ELSE 0 END AS is_regional_manager,
             CASE WHEN cluster_lead_email = ?1 THEN 1 ELSE 0 END AS is_cluster_lead
      FROM hub_assignments
      WHERE ops_manager_email = ?1 OR regional_manager_email = ?1 OR cluster_lead_email = ?1
    `,
    args: [email]
  });
  const roles = new Set();
  const hubs = [];
  for (const row of result.rows) {
    hubs.push(row.hub_name);
    if (row.is_ops_manager) roles.add('ops_manager');
    if (row.is_regional_manager) roles.add('regional_manager');
    if (row.is_cluster_lead) roles.add('cluster_lead');
  }
  return { roles: [...roles], hubs };
}

// ---------- auth routes ----------

// One-time bootstrap route to create a login. Protected by SETUP_KEY so a
// stranger with the URL can't create accounts. Call it once per person, then
// you're done — nothing else needs this header.
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name, app: appAccess } = req.body || {};
  if (req.headers['x-setup-key'] !== SETUP_KEY) {
    return res.status(403).json({ error: 'Invalid setup key.' });
  }
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required.' });
  }
  try {
    await db.execute({
      sql: 'INSERT INTO users (email, password, name, app_access) VALUES (?, ?, ?, ?)',
      args: [email.trim().toLowerCase(), password, name ? name.trim() : null, appAccess === 'ops' ? 'ops' : 'main']
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

// One-time helper to set/update the display name on an account that was
// registered before the `name` field existed. Protected by SETUP_KEY, same
// as /api/auth/register.
app.post('/api/auth/set-name', async (req, res) => {
  const { email, name } = req.body || {};
  if (req.headers['x-setup-key'] !== SETUP_KEY) {
    return res.status(403).json({ error: 'Invalid setup key.' });
  }
  if (!email || !name) {
    return res.status(400).json({ error: 'email and name are required.' });
  }
  try {
    const result = await db.execute({
      sql: 'UPDATE users SET name = ? WHERE email = ?',
      args: [name.trim(), email.trim().toLowerCase()]
    });
    if (result.rowsAffected === 0) {
      return res.status(404).json({ error: 'No user with that email.' });
    }
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not update name.' });
  }
});

// Bulk-create Ops Console logins in one call. Protected by SETUP_KEY. Body:
// { rows: [ { email, name }, ... ], password?, app? }. Defaults: password
// '0000', app 'ops'. Skips any email that's already registered — safe to
// re-run without clobbering a password someone has since changed.
app.post('/api/admin/bulk-register', async (req, res) => {
  if (req.headers['x-setup-key'] !== SETUP_KEY) {
    return res.status(403).json({ error: 'Invalid setup key.' });
  }
  const { rows, password, app: appAccess } = req.body || {};
  if (!Array.isArray(rows) || !rows.length) {
    return res.status(400).json({ error: 'rows must be a non-empty array.' });
  }
  const pw = password || '0000';
  const appVal = appAccess === 'main' ? 'main' : 'ops';
  let created = 0, skipped = 0;
  try {
    for (const r of rows) {
      if (!r.email) continue;
      const result = await db.execute({
        sql: `INSERT INTO users (email, password, name, app_access)
              VALUES (?, ?, ?, ?)
              ON CONFLICT(email) DO NOTHING`,
        args: [r.email.trim().toLowerCase(), pw, r.name ? r.name.trim() : null, appVal]
      });
      if (result.rowsAffected > 0) created++; else skipped++;
    }
    res.json({ ok: true, created, skipped });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Bulk register failed.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password, app: appAccess } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required.' });
  }
  try {
    const result = await db.execute({
      sql: 'SELECT email, password, name, app_access FROM users WHERE email = ?',
      args: [email.trim().toLowerCase()]
    });
    const row = result.rows[0];
    if (!row || row.password !== password) {
      return res.status(401).json({ error: 'Wrong email or password.' });
    }
    const effectiveApp = row.app_access || 'main';
    const requestedApp = appAccess === 'ops' ? 'ops' : 'main';
    if (effectiveApp !== requestedApp) {
      return res.status(403).json({ error: 'This login is not authorized for this dashboard.' });
    }
    const token = issueToken(row.email);
    res.json({ token, email: row.email, name: row.name || null });
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
    const result = await db.execute(`
      SELECT issues.*, COALESCE(users.name, issues.logged_by) AS logged_by_name
      FROM issues
      LEFT JOIN users ON users.email = issues.logged_by
      ORDER BY issues.ts DESC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not fetch issues.' });
  }
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

// ---------- admin: seed the hub -> manager mapping ----------

// One-time (or re-run-anytime) bulk upsert of the Hub/Ops-Manager/Regional-
// Manager/Cluster-Lead mapping. Protected by SETUP_KEY, same convention as
// /api/auth/register. Body: { rows: [ { hub_name, division, ops_manager_name,
// ops_manager_email, regional_manager_name, regional_manager_email,
// cluster_lead_name, cluster_lead_email }, ... ] }
app.post('/api/admin/import-hubs', async (req, res) => {
  if (req.headers['x-setup-key'] !== SETUP_KEY) {
    return res.status(403).json({ error: 'Invalid setup key.' });
  }
  const rows = (req.body || {}).rows;
  if (!Array.isArray(rows) || !rows.length) {
    return res.status(400).json({ error: 'rows must be a non-empty array.' });
  }
  try {
    for (const r of rows) {
      await db.execute({
        sql: `INSERT INTO hub_assignments
                (hub_name, division, ops_manager_name, ops_manager_email,
                 regional_manager_name, regional_manager_email,
                 cluster_lead_name, cluster_lead_email)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)
              ON CONFLICT(hub_name) DO UPDATE SET
                division = excluded.division,
                ops_manager_name = excluded.ops_manager_name,
                ops_manager_email = excluded.ops_manager_email,
                regional_manager_name = excluded.regional_manager_name,
                regional_manager_email = excluded.regional_manager_email,
                cluster_lead_name = excluded.cluster_lead_name,
                cluster_lead_email = excluded.cluster_lead_email`,
        args: [
          r.hub_name, r.division || null,
          r.ops_manager_name || null, r.ops_manager_email ? r.ops_manager_email.toLowerCase() : null,
          r.regional_manager_name || null, r.regional_manager_email ? r.regional_manager_email.toLowerCase() : null,
          r.cluster_lead_name || null, r.cluster_lead_email ? r.cluster_lead_email.toLowerCase() : null
        ]
      });
    }
    res.json({ ok: true, imported: rows.length });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Import failed.' });
  }
});

// Read-only lookup used by the main dashboard: given a hub name, return the
// names (not emails) of whoever is assigned so a viewer can see who owns it.
app.get('/api/hub-assignments/:hub', requireAuth, async (req, res) => {
  try {
    const result = await db.execute({
      sql: `SELECT hub_name, division, ops_manager_name, regional_manager_name, cluster_lead_name
            FROM hub_assignments WHERE hub_name = ?`,
      args: [req.params.hub]
    });
    res.json(result.rows[0] || null);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not look up hub.' });
  }
});

// ---------- ops sub-dashboard routes ----------
// Ops Manager / Regional Manager / Cluster Lead each see only the issues
// under the hub(s) hub_assignments says they're responsible for, and can
// update status + leave a remark, both of which land back in the same
// `issues` table the main dashboard reads from.

app.get('/api/ops/me', requireAuth, async (req, res) => {
  try {
    const scope = await resolveOpsScope(req.user);
    res.json({ email: req.user, ...scope });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not resolve access.' });
  }
});

app.get('/api/ops/issues', requireAuth, async (req, res) => {
  try {
    const scope = await resolveOpsScope(req.user);
    if (!scope.hubs.length) {
      return res.json([]);
    }
    const placeholders = scope.hubs.map(() => '?').join(',');
    const result = await db.execute({
      sql: `
        SELECT issues.*, COALESCE(users.name, issues.logged_by) AS logged_by_name
        FROM issues
        LEFT JOIN users ON users.email = issues.logged_by
        WHERE issues.hub IN (${placeholders})
        ORDER BY issues.ts DESC
      `,
      args: scope.hubs
    });
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not fetch issues.' });
  }
});

app.patch('/api/ops/issues/:id', requireAuth, async (req, res) => {
  const { status, remarks } = req.body || {};
  if (!status) {
    return res.status(400).json({ error: 'status is required.' });
  }
  try {
    const scope = await resolveOpsScope(req.user);
    if (!scope.hubs.length) {
      return res.status(403).json({ error: 'You are not assigned to any hub.' });
    }
    const existing = await db.execute({
      sql: 'SELECT hub FROM issues WHERE id = ?',
      args: [req.params.id]
    });
    const issue = existing.rows[0];
    if (!issue) {
      return res.status(404).json({ error: 'Issue not found.' });
    }
    if (!scope.hubs.includes(issue.hub)) {
      return res.status(403).json({ error: 'This issue is outside your assigned hubs.' });
    }
    await db.execute({
      sql: `UPDATE issues SET status = ?, remarks = ?, remarks_by = ?, updated_at = ? WHERE id = ?`,
      args: [status, remarks || null, req.user, new Date().toISOString(), req.params.id]
    });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not update issue.' });
  }
});

ensureTables()
  .then(() => {
    app.listen(PORT, () => console.log(`Escalation backend listening on port ${PORT}`));
  })
  .catch(err => {
    console.error('Failed to set up tables:', err);
    process.exit(1);
  });
