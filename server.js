// server.js — Tanscar Attorneys API
require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const crypto = require('crypto');

const pool = require('./db/pool');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-this';

// ============================================================
// AUTO DATABASE SETUP — runs schema.sql on every boot (idempotent)
// ============================================================
async function setupDatabase() {
  console.log('Checking database setup...');
  try {
    const schemaPath = path.join(__dirname, 'db', 'schema.sql');
    const schema = fs.readFileSync(schemaPath, 'utf8');
    await pool.query(schema);
    console.log('Database tables are ready.');
  } catch (err) {
    console.error('Database setup error:', err.message);
    throw err;
  }
}

// Creates a default lawyer/admin account the first time the app runs,
// so there's always a way to log in on a fresh database.
async function seedDefaultAdmin() {
  const { rows } = await pool.query('SELECT COUNT(*)::int AS count FROM users');
  if (rows[0].count > 0) return;

  const tempPassword = crypto.randomBytes(6).toString('hex');
  const hash = await bcrypt.hash(tempPassword, 10);
  await pool.query(
    `INSERT INTO users (username, email, password_hash, role, full_name)
     VALUES ($1, $2, $3, 'lawyer', $4)`,
    ['admin', 'admin@tanscarattorneys.local', hash, 'System Administrator']
  );
  console.log('==============================================');
  console.log('No users found — created a default admin account:');
  console.log('  Username: admin');
  console.log('  Email:    admin@tanscarattorneys.local');
  console.log(`  Password: ${tempPassword}`);
  console.log('Log in and change this password immediately via User Management.');
  console.log('==============================================');
}

// ============================================================
// MIDDLEWARE
// ============================================================
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function protectAPI(req, res, next) {
  if (req.path === '/auth/login' || req.path === '/auth/register' || req.path === '/health') return next();

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token. Please login again.' });
  }
}
app.use('/api', protectAPI);

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden: insufficient permissions for this action' });
    }
    next();
  };
}

async function logActivity(userId, username, action, entityType, entityId, oldData, newData, req) {
  try {
    const ipAddress = req ? (req.ip || req.connection?.remoteAddress || null) : null;
    const userAgent = req ? req.headers['user-agent'] : null;
    await pool.query(
      `INSERT INTO activity_logs (user_id, username, action, entity_type, entity_id, old_data, new_data, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [userId || null, username || 'system', action, entityType, entityId,
       oldData ? JSON.stringify(oldData) : null,
       newData ? JSON.stringify(newData) : null,
       ipAddress, userAgent]
    );
  } catch (err) {
    console.error('logActivity failed:', err.message);
  }
}

// ============================================================
// CLEAN URLS — access pages without .html extension
// ============================================================
const pages = [
  'dashboard', 'clients', 'cases', 'case-detail', 'calendar', 'documents',
  'tasks', 'billing', 'expenses', 'reports', 'case-status-report', 'settings', 'users',
  'permissions', 'user-guide'
];
pages.forEach(page => {
  app.get(`/${page}`, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'pages', `${page}.html`));
  });
});

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', database: 'connected' });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
//  AUTH
// ════════════════════════════════════════════════════════════════════════════

const MAX_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  try {
    const { rows } = await pool.query(
      'SELECT id, username, email, password_hash, role, full_name, is_active, failed_attempts, locked_until FROM users WHERE email = $1',
      [email]
    );
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const user = rows[0];

    if (!user.is_active) {
      return res.status(403).json({ error: 'This account has been deactivated.' });
    }

    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      const minutesLeft = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
      return res.status(403).json({ error: `Account locked. Try again in ${minutesLeft} minute(s).` });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      const newCount = user.failed_attempts + 1;
      if (newCount >= MAX_ATTEMPTS) {
        const lockUntil = new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000);
        await pool.query('UPDATE users SET failed_attempts = $1, locked_until = $2 WHERE id = $3', [newCount, lockUntil, user.id]);
      } else {
        await pool.query('UPDATE users SET failed_attempts = $1 WHERE id = $2', [newCount, user.id]);
      }
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    await pool.query('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1', [user.id]);

    await logActivity(user.id, user.username, 'LOGIN', 'user', user.id, null, null, req);

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, fullName: user.full_name },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      fullName: user.full_name
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Public self-registration. Always creates an 'assistant' role account —
// the lowest-privilege tier — regardless of what the client sends. A lawyer
// can promote the account later via User Management if needed.
// Roles selectable on public self-registration. 'secretary' is intentionally
// excluded — only these two, and only these two, ever come from this route.
const SELF_REGISTER_ROLES = ['lawyer', 'assistant'];

app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, fullName, role } = req.body;
  if (!username || !email || !password || !fullName) {
    return res.status(400).json({ error: 'username, email, password, and fullName are required' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  const finalRole = SELF_REGISTER_ROLES.includes(role) ? role : 'assistant';
  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO users (username, email, password_hash, role, full_name)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, username, email, role, full_name`,
      [username, email, hash, finalRole, fullName]
    );
    await logActivity(rows[0].id, rows[0].username, 'CREATE', 'user', rows[0].id, null, rows[0], req);
    res.status(201).json({ success: true, message: 'Account created. You can now log in.' });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Username or email already exists' });
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/logout', async (req, res) => {
  await logActivity(req.user.id, req.user.email, 'LOGOUT', 'user', req.user.id, null, null, req);
  res.json({ success: true });
});

app.get('/api/auth/me', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, username, email, role, full_name, is_active FROM users WHERE id = $1',
      [req.user.id]
    );
    if (!rows.length || !rows[0].is_active) return res.status(401).json({ error: 'Account not found or inactive' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
//  USERS
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/users', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, username, email, role, full_name, phone, is_active, failed_attempts, locked_until, created_at FROM users ORDER BY full_name'
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/users/:id', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, username, email, role, full_name, phone, is_active, created_at FROM users WHERE id = $1',
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/users', requireRole('lawyer'), async (req, res) => {
  const { username, email, password, role, fullName, phone } = req.body;
  if (!username || !email || !password || !role || !fullName) {
    return res.status(400).json({ error: 'username, email, password, role, fullName are required' });
  }
  if (!['lawyer', 'secretary', 'assistant'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO users (username, email, password_hash, role, full_name, phone)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, username, email, role, full_name, phone, is_active, created_at`,
      [username, email, hash, role, fullName, phone || null]
    );
    await logActivity(req.user.id, req.user.email, 'CREATE', 'user', rows[0].id, null, rows[0], req);
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Username or email already exists' });
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/users/:id', requireRole('lawyer'), async (req, res) => {
  const { fullName, username, email, phone, role, isActive } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE users SET
        full_name = COALESCE($1, full_name),
        username  = COALESCE($2, username),
        email     = COALESCE($3, email),
        phone     = COALESCE($4, phone),
        role      = COALESCE($5, role),
        is_active = COALESCE($6, is_active)
       WHERE id = $7
       RETURNING id, username, email, role, full_name, phone, is_active`,
      [fullName, username, email, phone, role, isActive, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    await logActivity(req.user.id, req.user.email, 'UPDATE', 'user', req.params.id, null, rows[0], req);
    res.json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Username or email already in use' });
    res.status(500).json({ error: err.message });
  }
});

// Hard delete. Guards against removing your own account (would lock you out
// mid-session) and against removing the last active lawyer account (would
// lock everyone out of admin functions). All references from other tables
// (created_by, assigned_to, etc.) are ON DELETE SET NULL, so case/client
// history is preserved even after the user record itself is gone.
app.delete('/api/users/:id', requireRole('lawyer'), async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (targetId === req.user.id) {
    return res.status(400).json({ error: 'You cannot delete your own account while logged in.' });
  }
  try {
    const { rows: target } = await pool.query('SELECT role FROM users WHERE id = $1', [targetId]);
    if (!target.length) return res.status(404).json({ error: 'User not found' });

    if (target[0].role === 'lawyer') {
      const { rows: lawyerCount } = await pool.query(
        `SELECT COUNT(*)::int AS count FROM users WHERE role = 'lawyer' AND is_active = TRUE AND id != $1`,
        [targetId]
      );
      if (lawyerCount[0].count === 0) {
        return res.status(400).json({ error: 'Cannot delete the last remaining lawyer account.' });
      }
    }

    await pool.query('DELETE FROM users WHERE id = $1', [targetId]);
    await logActivity(req.user.id, req.user.email, 'DELETE', 'user', targetId, target[0], null, req);
    res.json({ success: true, message: 'User deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/users/:id/reset-password', requireRole('lawyer'), async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'newPassword must be at least 6 characters' });
  }
  try {
    const hash = await bcrypt.hash(newPassword, 10);
    const { rowCount } = await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, message: 'Password reset' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/users/:id/unlock', requireRole('lawyer'), async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1',
      [req.params.id]
    );
    if (!rowCount) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, message: 'Account unlocked' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
//  CLIENTS
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/clients', async (req, res) => {
  const { q } = req.query;
  try {
    let query = 'SELECT * FROM clients';
    const params = [];
    if (q) {
      params.push(`%${q}%`);
      query += ` WHERE full_name ILIKE $1 OR phone ILIKE $1 OR email ILIKE $1`;
    }
    query += ' ORDER BY full_name';
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/clients/:id', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM clients WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Client not found' });
    const { rows: cases } = await pool.query(
      `SELECT c.id, c.case_number, c.case_title, c.status
       FROM cases c
       WHERE c.client_id = $1 ORDER BY c.created_at DESC`,
      [req.params.id]
    );
    res.json({ ...rows[0], cases });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/clients', async (req, res) => {
  const { fullName, phone, email, address, nationalId, notes } = req.body;
  if (!fullName) return res.status(400).json({ error: 'fullName is required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO clients (full_name, phone, email, address, national_id, notes, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [fullName, phone || null, email || null, address || null, nationalId || null, notes || null, req.user.id]
    );
    await logActivity(req.user.id, req.user.email, 'CREATE', 'client', rows[0].id, null, rows[0], req);
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/clients/:id', async (req, res) => {
  const { fullName, phone, email, address, nationalId, notes } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE clients SET
        full_name   = COALESCE($1, full_name),
        phone       = COALESCE($2, phone),
        email       = COALESCE($3, email),
        address     = COALESCE($4, address),
        national_id = COALESCE($5, national_id),
        notes       = COALESCE($6, notes)
       WHERE id = $7 RETURNING *`,
      [fullName, phone, email, address, nationalId, notes, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Client not found' });
    await logActivity(req.user.id, req.user.email, 'UPDATE', 'client', req.params.id, null, rows[0], req);
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/clients/:id', requireRole('lawyer'), async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM clients WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Client not found' });
    await logActivity(req.user.id, req.user.email, 'DELETE', 'client', req.params.id, null, null, req);
    res.json({ success: true });
  } catch (err) {
    if (err.code === '23503') {
      return res.status(409).json({ error: 'Cannot delete a client with existing cases. Close their cases instead.' });
    }
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
//  CASE CATEGORIES
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/case-categories', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM case_categories WHERE is_active = TRUE ORDER BY name');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/case-categories', requireRole('lawyer'), async (req, res) => {
  const { name, code } = req.body;
  if (!name || !code) return res.status(400).json({ error: 'name and code are required' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO case_categories (name, code) VALUES ($1, $2) RETURNING *',
      [name, code.toUpperCase()]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'A category with that name or code already exists' });
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/case-categories/:id', requireRole('lawyer'), async (req, res) => {
  const { name, code, isActive } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE case_categories SET
        name = COALESCE($1, name), code = COALESCE($2, code), is_active = COALESCE($3, is_active)
       WHERE id = $4 RETURNING *`,
      [name, code ? code.toUpperCase() : null, isActive, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Category not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/case-categories/:id', requireRole('lawyer'), async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM case_categories WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Category not found' });
    res.json({ success: true });
  } catch (err) {
    if (err.code === '23503') {
      await pool.query('UPDATE case_categories SET is_active = FALSE WHERE id = $1', [req.params.id]);
      return res.json({ success: true, message: 'Category is in use by existing cases — deactivated instead of deleted.' });
    }
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
//  CASE STATUSES
// ════════════════════════════════════════════════════════════════════════════

function slugify(label) {
  return String(label).toLowerCase().trim().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
}

app.get('/api/case-statuses', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM case_statuses WHERE is_active = TRUE ORDER BY sort_order, id');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/case-statuses', requireRole('lawyer'), async (req, res) => {
  const { label, isClosed } = req.body;
  if (!label) return res.status(400).json({ error: 'label is required' });
  const name = slugify(label);
  if (!name) return res.status(400).json({ error: 'label must contain at least one letter or number' });
  try {
    const { rows: maxRows } = await pool.query('SELECT COALESCE(MAX(sort_order), 0) + 1 AS next FROM case_statuses');
    const { rows } = await pool.query(
      'INSERT INTO case_statuses (name, label, is_closed, sort_order) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, label, !!isClosed, maxRows[0].next]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'A status with that name already exists' });
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/case-statuses/:id', requireRole('lawyer'), async (req, res) => {
  const { label, isClosed, isActive } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE case_statuses SET
        label = COALESCE($1, label), is_closed = COALESCE($2, is_closed), is_active = COALESCE($3, is_active)
       WHERE id = $4 RETURNING *`,
      [label, isClosed, isActive, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Status not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/case-statuses/:id', requireRole('lawyer'), async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM case_statuses WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Status not found' });
    res.json({ success: true });
  } catch (err) {
    if (err.code === '23503') {
      await pool.query('UPDATE case_statuses SET is_active = FALSE WHERE id = $1', [req.params.id]);
      return res.json({ success: true, message: 'Status is in use by existing cases — deactivated instead of deleted.' });
    }
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
//  EXPENSE CATEGORIES
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/expense-categories', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM expense_categories WHERE is_active = TRUE ORDER BY label');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/expense-categories', requireRole('lawyer'), async (req, res) => {
  const { label } = req.body;
  if (!label) return res.status(400).json({ error: 'label is required' });
  const name = slugify(label);
  if (!name) return res.status(400).json({ error: 'label must contain at least one letter or number' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO expense_categories (name, label) VALUES ($1, $2) RETURNING *',
      [name, label]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'A category with that name already exists' });
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/expense-categories/:id', requireRole('lawyer'), async (req, res) => {
  const { label, isActive } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE expense_categories SET label = COALESCE($1, label), is_active = COALESCE($2, is_active)
       WHERE id = $3 RETURNING *`,
      [label, isActive, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Category not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/expense-categories/:id', requireRole('lawyer'), async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM expense_categories WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Category not found' });
    res.json({ success: true });
  } catch (err) {
    if (err.code === '23503') {
      await pool.query('UPDATE expense_categories SET is_active = FALSE WHERE id = $1', [req.params.id]);
      return res.json({ success: true, message: 'Category is in use by existing expenses — deactivated instead of deleted.' });
    }
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
//  CASES (the hub)
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/cases', async (req, res) => {
  const { status, client_id, assigned_lawyer, q } = req.query;
  try {
    const conditions = [];
    const values = [];
    if (status) { values.push(status); conditions.push(`c.status = $${values.length}`); }
    if (client_id) { values.push(client_id); conditions.push(`c.client_id = $${values.length}`); }
    if (assigned_lawyer) { values.push(assigned_lawyer); conditions.push(`c.assigned_lawyer = $${values.length}`); }
    if (q) { values.push(`%${q}%`); conditions.push(`(c.case_title ILIKE $${values.length} OR c.case_number ILIKE $${values.length} OR cl.full_name ILIKE $${values.length})`); }
    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

    const { rows } = await pool.query(`
      SELECT c.*, cl.full_name AS client_name,
        u.full_name AS assigned_lawyer_name,
        -- The next court date is recorded on the Court Date form itself
        -- (filled in after attending court), so it's whatever was noted on
        -- the most recently attended hearing — not a future hearing_date,
        -- since hearing_date is always the date of a visit already made.
        (SELECT h.next_court_date FROM hearings h WHERE h.case_id = c.id ORDER BY h.hearing_date DESC, h.id DESC LIMIT 1) AS next_hearing_date,
        (SELECT COUNT(*)::int FROM tasks t WHERE t.case_id = c.id AND t.status = 'pending' AND t.due_date < CURRENT_DATE) AS overdue_task_count
      FROM cases c
      LEFT JOIN clients cl ON cl.id = c.client_id
      LEFT JOIN users u ON u.id = c.assigned_lawyer
      ${where}
      ORDER BY c.created_at DESC
    `, values);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/cases/:id', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.*, cl.full_name AS client_name, cl.phone AS client_phone, cl.email AS client_email,
        u.full_name AS assigned_lawyer_name, cb.full_name AS created_by_name
      FROM cases c
      LEFT JOIN clients cl ON cl.id = c.client_id
      LEFT JOIN users u ON u.id = c.assigned_lawyer
      LEFT JOIN users cb ON cb.id = c.created_by
      WHERE c.id = $1
    `, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Case not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Case status is the same Time Chart stage vocabulary as "Court Proceeding
// Type" on the Court Date form — rather than letting the two be set
// independently (and silently drift apart), the case's status always
// mirrors whatever proceeding type was recorded on its most recent Court
// Date. slugify() already turns "1st PTC" into "1st_ptc" via the generic
// non-alnum-run rule, which doesn't match the case_statuses seed name
// ("first_ptc") — so this needs its own explicit map, not slugify().
const PROCEEDING_TYPE_TO_STATUS = {
  'mention': 'mention', '1st ptc': 'first_ptc', 'mediation': 'mediation',
  'hearing': 'hearing', 'final ptc': 'final_ptc', 'judgment': 'judgment', 'ruling': 'ruling'
};
function statusFromProceedingType(proceedingType) {
  if (!proceedingType) return null;
  return PROCEEDING_TYPE_TO_STATUS[String(proceedingType).trim().toLowerCase()] || null;
}
// Re-derives a case's status from its most recently recorded Court Date
// (by hearing_date DESC, id DESC — same "what's next" ordering used
// everywhere else) — call after any hearing create/update/delete so the
// status badge never goes stale. Returns the derived status, or null if
// nothing changed (no hearings, or the proceeding type isn't one of the
// seven Time Chart stages).
async function syncCaseStatusFromLatestHearing(db, caseId) {
  const { rows } = await db.query(
    'SELECT proceeding_type FROM hearings WHERE case_id = $1 ORDER BY hearing_date DESC, id DESC LIMIT 1',
    [caseId]
  );
  const status = rows.length ? statusFromProceedingType(rows[0].proceeding_type) : null;
  if (status) await db.query('UPDATE cases SET status = $1 WHERE id = $2', [status, caseId]);
  return status;
}

app.post('/api/cases', requireRole('lawyer', 'secretary'), async (req, res) => {
  const {
    clientId, newClient, caseNumber, description, opposingParty, court, region,
    caseYear, parties, remarks, claimAmount, status,
    // Time Chart & Court Records fields — the New Case form is the sheet
    // itself, so this first entry becomes the case's first Court Date row
    // (see the hearings INSERT below), exactly like every subsequent visit
    // recorded from the Court Dates tab.
    presidingJudge, proceedingType, counselPlaintiff, counselDefendant,
    courtClerk, lastCourtOrder, prayerSought, courtOrderDirection, courtStartTime, courtEndTime,
    consultationStartTime, consultationEndTime, recordDate, recordedBy, nextCourtDate
  } = req.body;
  if (!caseNumber) {
    return res.status(400).json({ error: 'caseNumber is required' });
  }

  const dbClient = await pool.connect();
  try {
    await dbClient.query('BEGIN');

    // Client is optional at intake — a case can be created without one and
    // have it added later.
    let finalClientId = clientId || null;
    if (!finalClientId && newClient) {
      if (!newClient.fullName) throw new Error('newClient.fullName is required');
      const { rows: clientRows } = await dbClient.query(
        `INSERT INTO clients (full_name, phone, email, address, national_id, created_by)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
        [newClient.fullName, newClient.phone || null, newClient.email || null,
         newClient.address || null, newClient.nationalId || null, req.user.id]
      );
      finalClientId = clientRows[0].id;
    }

    // case_title has no dedicated input anymore — derive something
    // meaningful so every other part of the app that displays it
    // (lists, headers, timelines) still has a sensible label.
    const finalCaseTitle = (parties && parties.trim()) ? parties.trim() : caseNumber.trim();

    const { rows } = await dbClient.query(
      `INSERT INTO cases (
         case_number, client_id, case_title, description, opposing_party, court, region,
         case_year, parties, remarks, claim_amount, status, created_by
       )
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,COALESCE($12, 'mention'),$13)
       RETURNING *`,
      [caseNumber.trim(), finalClientId, finalCaseTitle, description || null,
       opposingParty || null, court || null, region || null,
       caseYear || null, parties || null, remarks || null, claimAmount || null, status || null, req.user.id]
    );
    const newCase = rows[0];

    // The Time Chart is filled out fresh every time the matter is in
    // court — this first pass (taken at intake) becomes hearing #1, using
    // the same Court Date form fields as every later visit. The hearing
    // date itself always defaults to today (no separate "Proceeding Date"
    // input on the New Case form — the case is created on the day of the
    // visit it represents).
    await dbClient.query(
      `INSERT INTO hearings (
         case_id, hearing_date, court, region, presiding_judge, proceeding_type, counsel_plaintiff, counsel_defendant,
         court_clerk, last_court_order, prayer_sought, court_order_direction, court_start_time, court_end_time,
         consultation_start_time, consultation_end_time, record_date, recorded_by, next_court_date, created_by
       )
       VALUES ($1,CURRENT_DATE,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
      [newCase.id, court || null, region || null, presidingJudge || null, proceedingType || null,
       counselPlaintiff || null, counselDefendant || null, courtClerk || null, lastCourtOrder || null,
       prayerSought || null, courtOrderDirection || null, courtStartTime || null, courtEndTime || null,
       consultationStartTime || null, consultationEndTime || null, recordDate || null, recordedBy || null,
       nextCourtDate || null, req.user.id]
    );

    const derivedStatus = await syncCaseStatusFromLatestHearing(dbClient, newCase.id);
    if (derivedStatus) newCase.status = derivedStatus;

    await dbClient.query('COMMIT');
    await logActivity(req.user.id, req.user.email, 'CREATE', 'case', newCase.id, null, newCase, req);
    res.status(201).json(newCase);
  } catch (err) {
    await dbClient.query('ROLLBACK');
    if (err.code === '23505' && err.constraint && err.constraint.includes('case_number')) {
      return res.status(400).json({ error: `Case number "${caseNumber}" is already in use` });
    }
    res.status(400).json({ error: err.message });
  } finally {
    dbClient.release();
  }
});

app.put('/api/cases/:id', requireRole('lawyer', 'secretary'), async (req, res) => {
  const {
    caseTitle, status, description, assignedLawyer, opposingParty, court, region,
    caseYear, parties, remarks, claimAmount, clientId, caseNumber,
    // Time Chart & Court Records fields — Edit Case mirrors every field on
    // the New Case form, so saving it updates the case's most recent Court
    // Date entry the same way New Case submission creates the first one.
    presidingJudge, proceedingType, proceedingDate, counselPlaintiff, counselDefendant,
    courtClerk, lastCourtOrder, prayerSought, courtOrderDirection, courtStartTime, courtEndTime,
    consultationStartTime, consultationEndTime, recordDate, recordedBy, nextCourtDate
  } = req.body;
  // NUMERIC/DATE/TIME columns reject '' outright, so an empty (but present)
  // form field must become null to fall through the COALESCE below and
  // leave the existing value untouched — the same as if it weren't sent.
  const caseYearN = caseYear || null;
  const claimAmountN = (claimAmount === '' || claimAmount === undefined) ? null : claimAmount;
  const clientIdN = clientId || null;
  const courtStartTimeN = courtStartTime || null;
  const courtEndTimeN = courtEndTime || null;
  const consultationStartTimeN = consultationStartTime || null;
  const consultationEndTimeN = consultationEndTime || null;
  const recordDateN = recordDate || null;
  const proceedingDateN = proceedingDate || null;
  const nextCourtDateN = nextCourtDate || null;

  const dbClient = await pool.connect();
  try {
    await dbClient.query('BEGIN');
    const { rows: before } = await dbClient.query('SELECT * FROM cases WHERE id = $1 FOR UPDATE', [req.params.id]);
    if (!before.length) { await dbClient.query('ROLLBACK'); return res.status(404).json({ error: 'Case not found' }); }

    const { rows } = await dbClient.query(
      `UPDATE cases SET
        case_number              = COALESCE($1, case_number),
        client_id                = COALESCE($2, client_id),
        case_title               = COALESCE($3, case_title),
        status                   = COALESCE($4, status),
        description              = COALESCE($5, description),
        assigned_lawyer          = COALESCE($6, assigned_lawyer),
        opposing_party           = COALESCE($7, opposing_party),
        court                    = COALESCE($8, court),
        region                   = COALESCE($9, region),
        case_year                = COALESCE($10, case_year),
        parties                  = COALESCE($11, parties),
        remarks                  = COALESCE($12, remarks),
        claim_amount             = COALESCE($13, claim_amount)
       WHERE id = $14 RETURNING *`,
      [caseNumber ? caseNumber.trim() : null, clientIdN, caseTitle, status, description,
       assignedLawyer, opposingParty, court, region, caseYearN, parties, remarks, claimAmountN, req.params.id]
    );
    const updatedCase = rows[0];

    const { rows: latestHearingRows } = await dbClient.query(
      'SELECT id FROM hearings WHERE case_id = $1 ORDER BY hearing_date DESC, id DESC LIMIT 1',
      [req.params.id]
    );
    if (latestHearingRows.length) {
      await dbClient.query(
        `UPDATE hearings SET
          court                    = COALESCE($1, court),
          region                   = COALESCE($2, region),
          hearing_date             = COALESCE($3, hearing_date),
          presiding_judge          = COALESCE($4, presiding_judge),
          proceeding_type          = COALESCE($5, proceeding_type),
          counsel_plaintiff        = COALESCE($6, counsel_plaintiff),
          counsel_defendant        = COALESCE($7, counsel_defendant),
          court_clerk              = COALESCE($8, court_clerk),
          last_court_order         = COALESCE($9, last_court_order),
          prayer_sought            = COALESCE($10, prayer_sought),
          court_order_direction    = COALESCE($11, court_order_direction),
          court_start_time         = COALESCE($12, court_start_time),
          court_end_time           = COALESCE($13, court_end_time),
          consultation_start_time  = COALESCE($14, consultation_start_time),
          consultation_end_time    = COALESCE($15, consultation_end_time),
          record_date              = COALESCE($16, record_date),
          recorded_by              = COALESCE($17, recorded_by),
          next_court_date          = COALESCE($18, next_court_date)
         WHERE id = $19`,
        [court, region, proceedingDateN, presidingJudge, proceedingType, counselPlaintiff, counselDefendant,
         courtClerk, lastCourtOrder, prayerSought, courtOrderDirection, courtStartTimeN, courtEndTimeN,
         consultationStartTimeN, consultationEndTimeN, recordDateN, recordedBy, nextCourtDateN,
         latestHearingRows[0].id]
      );
    } else {
      await dbClient.query(
        `INSERT INTO hearings (
           case_id, hearing_date, court, region, presiding_judge, proceeding_type, counsel_plaintiff, counsel_defendant,
           court_clerk, last_court_order, prayer_sought, court_order_direction, court_start_time, court_end_time,
           consultation_start_time, consultation_end_time, record_date, recorded_by, next_court_date, created_by
         )
         VALUES ($1,COALESCE($2, CURRENT_DATE),$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
        [req.params.id, proceedingDateN, court || null, region || null, presidingJudge || null, proceedingType || null,
         counselPlaintiff || null, counselDefendant || null, courtClerk || null, lastCourtOrder || null,
         prayerSought || null, courtOrderDirection || null, courtStartTimeN, courtEndTimeN,
         consultationStartTimeN, consultationEndTimeN, recordDateN, recordedBy || null,
         nextCourtDateN, req.user.id]
      );
    }

    const derivedStatus = await syncCaseStatusFromLatestHearing(dbClient, req.params.id);
    if (derivedStatus) updatedCase.status = derivedStatus;

    await dbClient.query('COMMIT');
    await logActivity(req.user.id, req.user.email, 'UPDATE', 'case', req.params.id, before[0], updatedCase, req);
    res.json(updatedCase);
  } catch (err) {
    await dbClient.query('ROLLBACK');
    if (err.code === '23505' && err.constraint && err.constraint.includes('case_number')) {
      return res.status(400).json({ error: `Case number "${caseNumber}" is already in use` });
    }
    if (err.code === '23503') return res.status(400).json({ error: 'Invalid status' });
    res.status(400).json({ error: err.message });
  } finally {
    dbClient.release();
  }
});

app.delete('/api/cases/:id', requireRole('lawyer'), async (req, res) => {
  try {
    const { rows: before } = await pool.query('SELECT * FROM cases WHERE id = $1', [req.params.id]);
    if (!before.length) return res.status(404).json({ error: 'Case not found' });

    const { rows: docs } = await pool.query('SELECT file_path FROM documents WHERE case_id = $1', [req.params.id]);

    await pool.query('DELETE FROM cases WHERE id = $1', [req.params.id]);

    docs.forEach(d => {
      const fullPath = path.join(__dirname, 'uploads', d.file_path);
      fs.unlink(fullPath, () => {});
    });

    await logActivity(req.user.id, req.user.email, 'DELETE', 'case', req.params.id, before[0], null, req);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
//  TIMELINE (computed, not stored)
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/cases/:id/timeline', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT hearing_date AS date, 'hearing' AS type,
             ('Court Date: ' || COALESCE(proceeding_type, 'Court date') || COALESCE(' — ' || court_order_direction, '')) AS description
        FROM hearings WHERE case_id = $1
      UNION ALL
      SELECT uploaded_at AS date, 'document' AS type, ('Document uploaded: ' || filename) AS description
        FROM documents WHERE case_id = $1
      UNION ALL
      SELECT completed_at AS date, 'task' AS type, ('Task completed: ' || title) AS description
        FROM tasks WHERE case_id = $1 AND status = 'done' AND completed_at IS NOT NULL
      UNION ALL
      SELECT expense_date::timestamp AS date, 'expense' AS type,
             ('Expense recorded: ' || description || ' (' || amount || ')') AS description
        FROM expenses WHERE case_id = $1
      UNION ALL
      SELECT p.created_at AS date, 'payment' AS type,
             ('Payment received: ' || p.amount || ' (' || p.payment_method || ')') AS description
        FROM payments p WHERE p.case_id = $1
      UNION ALL
      SELECT created_at AS date, 'note' AS type, ('Note added') AS description
        FROM notes WHERE case_id = $1
      ORDER BY date DESC
    `, [req.params.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
//  HEARINGS
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/hearings', async (req, res) => {
  const { from, to } = req.query;
  try {
    const conditions = [];
    const values = [];
    if (from) { values.push(from); conditions.push(`h.hearing_date >= $${values.length}`); }
    if (to) { values.push(to); conditions.push(`h.hearing_date <= $${values.length}`); }
    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
    const { rows } = await pool.query(`
      SELECT h.*, c.case_number, c.case_title, cl.full_name AS client_name
      FROM hearings h
      JOIN cases c ON c.id = h.case_id
      LEFT JOIN clients cl ON cl.id = c.client_id
      ${where}
      ORDER BY h.hearing_date ASC
    `, values);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/cases/:id/hearings', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM hearings WHERE case_id = $1 ORDER BY hearing_date DESC, id DESC', [req.params.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/cases/:id/hearings', async (req, res) => {
  const {
    hearingDate, court, region, presidingJudge, proceedingType, counselPlaintiff, counselDefendant,
    courtClerk, lastCourtOrder, prayerSought, courtOrderDirection, courtStartTime, courtEndTime,
    consultationStartTime, consultationEndTime, recordDate, recordedBy, nextCourtDate
  } = req.body;
  if (!hearingDate) return res.status(400).json({ error: 'hearingDate (Court Date) is required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO hearings (
         case_id, hearing_date, court, region, presiding_judge, proceeding_type, counsel_plaintiff, counsel_defendant,
         court_clerk, last_court_order, prayer_sought, court_order_direction, court_start_time, court_end_time,
         consultation_start_time, consultation_end_time, record_date, recorded_by, next_court_date, created_by
       )
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
       RETURNING *`,
      [req.params.id, hearingDate, court || null, region || null, presidingJudge || null, proceedingType || null,
       counselPlaintiff || null, counselDefendant || null, courtClerk || null, lastCourtOrder || null,
       prayerSought || null, courtOrderDirection || null, courtStartTime || null, courtEndTime || null,
       consultationStartTime || null, consultationEndTime || null, recordDate || null, recordedBy || null,
       nextCourtDate || null, req.user.id]
    );
    await syncCaseStatusFromLatestHearing(pool, req.params.id);
    await logActivity(req.user.id, req.user.email, 'CREATE', 'hearing', rows[0].id, null, rows[0], req);
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/hearings/:id', async (req, res) => {
  const {
    hearingDate, court, region, presidingJudge, proceedingType, counselPlaintiff, counselDefendant,
    courtClerk, lastCourtOrder, prayerSought, courtOrderDirection, courtStartTime, courtEndTime,
    consultationStartTime, consultationEndTime, recordDate, recordedBy, nextCourtDate
  } = req.body;
  // TIME/DATE columns reject '' — an empty (but present) form field must
  // become null so it falls through COALESCE instead of erroring.
  const courtStartTimeN = courtStartTime || null;
  const courtEndTimeN = courtEndTime || null;
  const consultationStartTimeN = consultationStartTime || null;
  const consultationEndTimeN = consultationEndTime || null;
  const recordDateN = recordDate || null;
  const nextCourtDateN = nextCourtDate || null;
  try {
    const { rows } = await pool.query(
      `UPDATE hearings SET
        hearing_date             = COALESCE($1, hearing_date),
        court                    = COALESCE($2, court),
        region                   = COALESCE($3, region),
        presiding_judge          = COALESCE($4, presiding_judge),
        proceeding_type          = COALESCE($5, proceeding_type),
        counsel_plaintiff        = COALESCE($6, counsel_plaintiff),
        counsel_defendant        = COALESCE($7, counsel_defendant),
        court_clerk              = COALESCE($8, court_clerk),
        last_court_order         = COALESCE($9, last_court_order),
        prayer_sought            = COALESCE($10, prayer_sought),
        court_order_direction    = COALESCE($11, court_order_direction),
        court_start_time         = COALESCE($12, court_start_time),
        court_end_time           = COALESCE($13, court_end_time),
        consultation_start_time  = COALESCE($14, consultation_start_time),
        consultation_end_time    = COALESCE($15, consultation_end_time),
        record_date              = COALESCE($16, record_date),
        recorded_by              = COALESCE($17, recorded_by),
        next_court_date          = COALESCE($18, next_court_date)
       WHERE id = $19 RETURNING *`,
      [hearingDate, court, region, presidingJudge, proceedingType, counselPlaintiff, counselDefendant,
       courtClerk, lastCourtOrder, prayerSought, courtOrderDirection, courtStartTimeN, courtEndTimeN,
       consultationStartTimeN, consultationEndTimeN, recordDateN, recordedBy, nextCourtDateN, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Hearing not found' });
    await syncCaseStatusFromLatestHearing(pool, rows[0].case_id);
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/hearings/:id', requireRole('lawyer', 'secretary'), async (req, res) => {
  try {
    const { rows: before } = await pool.query('SELECT case_id FROM hearings WHERE id = $1', [req.params.id]);
    if (!before.length) return res.status(404).json({ error: 'Hearing not found' });
    await pool.query('DELETE FROM hearings WHERE id = $1', [req.params.id]);
    await syncCaseStatusFromLatestHearing(pool, before[0].case_id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
//  APPOINTMENTS
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/appointments', async (req, res) => {
  const { from, to, client_id } = req.query;
  try {
    const conditions = [];
    const values = [];
    if (from) { values.push(from); conditions.push(`a.appointment_date >= $${values.length}`); }
    if (to) { values.push(to); conditions.push(`a.appointment_date <= $${values.length}`); }
    if (client_id) { values.push(client_id); conditions.push(`a.client_id = $${values.length}`); }
    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
    const { rows } = await pool.query(`
      SELECT a.*, cl.full_name AS client_name, c.case_number
      FROM appointments a
      JOIN clients cl ON cl.id = a.client_id
      LEFT JOIN cases c ON c.id = a.case_id
      ${where}
      ORDER BY a.appointment_date ASC
    `, values);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/cases/:id/appointments', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM appointments WHERE case_id = $1 ORDER BY appointment_date DESC', [req.params.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/appointments', async (req, res) => {
  const { caseId, clientId, appointmentDate, purpose, consultationFee } = req.body;
  if (!clientId || !appointmentDate) {
    return res.status(400).json({ error: 'clientId and appointmentDate are required' });
  }
  try {
    const { rows } = await pool.query(
      `INSERT INTO appointments (case_id, client_id, appointment_date, purpose, consultation_fee, created_by)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [caseId || null, clientId, appointmentDate, purpose || null, consultationFee || null, req.user.id]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/appointments/:id', async (req, res) => {
  const { appointmentDate, purpose, consultationFee, feePaid } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE appointments SET
        appointment_date = COALESCE($1, appointment_date),
        purpose          = COALESCE($2, purpose),
        consultation_fee = COALESCE($3, consultation_fee),
        fee_paid         = COALESCE($4, fee_paid)
       WHERE id = $5 RETURNING *`,
      [appointmentDate, purpose, consultationFee, feePaid, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Appointment not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/appointments/:id', requireRole('lawyer', 'secretary'), async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM appointments WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Appointment not found' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/calendar', async (req, res) => {
  const { from, to } = req.query;
  try {
    const hConditions = [];
    const aConditions = [];
    const values = [];
    if (from) { values.push(from); hConditions.push(`h.hearing_date >= $${values.length}`); aConditions.push(`a.appointment_date >= $${values.length}`); }
    if (to) { values.push(to); hConditions.push(`h.hearing_date <= $${values.length}`); aConditions.push(`a.appointment_date <= $${values.length}`); }
    const hWhere = hConditions.length ? 'WHERE ' + hConditions.join(' AND ') : '';
    const aWhere = aConditions.length ? 'WHERE ' + aConditions.join(' AND ') : '';

    const { rows: hearings } = await pool.query(`
      SELECT h.id, h.hearing_date AS date, 'hearing' AS type, h.court, h.proceeding_type AS purpose,
             c.id AS case_id, c.case_number, c.case_title, cl.full_name AS client_name
      FROM hearings h
      JOIN cases c ON c.id = h.case_id
      LEFT JOIN clients cl ON cl.id = c.client_id
      ${hWhere}
    `, values);

    const { rows: appointments } = await pool.query(`
      SELECT a.id, a.appointment_date AS date, 'appointment' AS type, a.purpose,
             c.id AS case_id, c.case_number, c.case_title, cl.full_name AS client_name
      FROM appointments a
      LEFT JOIN cases c ON c.id = a.case_id
      JOIN clients cl ON cl.id = a.client_id
      ${aWhere}
    `, values);

    const combined = [...hearings, ...appointments].sort((x, y) => new Date(x.date) - new Date(y.date));
    res.json(combined);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
//  DOCUMENTS
// ════════════════════════════════════════════════════════════════════════════

const uploadsRoot = path.join(__dirname, 'uploads');

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(uploadsRoot, 'cases', String(req.params.id));
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + crypto.randomBytes(6).toString('hex');
    cb(null, unique + path.extname(file.originalname));
  }
});
const upload = multer({ storage, limits: { fileSize: 25 * 1024 * 1024 } });

app.post('/api/cases/:id/documents', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const { category } = req.body;
  try {
    const relativePath = path.join('cases', String(req.params.id), req.file.filename);
    const { rows } = await pool.query(
      `INSERT INTO documents (case_id, category, filename, file_path, file_size, mime_type, uploaded_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [req.params.id, category || 'other', req.file.originalname, relativePath, req.file.size, req.file.mimetype, req.user.id]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/cases/:id/documents', async (req, res) => {
  const { category } = req.query;
  try {
    const values = [req.params.id];
    let query = 'SELECT * FROM documents WHERE case_id = $1';
    if (category) { values.push(category); query += ` AND category = $2`; }
    query += ' ORDER BY uploaded_at DESC';
    const { rows } = await pool.query(query, values);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/documents/:id/download', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM documents WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Document not found' });
    const fullPath = path.join(uploadsRoot, rows[0].file_path);
    res.download(fullPath, rows[0].filename);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/documents/:id', requireRole('lawyer', 'secretary'), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM documents WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Document not found' });
    await pool.query('DELETE FROM documents WHERE id = $1', [req.params.id]);
    fs.unlink(path.join(uploadsRoot, rows[0].file_path), () => {});
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
//  TASKS
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/tasks', async (req, res) => {
  const { status, assigned_to, overdue } = req.query;
  try {
    const conditions = [];
    const values = [];
    if (status) { values.push(status); conditions.push(`t.status = $${values.length}`); }
    if (assigned_to) { values.push(assigned_to); conditions.push(`t.assigned_to = $${values.length}`); }
    if (overdue === 'true') { conditions.push(`t.status = 'pending' AND t.due_date < CURRENT_DATE`); }
    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
    const { rows } = await pool.query(`
      SELECT t.*, c.case_number, c.case_title, u.full_name AS assigned_to_name
      FROM tasks t
      JOIN cases c ON c.id = t.case_id
      LEFT JOIN users u ON u.id = t.assigned_to
      ${where}
      ORDER BY t.due_date ASC NULLS LAST
    `, values);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/cases/:id/tasks', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT t.*, u.full_name AS assigned_to_name
      FROM tasks t LEFT JOIN users u ON u.id = t.assigned_to
      WHERE case_id = $1 ORDER BY t.due_date ASC NULLS LAST
    `, [req.params.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/cases/:id/tasks', async (req, res) => {
  const { title, dueDate, assignedTo, priority } = req.body;
  if (!title) return res.status(400).json({ error: 'title is required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO tasks (case_id, title, due_date, assigned_to, priority, created_by)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [req.params.id, title, dueDate || null, assignedTo || null, priority || 'medium', req.user.id]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/tasks/:id', async (req, res) => {
  const { title, dueDate, assignedTo, priority, status } = req.body;
  try {
    const completedAt = status === 'done' ? new Date() : (status === 'pending' ? null : undefined);
    const { rows } = await pool.query(
      `UPDATE tasks SET
        title       = COALESCE($1, title),
        due_date    = COALESCE($2, due_date),
        assigned_to = COALESCE($3, assigned_to),
        priority    = COALESCE($4, priority),
        status      = COALESCE($5, status),
        completed_at = CASE WHEN $5 = 'done' THEN CURRENT_TIMESTAMP WHEN $5 = 'pending' THEN NULL ELSE completed_at END
       WHERE id = $6 RETURNING *`,
      [title, dueDate, assignedTo, priority, status, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Task not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/tasks/:id', requireRole('lawyer', 'secretary'), async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM tasks WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Task not found' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
//  EXPENSES
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/expenses', requireRole('lawyer', 'secretary'), async (req, res) => {
  const { from, to, category, case_id } = req.query;
  try {
    const conditions = [];
    const values = [];
    if (from) { values.push(from); conditions.push(`e.expense_date >= $${values.length}`); }
    if (to) { values.push(to); conditions.push(`e.expense_date <= $${values.length}`); }
    if (category) { values.push(category); conditions.push(`e.category = $${values.length}`); }
    if (case_id) { values.push(case_id); conditions.push(`e.case_id = $${values.length}`); }
    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
    const { rows } = await pool.query(`
      SELECT e.*, c.case_number, c.case_title
      FROM expenses e LEFT JOIN cases c ON c.id = e.case_id
      ${where}
      ORDER BY e.expense_date DESC
    `, values);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Office overhead expenses (electricity, water, salaries, etc.) aren't tied
// to a case — this is the general entry point used by the standalone
// Expenses page's "Add Expense" button; caseId is optional.
app.post('/api/expenses', requireRole('lawyer', 'secretary'), async (req, res) => {
  const { caseId, description, category, amount, expenseDate } = req.body;
  if (!description || amount === undefined) return res.status(400).json({ error: 'description and amount are required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO expenses (case_id, description, category, amount, expense_date, created_by)
       VALUES ($1, $2, $3, $4, COALESCE($5, CURRENT_DATE), $6) RETURNING *`,
      [caseId || null, description, category || 'other', amount, expenseDate || null, req.user.id]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23503') return res.status(400).json({ error: 'Invalid category or case' });
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/cases/:id/expenses', requireRole('lawyer', 'secretary'), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM expenses WHERE case_id = $1 ORDER BY expense_date DESC', [req.params.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/cases/:id/expenses', requireRole('lawyer', 'secretary'), async (req, res) => {
  const { description, category, amount, expenseDate } = req.body;
  if (!description || amount === undefined) return res.status(400).json({ error: 'description and amount are required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO expenses (case_id, description, category, amount, expense_date, created_by)
       VALUES ($1, $2, $3, $4, COALESCE($5, CURRENT_DATE), $6) RETURNING *`,
      [req.params.id, description, category || 'other', amount, expenseDate || null, req.user.id]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    if (err.code === '23503') return res.status(400).json({ error: 'Invalid category' });
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/expenses/:id', requireRole('lawyer', 'secretary'), async (req, res) => {
  const { description, category, amount, expenseDate } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE expenses SET
        description  = COALESCE($1, description),
        category     = COALESCE($2, category),
        amount       = COALESCE($3, amount),
        expense_date = COALESCE($4, expense_date)
       WHERE id = $5 RETURNING *`,
      [description, category, amount, expenseDate, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Expense not found' });
    res.json(rows[0]);
  } catch (err) {
    if (err.code === '23503') return res.status(400).json({ error: 'Invalid category' });
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/expenses/:id', requireRole('lawyer'), async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM expenses WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Expense not found' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
//  INVOICES / PAYMENTS (Billing & Payments — lawyer only)
// ════════════════════════════════════════════════════════════════════════════

async function recomputeInvoiceStatus(invoiceId) {
  const { rows } = await pool.query(
    `SELECT i.total_amount, COALESCE(SUM(p.amount), 0) AS paid
     FROM invoices i LEFT JOIN payments p ON p.invoice_id = i.id
     WHERE i.id = $1 GROUP BY i.total_amount`,
    [invoiceId]
  );
  if (!rows.length) return;
  const { total_amount, paid } = rows[0];
  let status = 'unpaid';
  if (parseFloat(paid) >= parseFloat(total_amount) && parseFloat(total_amount) > 0) status = 'paid';
  else if (parseFloat(paid) > 0) status = 'partial';
  await pool.query('UPDATE invoices SET status = $1 WHERE id = $2', [status, invoiceId]);
}

app.get('/api/invoices', requireRole('lawyer'), async (req, res) => {
  const { status, case_id, from, to } = req.query;
  try {
    const conditions = [];
    const values = [];
    if (status) { values.push(status); conditions.push(`i.status = $${values.length}`); }
    if (case_id) { values.push(case_id); conditions.push(`i.case_id = $${values.length}`); }
    if (from) { values.push(from); conditions.push(`i.issued_date >= $${values.length}`); }
    if (to) { values.push(to); conditions.push(`i.issued_date <= $${values.length}`); }
    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
    const { rows } = await pool.query(`
      SELECT i.*, c.case_number, c.case_title, cl.full_name AS client_name,
        COALESCE((SELECT SUM(amount) FROM payments p WHERE p.invoice_id = i.id), 0) AS amount_paid
      FROM invoices i
      JOIN cases c ON c.id = i.case_id
      LEFT JOIN clients cl ON cl.id = c.client_id
      ${where}
      ORDER BY i.issued_date DESC
    `, values);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/invoices/:id', requireRole('lawyer'), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM invoices WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Invoice not found' });
    const { rows: items } = await pool.query('SELECT * FROM invoice_items WHERE invoice_id = $1', [req.params.id]);
    const { rows: payments } = await pool.query('SELECT * FROM payments WHERE invoice_id = $1 ORDER BY payment_date DESC', [req.params.id]);
    const paid = payments.reduce((s, p) => s + parseFloat(p.amount), 0);
    res.json({ ...rows[0], items, payments, balance: parseFloat(rows[0].total_amount) - paid });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/cases/:id/invoices', requireRole('lawyer'), async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT i.*, COALESCE((SELECT SUM(amount) FROM payments p WHERE p.invoice_id = i.id), 0) AS amount_paid
      FROM invoices i WHERE case_id = $1 ORDER BY issued_date DESC
    `, [req.params.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/cases/:id/invoices', requireRole('lawyer'), async (req, res) => {
  const { description, items, totalAmount, dueDate } = req.body;
  const dbClient = await pool.connect();
  try {
    await dbClient.query('BEGIN');
    const invoiceNumber = 'INV-' + Date.now();
    let total = totalAmount || 0;
    if (items && items.length) {
      total = items.reduce((s, it) => s + (parseFloat(it.quantity || 1) * parseFloat(it.unitPrice)), 0);
    }
    const { rows } = await dbClient.query(
      `INSERT INTO invoices (case_id, invoice_number, description, total_amount, due_date, created_by)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [req.params.id, invoiceNumber, description || null, total, dueDate || null, req.user.id]
    );
    if (items && items.length) {
      for (const it of items) {
        const lineTotal = parseFloat(it.quantity || 1) * parseFloat(it.unitPrice);
        await dbClient.query(
          `INSERT INTO invoice_items (invoice_id, description, quantity, unit_price, line_total)
           VALUES ($1, $2, $3, $4, $5)`,
          [rows[0].id, it.description, it.quantity || 1, it.unitPrice, lineTotal]
        );
      }
    }
    await dbClient.query('COMMIT');
    res.status(201).json(rows[0]);
  } catch (err) {
    await dbClient.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    dbClient.release();
  }
});

app.put('/api/invoices/:id', requireRole('lawyer'), async (req, res) => {
  const { description, dueDate } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE invoices SET description = COALESCE($1, description), due_date = COALESCE($2, due_date)
       WHERE id = $3 RETURNING *`,
      [description, dueDate, req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Invoice not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/invoices/:id', requireRole('lawyer'), async (req, res) => {
  try {
    const { rowCount } = await pool.query('DELETE FROM invoices WHERE id = $1', [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: 'Invoice not found' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/invoices/:id/payments', requireRole('lawyer'), async (req, res) => {
  const { amount, paymentDate, paymentMethod, notes } = req.body;
  if (!amount) return res.status(400).json({ error: 'amount is required' });
  try {
    const { rows: inv } = await pool.query('SELECT case_id FROM invoices WHERE id = $1', [req.params.id]);
    if (!inv.length) return res.status(404).json({ error: 'Invoice not found' });

    const { rows } = await pool.query(
      `INSERT INTO payments (invoice_id, case_id, amount, payment_date, payment_method, received_by, notes)
       VALUES ($1, $2, $3, COALESCE($4, CURRENT_DATE), $5, $6, $7) RETURNING *`,
      [req.params.id, inv[0].case_id, amount, paymentDate || null, paymentMethod || 'cash', req.user.id, notes || null]
    );
    await recomputeInvoiceStatus(req.params.id);
    await logActivity(req.user.id, req.user.email, 'CREATE', 'payment', rows[0].id, null, rows[0], req);
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/payments/:id', requireRole('lawyer'), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM payments WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Payment not found' });
    await pool.query('DELETE FROM payments WHERE id = $1', [req.params.id]);
    await recomputeInvoiceStatus(rows[0].invoice_id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
//  NOTES
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/cases/:id/notes', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT n.*, u.full_name AS author_name FROM notes n
      LEFT JOIN users u ON u.id = n.author_id
      WHERE case_id = $1 ORDER BY created_at DESC
    `, [req.params.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/cases/:id/notes', async (req, res) => {
  const { body } = req.body;
  if (!body) return res.status(400).json({ error: 'body is required' });
  try {
    const { rows } = await pool.query(
      'INSERT INTO notes (case_id, author_id, body) VALUES ($1, $2, $3) RETURNING *',
      [req.params.id, req.user.id, body]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/notes/:id', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM notes WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Note not found' });
    if (rows[0].author_id !== req.user.id && req.user.role !== 'lawyer') {
      return res.status(403).json({ error: 'You can only delete your own notes' });
    }
    await pool.query('DELETE FROM notes WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
//  DASHBOARD
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/dashboard/summary', async (req, res) => {
  try {
    // Today's/Upcoming "hearings" are driven by next_court_date, not
    // hearing_date — the Court Date form is filled in after attending
    // court, so hearing_date is always a date already in the past by the
    // time it's recorded. next_court_date (noted on that same form) is
    // what's actually still ahead. Only the most recently recorded court
    // date per case reflects what's currently expected next.
    const { rows: todayHearings } = await pool.query(`
      SELECT * FROM (
        SELECT DISTINCT ON (h.case_id) h.*, c.case_number, c.case_title, cl.full_name AS client_name
        FROM hearings h JOIN cases c ON c.id = h.case_id LEFT JOIN clients cl ON cl.id = c.client_id
        ORDER BY h.case_id, h.hearing_date DESC, h.id DESC
      ) latest
      WHERE latest.next_court_date::date = CURRENT_DATE
      ORDER BY latest.next_court_date
    `);
    const { rows: upcomingAppointments } = await pool.query(`
      SELECT a.*, cl.full_name AS client_name
      FROM appointments a JOIN clients cl ON cl.id = a.client_id
      WHERE a.appointment_date::date >= CURRENT_DATE AND a.appointment_date::date <= CURRENT_DATE + INTERVAL '7 days'
      ORDER BY a.appointment_date LIMIT 10
    `);
    const { rows: upcomingHearings } = await pool.query(`
      SELECT * FROM (
        SELECT DISTINCT ON (h.case_id) h.*, c.case_number, c.case_title, cl.full_name AS client_name
        FROM hearings h JOIN cases c ON c.id = h.case_id LEFT JOIN clients cl ON cl.id = c.client_id
        ORDER BY h.case_id, h.hearing_date DESC, h.id DESC
      ) latest
      WHERE latest.next_court_date::date > CURRENT_DATE AND latest.next_court_date::date <= CURRENT_DATE + INTERVAL '7 days'
      ORDER BY latest.next_court_date LIMIT 10
    `);
    const { rows: caseStatusCounts } = await pool.query(`
      SELECT c.status, COUNT(*)::int AS count, cs.is_closed
      FROM cases c LEFT JOIN case_statuses cs ON cs.name = c.status
      GROUP BY c.status, cs.is_closed
    `);
    const { rows: activeCountRows } = await pool.query(`
      SELECT COUNT(*)::int AS count
      FROM cases c JOIN case_statuses cs ON cs.name = c.status
      WHERE cs.is_closed = FALSE
    `);
    const { rows: recentActivity } = await pool.query(`
      SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 15
    `);

    const summary = {
      todayHearings,
      upcomingHearings,
      upcomingAppointments,
      caseStatusCounts,
      activeCaseCount: activeCountRows[0].count,
      recentActivity
    };

    if (req.user.role === 'lawyer') {
      const { rows: billing } = await pool.query(`
        SELECT COALESCE(SUM(i.total_amount - COALESCE(p.paid, 0)), 0) AS outstanding
        FROM invoices i
        LEFT JOIN (SELECT invoice_id, SUM(amount) AS paid FROM payments GROUP BY invoice_id) p ON p.invoice_id = i.id
        WHERE i.status != 'paid'
      `);
      summary.outstandingInvoicesTotal = parseFloat(billing[0].outstanding);

      // All-time financial totals for the dashboard's Financial Overview
      // card — same shape as GET /api/reports/financial with no date
      // filter, kept in the summary payload so a plain dashboard reload is
      // enough to pick up new expenses/payments (no separate report call).
      const { rows: revenueRows } = await pool.query(`SELECT COALESCE(SUM(amount),0) AS total FROM payments`);
      const { rows: expenseRows } = await pool.query(`SELECT COALESCE(SUM(amount),0) AS total FROM expenses`);
      const totalRevenueAllTime = parseFloat(revenueRows[0].total);
      const totalExpensesAllTime = parseFloat(expenseRows[0].total);
      summary.totalRevenueAllTime = totalRevenueAllTime;
      summary.totalExpensesAllTime = totalExpensesAllTime;
      summary.netProfitAllTime = totalRevenueAllTime - totalExpensesAllTime;
    }

    res.json(summary);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
//  REPORTS (lawyer only)
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/reports/cases-summary', requireRole('lawyer'), async (req, res) => {
  const { from, to, status } = req.query;
  try {
    const conditions = [];
    const values = [];
    if (from) { values.push(from); conditions.push(`created_at >= $${values.length}`); }
    if (to) { values.push(to); conditions.push(`created_at <= $${values.length}`); }
    if (status) { values.push(status); conditions.push(`status = $${values.length}`); }
    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
    const { rows } = await pool.query(`SELECT status, COUNT(*)::int AS count FROM cases ${where} GROUP BY status`, values);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/reports/financial', requireRole('lawyer'), async (req, res) => {
  const { from, to } = req.query;
  try {
    const dateFilterP = from && to ? 'WHERE payment_date BETWEEN $1 AND $2' : '';
    const dateFilterE = from && to ? 'WHERE expense_date BETWEEN $1 AND $2' : '';
    const values = from && to ? [from, to] : [];
    const { rows: income } = await pool.query(`SELECT COALESCE(SUM(amount),0) AS total FROM payments ${dateFilterP}`, values);
    const { rows: expenses } = await pool.query(`SELECT COALESCE(SUM(amount),0) AS total FROM expenses ${dateFilterE}`, values);
    res.json({
      totalIncome: parseFloat(income[0].total),
      totalExpenses: parseFloat(expenses[0].total),
      netProfit: parseFloat(income[0].total) - parseFloat(expenses[0].total)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
//  SETTINGS
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/settings', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM settings');
    const settings = {};
    rows.forEach(r => { settings[r.key] = r.value; });
    res.json(settings);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/settings', requireRole('lawyer'), async (req, res) => {
  try {
    const entries = Object.entries(req.body);
    for (const [key, value] of entries) {
      await pool.query(
        `INSERT INTO settings (key, value) VALUES ($1, $2)
         ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP`,
        [key, String(value)]
      );
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// START SERVER
// ============================================================
setupDatabase()
  .then(() => seedDefaultAdmin())
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Tanscar Attorneys API running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('Failed to start server:', err);
    process.exit(1);
  });
