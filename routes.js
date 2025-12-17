const express = require('express');
const bcrypt = require('bcrypt');
const { sql, getPool } = require('./db');
const { requireLogin, requireAdmin } = require('./auth');

const router = express.Router();

// ---- Helpers ----
function toLocalDateTime(input) {
  if (!input) return null;
  const [datePart, timePart] = input.split('T');
  const isoString = `${datePart}T${timePart}:00`;
  return new Date(isoString);
}

async function logLoginAttempt(userID, username, status, reason, ip, userAgent) {
  const pool = await getPool();
  await pool.request()
    .input('userID', sql.Int, userID)
    .input('username', sql.NVarChar, username)
    .input('status', sql.NVarChar, status)
    .input('reason', sql.NVarChar, reason)
    .input('ipAddress', sql.NVarChar, ip)
    .input('userAgent', sql.NVarChar, userAgent)
    .query(`
      INSERT INTO LoginHistory (userID, username, status, reason, ipAddress, userAgent)
      VALUES (@userID, @username, @status, @reason, @ipAddress, @userAgent)
    `);
}

// ---- Web login ----
router.get('/login', (req, res) => {
  res.render('login', { error: null });
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const pool = await getPool();
  const result = await pool.request()
    .input('username', sql.NVarChar, username)
    .query('SELECT * FROM Users WHERE username = @username');

  const user = result.recordset[0];
  const ip = req.ip === '::1' ? '127.0.0.1' : req.ip;
  const ua = req.headers['user-agent'];

  if (!user) {
    await logLoginAttempt(null, username, 'fail', 'User not found', ip, ua);
    return res.render('login', { error: 'Invalid username or password' });
  }

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) {
    await logLoginAttempt(user.userID, username, 'fail', 'Wrong password', ip, ua);
    return res.render('login', { error: 'Invalid username or password' });
  }

  req.session.user = { userID: user.userID, username: user.username, role: user.role };
  await logLoginAttempt(user.userID, username, 'success', null, ip, ua);

  res.redirect('/');
});

// ---- API login (Postman-friendly) ----
router.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  const pool = await getPool();
  const result = await pool.request()
    .input('username', sql.NVarChar, username)
    .query('SELECT * FROM Users WHERE username = @username');

  const user = result.recordset[0];
  const ip = req.ip === '::1' ? '127.0.0.1' : req.ip;
  const ua = req.headers['user-agent'];

  if (!user) {
    await logLoginAttempt(null, username, 'fail', 'User not found', ip, ua);
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) {
    await logLoginAttempt(user.userID, username, 'fail', 'Wrong password', ip, ua);
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  req.session.user = { userID: user.userID, username: user.username, role: user.role };
  await logLoginAttempt(user.userID, username, 'success', null, ip, ua);

  res.json({ ok: true, user: req.session.user });
});

// ---- Logout ----
router.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

router.post('/api/logout', requireLogin, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ---- Admin: create user ----
router.post('/api/users', requireLogin, requireAdmin, async (req, res) => {
  try {
    let { username, password, role } = req.body;
    username = (username || '').trim();
    password = (password || '').trim();
    role = (role || 'user').trim();

    if (!username || !password) return res.status(400).json({ error: 'username and password are required' });
    if (!['user', 'admin'].includes(role)) return res.status(400).json({ error: 'role must be "user" or "admin"' });

    const pool = await getPool();

    const existing = await pool.request()
      .input('username', sql.NVarChar, username)
      .query('SELECT userID FROM Users WHERE username = @username');

    if (existing.recordset.length > 0) return res.status(409).json({ error: 'username already exists' });

    const passwordHash = await bcrypt.hash(password, 10);

    const insertResult = await pool.request()
      .input('username', sql.NVarChar, username)
      .input('passwordHash', sql.NVarChar, passwordHash)
      .input('role', sql.NVarChar, role)
      .query(`
        INSERT INTO Users (username, passwordHash, role)
        OUTPUT INSERTED.userID, INSERTED.username, INSERTED.role, INSERTED.createdAt
        VALUES (@username, @passwordHash, @role)
      `);

    return res.status(201).json({ user: insertResult.recordset[0] });
  } catch (err) {
    return res.status(500).json({ error: 'server error', details: err.message });
  }
});

// ---- Admin: reset any user's password ----
router.put('/api/users/:username/password', requireLogin, requireAdmin, async (req, res) => {
  try {
    const targetUsername = (req.params.username || '').trim();
    const newPassword = (req.body?.newPassword || '').trim();

    if (!targetUsername || !newPassword) {
      return res.status(400).json({ error: 'username and newPassword are required' });
    }

    const pool = await getPool();

    const existing = await pool.request()
      .input('username', sql.NVarChar, targetUsername)
      .query('SELECT userID FROM Users WHERE username = @username');

    if (existing.recordset.length === 0) return res.status(404).json({ error: 'user not found' });

    const passwordHash = await bcrypt.hash(newPassword, 10);

    await pool.request()
      .input('username', sql.NVarChar, targetUsername)
      .input('passwordHash', sql.NVarChar, passwordHash)
      .query('UPDATE Users SET passwordHash=@passwordHash WHERE username=@username');

    return res.json({ ok: true, message: `Password updated for ${targetUsername}` });
  } catch (err) {
    return res.status(500).json({ error: 'server error', details: err.message });
  }
});

// ---- Admin: view login history page ----
router.get('/history', requireLogin, requireAdmin, async (req, res) => {
  const pool = await getPool();
  const result = await pool.request().query('SELECT * FROM LoginHistory ORDER BY loginTime DESC');
  res.render('history', { history: result.recordset });
});

// ---- Timecards list page (protected) ----
router.get('/', requireLogin, async (req, res) => {
  const { date, name } = req.query;

  const filterDate = date || new Date().toISOString().split('T')[0];
  const nameFilter = name ? `%${name}%` : '%';

  try {
    const pool = await getPool();
    const request = pool.request()
      .input('filterDate', sql.Date, filterDate)
      .input('name', sql.NVarChar, nameFilter);

    const result = await request.query(`
      SELECT 
        tc.lmpTimecardID,
        empl.lmeEmployeeName, 
        tc.lmpActualStartTime, 
        tc.lmpActualEndTime
      FROM Timecards tc
      INNER JOIN Employees empl ON tc.lmpEmployeeID = empl.lmeEmployeeID
      WHERE CAST(tc.lmpActualStartTime as date) = @filterDate
        AND empl.lmeEmployeeName LIKE @name
      ORDER BY tc.lmpActualStartTime DESC
    `);

    res.render('index', {
      timecards: result.recordset,
      filterDate,
      name,
      user: req.session.user
    });
  } catch (err) {
    res.status(500).send('Database Error: ' + err.message);
  }
});

// ---- Timecard update (protected) ----
router.post('/update/:id', requireLogin, async (req, res) => {
  const id = req.params.id;
  const { startTime, endTime } = req.body;

  const startDate = toLocalDateTime(startTime);
  const endDate = endTime?.trim() === '' ? null : toLocalDateTime(endTime);

  const adjustedStart = new Date(startDate.getTime() - (startDate.getTimezoneOffset() * 60000));
  const adjustedEnd = endDate ? new Date(endDate.getTime() - (endDate.getTimezoneOffset() * 60000)) : null;

  try {
    const pool = await getPool();
    await pool.request()
      .input('id', sql.Int, id)
      .input('startTime', sql.DateTime, adjustedStart)
      .input('endTime', sql.DateTime, adjustedEnd)
      .query(`
        UPDATE Timecards
        SET lmpActualStartTime = @startTime,
            lmpActualEndTime = @endTime
        WHERE lmpTimecardID = @id
      `);

    res.redirect('/');
  } catch (err) {
    res.status(500).send('Update Error: ' + err.message);
  }
});

module.exports = router;
