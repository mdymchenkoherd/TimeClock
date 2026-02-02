const express = require('express');
const bcrypt = require('bcrypt');
const { sql, getPool } = require('./db');
const { requireLogin, requireAdmin } = require('./auth');
const ExcelJS = require('exceljs');

const router = express.Router();

// ---- Helpers ----
function toLocalDateTime(input) {
  if (!input) return null;
  const [datePart, timePart] = input.split('T');
  const isoString = `${datePart}T${timePart}:00`;
  return new Date(isoString);
}

function hoursBetween(start, end) {
  if (!start || !end) return null;
  const s = new Date(start);
  const e = new Date(end);
  if (Number.isNaN(s.getTime()) || Number.isNaN(e.getTime())) return null;
  const diffMs = e.getTime() - s.getTime();
  if (diffMs < 0) return null;
  return Math.round((diffMs / 3600000) * 100) / 100; // 2 decimals
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

// ---- Timecards list page (protected): From/To filter ----
router.get('/', requireLogin, async (req, res) => {
  const { date, from, to, name } = req.query;

  const today = new Date().toISOString().split('T')[0];
  const filterFrom = (from || date || today);
  const filterTo = (to || date || today);

  const nameFilter = name ? `%${name}%` : '%';

  try {
    const pool = await getPool();
    const result = await pool.request()
      .input('fromDate', sql.Date, filterFrom)
      .input('toDate', sql.Date, filterTo)
      .input('name', sql.NVarChar, nameFilter)
      .query(`
        SELECT 
          tc.lmpTimecardID,
          empl.lmeEmployeeName, 
          tc.lmpActualStartTime, 
          tc.lmpActualEndTime
        FROM Timecards tc
        INNER JOIN Employees empl ON tc.lmpEmployeeID = empl.lmeEmployeeID
        WHERE CAST(tc.lmpActualStartTime as date) >= @fromDate
          AND CAST(tc.lmpActualStartTime as date) <= @toDate
          AND empl.lmeEmployeeName LIKE @name
        ORDER BY tc.lmpActualStartTime DESC
      `);

    res.render('index', {
      timecards: result.recordset,
      filterFrom,
      filterTo,
      name,
      user: req.session.user
    });
  } catch (err) {
    res.status(500).send('Database Error: ' + err.message);
  }
});

// ---- Export timecards to Excel (protected) ----
router.get('/export', requireLogin, async (req, res) => {
  const { date, from, to, name } = req.query;

  const today = new Date().toISOString().split('T')[0];
  const filterFrom = (from || date || today);
  const filterTo = (to || date || today);
  const nameFilter = name ? `%${name}%` : '%';

  try {
    const pool = await getPool();
    const result = await pool.request()
      .input('fromDate', sql.Date, filterFrom)
      .input('toDate', sql.Date, filterTo)
      .input('name', sql.NVarChar, nameFilter)
      .query(`
        SELECT 
          empl.lmeEmployeeName, 
          tc.lmpActualStartTime, 
          tc.lmpActualEndTime
        FROM Timecards tc
        INNER JOIN Employees empl ON tc.lmpEmployeeID = empl.lmeEmployeeID
        WHERE CAST(tc.lmpActualStartTime as date) >= @fromDate
          AND CAST(tc.lmpActualStartTime as date) <= @toDate
          AND empl.lmeEmployeeName LIKE @name
        ORDER BY empl.lmeEmployeeName ASC, tc.lmpActualStartTime ASC
      `);

    // totals map stays (we keep your current version)
    const totalsByEmployee = new Map(); // name -> totalHours

    const workbook = new ExcelJS.Workbook();
    workbook.creator = 'TimeClock';
    workbook.created = new Date();

    // Sheet 1: detailed rows + inline totals
    const sheet = workbook.addWorksheet('Timecards');
    sheet.columns = [
      { header: 'Employee', key: 'employee', width: 35 },
      { header: 'Clock In', key: 'clockIn', width: 22 },
      { header: 'Clock Out', key: 'clockOut', width: 22 },
      { header: 'Hours', key: 'hours', width: 10 },
    ];
    sheet.getRow(1).font = { bold: true };
    sheet.views = [{ state: 'frozen', ySplit: 1 }];

    // We will write rows grouped by employee, then insert a "Total for:" line.
    let currentEmployee = null;
    let runningTotal = 0;

    const flushTotalRow = () => {
      if (!currentEmployee) return;

      // blank spacer row (optional; comment out if you don’t want spacing)
      // sheet.addRow({ employee: '', clockIn: null, clockOut: null, hours: null });

      const totalRow = sheet.addRow({
        employee: `Total for: ${currentEmployee}`,
        clockIn: null,
        clockOut: null,
        hours: Math.round(runningTotal * 100) / 100
      });

      totalRow.font = { bold: true };
    };

    for (const r of result.recordset) {
      const employee = r.lmeEmployeeName;

      // When employee changes -> write total row for previous employee
      if (currentEmployee !== null && employee !== currentEmployee) {
        flushTotalRow();
        runningTotal = 0;
      }

      currentEmployee = employee;

      const h = hoursBetween(r.lmpActualStartTime, r.lmpActualEndTime);

      sheet.addRow({
        employee,
        clockIn: r.lmpActualStartTime ? new Date(r.lmpActualStartTime) : null,
        clockOut: r.lmpActualEndTime ? new Date(r.lmpActualEndTime) : null,
        hours: h
      });

      if (h != null) {
        runningTotal += h;

        const prev = totalsByEmployee.get(employee) || 0;
        totalsByEmployee.set(employee, Math.round((prev + h) * 100) / 100);
      }
    }

    // Flush last employee total
    flushTotalRow();

    sheet.getColumn('clockIn').numFmt = 'yyyy-mm-dd hh:mm';
    sheet.getColumn('clockOut').numFmt = 'yyyy-mm-dd hh:mm';
    sheet.getColumn('hours').numFmt = '0.00';

    // Sheet 2: totals per employee (kept as-is)
    const totalsSheet = workbook.addWorksheet('Totals');
    totalsSheet.columns = [
      { header: 'Employee', key: 'employee', width: 35 },
      { header: 'Total Hours', key: 'totalHours', width: 14 },
    ];
    totalsSheet.getRow(1).font = { bold: true };
    totalsSheet.views = [{ state: 'frozen', ySplit: 1 }];

    const sorted = Array.from(totalsByEmployee.entries())
      .sort((a, b) => a[0].localeCompare(b[0]));

    for (const [employee, totalHours] of sorted) {
      totalsSheet.addRow({ employee, totalHours });
    }
    totalsSheet.getColumn('totalHours').numFmt = '0.00';

    const safeFrom = String(filterFrom).replace(/[^0-9-]/g, '');
    const safeTo = String(filterTo).replace(/[^0-9-]/g, '');
    const filename = `timecards_${safeFrom}_to_${safeTo}.xlsx`;

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    const buffer = await workbook.xlsx.writeBuffer();
    res.send(Buffer.from(buffer));
  } catch (err) {
    res.status(500).send('Export Error: ' + err.message);
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
