const express = require('express');
const bodyParser = require('body-parser');
const sql = require('mssql');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
const PORT = 4142;

// SQL Server config
const dbConfig = {
  user: 'sa',
  password: 'Neglector-Reunite7-Kisser',
  server: 'HNA-INT02',
  database: 'M1_HN',
  driver: 'mssql',
  options: {
    encrypt: false,
    trustServerCertificate: true
  }
};

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));

// ✅ Accept JSON bodies for API routes
app.use(express.json());

// (Your existing form parsing)
app.use(bodyParser.urlencoded({ extended: false }));

// Session setup
app.use(session({
  secret: 'superSecretKey123!',
  resave: false,
  saveUninitialized: false
}));

// 🔐 Middleware: Check login
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

// 🔐 Middleware: Admin only
function requireAdmin(req, res, next) {
  if (req.session.user?.role !== 'admin') {
    return res.status(403).send('Forbidden: Admins only');
  }
  next();
}

// 🔧 Automatically create tables and default users
async function initializeDatabase() {
  try {
    const pool = await sql.connect(dbConfig);
    const request = pool.request();

    // Users table
    await request.batch(`
      IF NOT EXISTS (
        SELECT * FROM INFORMATION_SCHEMA.TABLES 
        WHERE TABLE_NAME = 'Users'
      )
      BEGIN
        CREATE TABLE Users (
          userID INT IDENTITY(1,1) PRIMARY KEY,
          username NVARCHAR(50) NOT NULL UNIQUE,
          passwordHash NVARCHAR(255) NOT NULL,
          role NVARCHAR(50) DEFAULT 'user',
          createdAt DATETIME DEFAULT GETDATE()
        );
      END
    `);

    // LoginHistory table
    await request.batch(`
      IF NOT EXISTS (
        SELECT * FROM INFORMATION_SCHEMA.TABLES 
        WHERE TABLE_NAME = 'LoginHistory'
      )
      BEGIN
        CREATE TABLE LoginHistory (
          id INT IDENTITY(1,1) PRIMARY KEY,
          userID INT NULL,
          username NVARCHAR(100) NOT NULL,
          loginTime DATETIME DEFAULT GETDATE(),
          ipAddress NVARCHAR(50),
          userAgent NVARCHAR(255),
          status NVARCHAR(20) NOT NULL,
          reason NVARCHAR(255) NULL,
          FOREIGN KEY (userID) REFERENCES Users(userID)
        );
      END
    `);

    // Insert default users ONLY if table empty (your original behavior)
    const result = await request.query(`SELECT COUNT(*) as count FROM Users`);
    if (result.recordset[0].count === 0) {
      const hash1 = await bcrypt.hash('Admin123!', 10);
      const hash2 = await bcrypt.hash('User123!', 10);

      await pool.request().query(`
        INSERT INTO Users (username, passwordHash, role)
        VALUES 
        ('admin', '${hash1}', 'admin'),
        ('user1', '${hash2}', 'user');
      `);

      console.log('✅ Default users created.');
    }

    console.log('✅ Tables checked/created successfully');
  } catch (err) {
    console.error('❌ Database init error:', err.message);
  }
}

// 📄 Helper: Convert datetime-local to JS Date
function toLocalDateTime(input) {
  if (!input) return null;
  const [datePart, timePart] = input.split('T');
  const isoString = `${datePart}T${timePart}:00`;
  return new Date(isoString);
}

// 📄 Login route
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const pool = await sql.connect(dbConfig);
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

  req.session.user = {
    userID: user.userID,
    username: user.username,
    role: user.role
  };

  await logLoginAttempt(user.userID, username, 'success', null, ip, ua);
  res.redirect('/');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// Log login attempt
async function logLoginAttempt(userID, username, status, reason, ip, userAgent) {
  const pool = await sql.connect(dbConfig);
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

// ✅ NEW: Admin API route to add users
// POST /api/users
// JSON body: { "username": "alice", "password": "Secret123!", "role": "user" }
app.post('/api/users', requireLogin, requireAdmin, async (req, res) => {
  try {
    let { username, password, role } = req.body;

    username = (username || '').trim();
    password = (password || '').trim();
    role = (role || 'user').trim();

    if (!username || !password) {
      return res.status(400).json({ error: 'username and password are required' });
    }

    if (!['user', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'role must be "user" or "admin"' });
    }

    const pool = await sql.connect(dbConfig);

    // Check if username exists
    const existing = await pool.request()
      .input('username', sql.NVarChar, username)
      .query('SELECT userID FROM Users WHERE username = @username');

    if (existing.recordset.length > 0) {
      return res.status(409).json({ error: 'username already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    // Insert new user
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
    // If unique constraint triggers anyway (race condition), return 409
    if (String(err.message || '').toLowerCase().includes('unique')) {
      return res.status(409).json({ error: 'username already exists' });
    }
    return res.status(500).json({ error: 'server error', details: err.message });
  }
});

// 🧾 View login history (admin only)
app.get('/history', requireLogin, requireAdmin, async (req, res) => {
  const pool = await sql.connect(dbConfig);
  const result = await pool.request().query(`
    SELECT * FROM LoginHistory ORDER BY loginTime DESC
  `);
  res.render('history', { history: result.recordset });
});

// 🔐 Protected Timecard List
app.get('/', requireLogin, async (req, res) => {
  const { date, name } = req.query;

  const filterDate = date || new Date().toISOString().split('T')[0];
  const nameFilter = name ? `%${name}%` : '%';

  try {
    const pool = await sql.connect(dbConfig);
    const request = pool.request();
    request.input('filterDate', sql.Date, filterDate);
    request.input('name', sql.NVarChar, nameFilter);

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

// 🔐 Protected Update Route
app.post('/update/:id', requireLogin, async (req, res) => {
  const id = req.params.id;
  const { startTime, endTime } = req.body;

  const startDate = toLocalDateTime(startTime);
  const endDate = endTime.trim() === '' ? null : toLocalDateTime(endTime);

  const adjustedStart = new Date(startDate.getTime() - (startDate.getTimezoneOffset() * 60000));
  const adjustedEnd = endDate ? new Date(endDate.getTime() - (endDate.getTimezoneOffset() * 60000)) : null;

  try {
    const pool = await sql.connect(dbConfig);
    const request = pool.request()
      .input('id', sql.Int, id)
      .input('startTime', sql.DateTime, adjustedStart)
      .input('endTime', sql.DateTime, adjustedEnd);

    await request.query(`
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

// ✅ Start server after DB init
initializeDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`✅ Server is running at http://localhost:${PORT}`);
  });
});
