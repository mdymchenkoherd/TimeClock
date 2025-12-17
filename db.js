const sql = require('mssql');

const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_DATABASE,
  options: {
    encrypt: false,
    trustServerCertificate: true
  }
};

let poolPromise = null;

function getPool() {
  if (!poolPromise) {
    poolPromise = sql.connect(dbConfig);
  }
  return poolPromise;
}

async function initializeDatabase() {
  try {
    const pool = await getPool();
    const request = pool.request();

    // Users
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

    // LoginHistory
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

    console.log('✅ Tables checked/created successfully');
  } catch (err) {
    console.error('❌ Database init error:', err.message);
  }
}

module.exports = { sql, getPool, initializeDatabase };
