require('dotenv').config();
const app = require('./app');
const { initializeDatabase } = require('./db');

const PORT = Number(process.env.PORT || 4142);

initializeDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`✅ Server is running at http://0.0.0.0:${PORT}`);
  });
});
