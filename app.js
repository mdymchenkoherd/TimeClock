const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');

const routes = require('./routes');

const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));

app.use(express.json());
app.use(bodyParser.urlencoded({ extended: false }));

app.use(session({
  name: 'connect.sid',
  secret: process.env.SESSION_SECRET || 'dev-only-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false // set true only when HTTPS is used
  }
}));

app.use(routes);

module.exports = app;
