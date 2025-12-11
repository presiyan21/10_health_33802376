// index.js
require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const expressSanitizer = require('express-sanitizer');
const helmet = require('helmet');
const csurf = require('csurf');

const { pool, testConnection } = require('./db');

const app = express();
const port = Number(process.env.PORT) || 8000;

// trust proxy
app.set('trust proxy', 1); 

// view engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// static
app.use(express.static(path.join(__dirname, 'public')));

// uploads
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// security + parsing
app.use(helmet());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(expressSanitizer());

// session 
app.use(session({
  secret: process.env.SESSION_SECRET || 'somefallbacksecret',
  resave: false,
  saveUninitialized: false,
  proxy: true, 
  cookie: {
    maxAge: 60 * 60 * 1000,
    secure: (process.env.NODE_ENV === 'production'), 
    sameSite: 'lax'
  }
}));

// CSRF protection
const csrfProtection = csurf();
app.use((req, res, next) => {
  if (req.path.startsWith('/api')) return next();
  const ct = String(req.headers['content-type'] || '').toLowerCase();
  if (req.method === 'POST' && ct.includes('multipart/form-data')) {
    return next();
  }
  csrfProtection(req, res, next);
});

app.use((req, res, next) => {
  res.locals.csrfToken = typeof req.csrfToken === 'function' ? req.csrfToken() : null;
  next();
});

// dynamic basePath 
app.use((req, res, next) => {
  const proto = (req.get('x-forwarded-proto') || req.protocol).split(',')[0].trim();
  const host = req.get('host');
  res.locals.basePath = (process.env.HEALTH_BASE_PATH && process.env.HEALTH_BASE_PATH !== 'http://localhost:8000')
    ? process.env.HEALTH_BASE_PATH
    : `${proto}://${host}`;
  next();
});

// global locals
app.locals.siteName = 'Health & Fitness Tracker';

// database
global.db = pool;

// Define user locals 
app.use((req, res, next) => {
  if (typeof res.locals.currentUser === 'undefined') res.locals.currentUser = null;
  if (typeof res.locals.currentUserRole === 'undefined') res.locals.currentUserRole = null;
  if (typeof res.locals.isVerified === 'undefined') res.locals.isVerified = false;
  next();
});

// Attach logged-in user info
app.use(async (req, res, next) => {
  try {
    if (req.session && req.session.userId) {
      const [rows] = await global.db.execute(
        'SELECT id, username, role, is_verified FROM users WHERE id = ?',
        [req.session.userId]
      );

      if (rows.length) {
        res.locals.currentUser = rows[0].username;
        res.locals.currentUserRole = rows[0].role;
        res.locals.isVerified = !!rows[0].is_verified;

        req.currentUser = {
          id: rows[0].id,
          username: rows[0].username,
          role: rows[0].role
        };
      } else {
        delete req.session.userId;
      }
    }
  } catch (err) {
    console.error('Failed to load session user:', err.message || err);
  }
  next();
});

// Routes
app.use('/', require('./routes/main'));
app.use('/users', require('./routes/users'));
app.use('/workouts', require('./routes/workouts'));
app.use('/api', require('./routes/api'));
app.use('/posts', require('./routes/posts'));   

// Global error handler 
app.use((err, req, res, next) => {
  console.error('ERROR:', err);

  res.locals.currentUser = res.locals.currentUser || null;
  res.locals.currentUserRole = res.locals.currentUserRole || null;
  res.locals.isVerified = res.locals.isVerified || false;

  if (err && err.code === 'EBADCSRFTOKEN') {
    return res.status(403).render('error', {
      error: 'Invalid or missing CSRF token. Please reload the page and try again.'
    });
  }

  res.status(500).render('error', {
    error: err.message || 'Server Error'
  });
});

// Server startup + DB check
let server;

(async function start() {
  try {
    await testConnection();
  } catch (err) {
    console.error('Exiting because DB connection failed on startup.');
    process.exit(1);
  }

  server = app.listen(port, () => {
    console.log(`App listening on port ${port}`);
  });
})();

// shutdown
async function shutdown(signal) {
  console.log(`Received ${signal} — shutting down...`);
  try {
    if (server) {
      server.close(() => console.log('HTTP server closed'));
    }
    await pool.end();
    console.log('MySQL pool closed');
    process.exit(0);
  } catch (err) {
    console.error('Error during shutdown:', err);
    process.exit(1);
  }
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
