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

// BASE path 
const BASE = process.env.BASE_PATH || '';
app.locals.base = BASE;

// expose a full basePath 
app.locals.basePath = process.env.HEALTH_BASE_PATH || `http://localhost:${port}`;

const TRUST_PROXY = process.env.TRUST_PROXY === '1' || process.env.TRUST_PROXY === 'true';
if (TRUST_PROXY) {
  app.set('trust proxy', 1);
}

// view engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// static assets 
if (BASE) {
  app.use(BASE, express.static(path.join(__dirname, 'public')));
  app.use(`${BASE}/uploads`, express.static(path.join(__dirname, 'uploads')));
} else {
  app.use(express.static(path.join(__dirname, 'public')));
  app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
}

// security + parsing
app.use(helmet());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(expressSanitizer());

// session
const sessionCookieSecure = process.env.SESSION_COOKIE_SECURE === 'true';
app.use(session({
  secret: process.env.SESSION_SECRET || 'somefallbacksecret',
  resave: false,
  saveUninitialized: false,           
  cookie: {
    maxAge: 60 * 60 * 1000,
    secure: sessionCookieSecure,
    path: BASE || '/',
    httpOnly: true,
    sameSite: 'lax'
  }
}));

const globalCsurf = csurf({ cookie: false });

app.use((req, res, next) => {
  const apiPrefix = (BASE ? `${BASE}/api` : '/api');

  // Skip API endpoints 
  if (req.path.startsWith(apiPrefix)) return next();

  // Skip multipart POSTs here 
  const ct = String(req.headers['content-type'] || '').toLowerCase();
  if (req.method === 'POST' && ct.includes('multipart/form-data')) return next();

  // Run csurf for all other requests 
  return globalCsurf(req, res, next);
});

// expose csrf token and helpers to views
app.use((req, res, next) => {
  try {
    res.locals.csrfToken = (typeof req.csrfToken === 'function') ? req.csrfToken() : '';
  } catch (e) {
    res.locals.csrfToken = '';
  }

  res.locals.base = BASE || '';
  res.locals.buildUrl = (p) => {
    if (!p) return BASE || '/';
    const pathPart = p.startsWith('/') ? p : `/${p}`;
    return (BASE || '') + pathPart;
  };

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

// Routes mount
if (BASE) {
  app.use(BASE, require('./routes/main'));
  app.use(`${BASE}/users`, require('./routes/users'));
  app.use(`${BASE}/workouts`, require('./routes/workouts'));
  app.use(`${BASE}/api`, require('./routes/api'));
  app.use(`${BASE}/posts`, require('./routes/posts'));
} else {
  app.use('/', require('./routes/main'));
  app.use('/users', require('./routes/users'));
  app.use('/workouts', require('./routes/workouts'));
  app.use('/api', require('./routes/api'));
  app.use('/posts', require('./routes/posts'));
}

// Global error handler 
app.use((err, req, res, next) => {
  console.error('ERROR:', err && err.stack ? err.stack : err);

  // Ensure locals exist
  res.locals.currentUser = res.locals.currentUser || null;
  res.locals.currentUserRole = res.locals.currentUserRole || null;
  res.locals.isVerified = res.locals.isVerified || false;

  // Special-case: CSRF token errors
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
    console.error('Exiting because DB connection failed on startup.', err.message || err);
    process.exit(1);
  }

  server = app.listen(port, () => {
    console.log(`App listening on port ${port} (BASE='${BASE}')`);
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
