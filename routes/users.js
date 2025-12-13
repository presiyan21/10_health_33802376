// routes/users.js

const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { check, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

const db = global.db;
const saltRounds = 12;

/* --------------------------------------------------------------
   Audit log helper for login/TOTP attempts
--------------------------------------------------------------- */
async function logLoginAttempt(username, status) {
  try {
    await db.execute(
      'INSERT INTO audit_log (username, status) VALUES (?, ?)',
      [username, status]
    );
  } catch (err) {
    console.error('Failed to log audit:', err);
  }
}

/* --------------------------------------------------------------
   Mail transport factory
--------------------------------------------------------------- */
function createTransporter() {
  if (process.env.SMTP_HOST && process.env.SMTP_USER) {
    return nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT) || 587,
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD
      }
    });
  }

  // fallback logs email instead of sending
  return {
    sendMail: async opts => {
      console.log('--- EMAIL Fallback ---');
      console.log(opts);
      console.log('----------------------');
    }
  };
}

const transporter = createTransporter();

/* --------------------------------------------------------------
   Registration page
--------------------------------------------------------------- */
router.get('/register', (req, res) => {
  res.render('register', {
    errors: [],
    fieldErrors: {},
    formData: {},
    pageTitle: 'Register',
    csrfToken: req.csrfToken()
  });
});

/* --------------------------------------------------------------
   Handle registration + TOTP secret creation
--------------------------------------------------------------- */
router.post(
  '/registered',
  [
    // input validation rules
    check('first').trim().notEmpty().withMessage('First name is required'),
    check('last').trim().notEmpty().withMessage('Last name is required'),
    check('email').trim().isEmail().withMessage('Enter a valid email'),
    check('username')
      .trim()
      .isLength({ min: 5, max: 30 })
      .withMessage('Username must be 5–30 characters'),
    check('password')
      .isLength({ min: 8 }).withMessage('Minimum 8 characters')
      .matches(/[a-z]/).withMessage('Must contain lowercase')
      .matches(/[A-Z]/).withMessage('Must contain uppercase')
      .matches(/[0-9]/).withMessage('Must contain number')
      .matches(/[^A-Za-z0-9]/).withMessage('Must contain special character')
  ],
  async (req, res, next) => {
    try {
      const errors = validationResult(req);

      // repopulate form if needed
      const formData = {
        first: req.body.first || '',
        last: req.body.last || '',
        email: req.body.email || '',
        username: req.body.username || ''
      };

      if (!errors.isEmpty()) {
        return res.render('register', {
          errors: errors.array(),
          fieldErrors: errors.mapped(),
          formData,
          pageTitle: 'Register',
          csrfToken: req.csrfToken()
        });
      }

      // sanitisation fallback
      const first = req.sanitize ? req.sanitize(req.body.first) : req.body.first;
      const last = req.sanitize ? req.sanitize(req.body.last) : req.body.last;
      const email = req.sanitize ? req.sanitize(req.body.email) : req.body.email;
      const username = req.sanitize ? req.sanitize(req.body.username) : req.body.username;

      const hashed = await bcrypt.hash(req.body.password, saltRounds);

      // create user (unverified)
      const [result] = await db.execute(
        `INSERT INTO users 
         (username, first_name, last_name, email, hashed_password, role, is_verified)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [username, first, last, email, hashed, 'user', 0]
      );

      const userId = result.insertId;

      // generate a new TOTP secret for the user
      const secret = speakeasy.generateSecret({
        name: `Health & Fitness Tracker (${username})`
      });

      await db.execute('UPDATE users SET totp_secret = ? WHERE id = ?', [
        secret.base32,
        userId
      ]);

      // make QR for authenticator apps
      const qrDataUrl = await qrcode.toDataURL(secret.otpauth_url);

      return res.render('verify_totp', {
        username,
        qrDataUrl,
        secret: secret.base32,
        error: null,
        csrfToken: req.csrfToken(),
        pageTitle: 'Verify TOTP'
      });
    } catch (err) {
      // unique key fail → username/email taken
      if (err.code === 'ER_DUP_ENTRY') {
        return res.render('register', {
          errors: [{ msg: 'Username or email already exists' }],
          fieldErrors: {
            username: { msg: 'Username already exists' },
            email: { msg: 'Email already exists' }
          },
          formData: {
            first: req.body.first || '',
            last: req.body.last || '',
            email: req.body.email || '',
            username: req.body.username || ''
          },
          pageTitle: 'Register',
          csrfToken: req.csrfToken()
        });
      }
      next(err);
    }
  }
);

/* --------------------------------------------------------------
   TOTP verification page + code submission
--------------------------------------------------------------- */
router.get('/verify-totp', async (req, res, next) => {
  try {
    const username = (req.query.username || '').trim();
    if (!username) return res.status(400).send('Missing username');

    const [rows] = await db.execute(
      'SELECT id, totp_secret, is_verified FROM users WHERE username = ?',
      [username]
    );

    if (!rows.length) return res.status(404).send('User not found');

    const user = rows[0];

    if (user.is_verified) {
      const loginUrl = res.locals.buildUrl('/users/login');
      return res.send(`Already verified. <a href="${loginUrl}">Log in</a>`);
    }

    // rebuild otpauth URL for QR
    const issuer = encodeURIComponent('Health & Fitness Tracker');
    const label = encodeURIComponent(username);
    const otpauth = `otpauth://totp/${issuer}:${label}?secret=${user.totp_secret}&issuer=${issuer}`;
    const qrDataUrl = await qrcode.toDataURL(otpauth);

    res.render('verify_totp', {
      username,
      qrDataUrl,
      secret: user.totp_secret,
      error: null,
      csrfToken: req.csrfToken(),
      pageTitle: 'Verify TOTP'
    });
  } catch (err) {
    next(err);
  }
});

router.post('/verify-totp', async (req, res, next) => {
  try {
    const username = (req.body.username || '').trim();
    const token = (req.body.token || '').trim();

    if (!username || !token)
      return res.status(400).send('Missing fields');

    const [rows] = await db.execute(
      'SELECT id, totp_secret, is_verified FROM users WHERE username = ?',
      [username]
    );

    if (!rows.length) return res.status(404).send('User not found');

    const user = rows[0];

    if (user.is_verified) {
      const loginUrl = res.locals.buildUrl('/users/login');
      return res.send(`Already verified. <a href="${loginUrl}">Log in</a>`);
    }

    // validate TOTP code against secret
    const verified = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: 'base32',
      token,
      window: 1
    });

    if (!verified) {
      await logLoginAttempt(username, 'FAILURE');

      const qrDataUrl = await qrcode.toDataURL(
        `otpauth://totp/Health%20%26%20Fitness%20Tracker:${username}?secret=${user.totp_secret}&issuer=Health%20%26%20Fitness%20Tracker`
      );

      return res.render('verify_totp', {
        username,
        qrDataUrl,
        secret: user.totp_secret,
        error: 'Invalid code, try again',
        csrfToken: req.csrfToken(),
        pageTitle: 'Verify TOTP'
      });
    }

    // mark verified
    await db.execute('UPDATE users SET is_verified = 1 WHERE id = ?', [
      user.id
    ]);

    await logLoginAttempt(username, 'SUCCESS');

    res.render('verify_success', {
      success: true,
      message: 'Your account is now verified. You may log in.',
      pageTitle: 'Verified'
    });
  } catch (err) {
    next(err);
  }
});

/* --------------------------------------------------------------
   Login
--------------------------------------------------------------- */
router.get('/login', (req, res) => {
  res.render('login', { pageTitle: 'Login' });
});

router.post('/loggedin', async (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;

  try {
    const [rows] = await db.execute(
      'SELECT id, hashed_password, is_verified FROM users WHERE username = ?',
      [username]
    );

    // no such user
    if (!rows.length) {
      await logLoginAttempt(username, 'FAILURE');
      return res.send('Login failed: Username not found');
    }

    const user = rows[0];

    // verify password
    const ok = await bcrypt.compare(password, user.hashed_password);
    if (!ok) {
      await logLoginAttempt(username, 'FAILURE');
      return res.send('Login failed: Incorrect password');
    }

    // enforce TOTP verification
    if (!user.is_verified) {
      const verifyUrl = `${res.locals.buildUrl('/users/verify-totp')}?username=${encodeURIComponent(username)}`;
      return res.redirect(verifyUrl);
    }

    // success → build session
    req.session.userId = user.id;
    req.session.username = username;
    await logLoginAttempt(username, 'SUCCESS');

    // redirect to dashboard with base prefix
    return res.redirect(res.locals.buildUrl('/workouts/dashboard'));
  } catch (err) {
    await logLoginAttempt(username, 'FAILURE');
    next(err);
  }
});

/* --------------------------------------------------------------
   Logout
--------------------------------------------------------------- */
router.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.send(`Logged out. <a href="${res.locals.buildUrl('/')}">Home</a>`);
  });
});

/* --------------------------------------------------------------
   Password reset: request form
--------------------------------------------------------------- */
router.get('/reset', (req, res) => {
  res.render('reset_request', { pageTitle: 'Password Reset' });
});

/* --------------------------------------------------------------
   Password reset: generate token + send link
--------------------------------------------------------------- */
router.post('/reset', async (req, res, next) => {
  try {
    const email = req.body.email;

    const [rows] = await db.execute(
      'SELECT id, username FROM users WHERE email = ?',
      [email]
    );

    // identical response regardless of user existence
    if (!rows.length)
      return res.send('If the email exists, reset instructions were sent.');

    const user = rows[0];

    // create token valid for 1 hour
    const token = crypto.randomBytes(20).toString('hex');
    const expires = new Date(Date.now() + 3600_000);

    await db.execute(
      'UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?',
      [token, expires, user.id]
    );

    const publicBase = process.env.HEALTH_BASE_PATH ||
      `${req.protocol}://${req.get('host')}${req.app.locals.base || ''}`;

    const resetUrl = `${publicBase}/users/reset/${token}`;

    await transporter.sendMail({
      to: email,
      subject: 'Password Reset',
      text: `Reset your password: ${resetUrl}`,
      html: `<p>Reset your password: <a href="${resetUrl}">${resetUrl}</a></p>`
    });

    res.send('If the email exists, reset instructions were sent.');
  } catch (err) {
    next(err);
  }
});

/* --------------------------------------------------------------
   Password reset link → load form
--------------------------------------------------------------- */
router.get('/reset/:token', async (req, res, next) => {
  try {
    const token = req.params.token;

    const [rows] = await db.execute(
      'SELECT id, reset_expires FROM users WHERE reset_token = ?',
      [token]
    );

    if (!rows.length) return res.send('Invalid token');

    const user = rows[0];

    if (new Date(user.reset_expires) < new Date())
      return res.send('Token expired');

    res.render('reset_form', {
      token,
      errors: [],
      pageTitle: 'Set New Password'
    });
  } catch (err) {
    next(err);
  }
});

/* --------------------------------------------------------------
   Save new password after reset
--------------------------------------------------------------- */
router.post(
  '/reset/:token',
  [
    check('password')
      .isLength({ min: 8 })
      .matches(/[a-z]/)
      .matches(/[A-Z]/)
      .matches(/[0-9]/)
      .matches(/[^A-Za-z0-9]/)
  ],
  async (req, res, next) => {
    try {
      const token = req.params.token;
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        return res.render('reset_form', {
          token,
          errors: errors.array(),
          pageTitle: 'Set New Password'
        });
      }

      const [rows] = await db.execute(
        'SELECT id, reset_expires FROM users WHERE reset_token = ?',
        [token]
      );

      if (!rows.length) return res.send('Invalid token');

      const user = rows[0];

      if (new Date(user.reset_expires) < new Date())
        return res.send('Token expired');

      const hashed = await bcrypt.hash(req.body.password, saltRounds);

      await db.execute(
        'UPDATE users SET hashed_password = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?',
        [hashed, user.id]
      );

      res.send(`Password updated. <a href="${res.locals.buildUrl('/users/login')}">Log in</a>`);
    } catch (err) {
      next(err);
    }
  }
);

/* --------------------------------------------------------------
   Role helpers
--------------------------------------------------------------- */
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect(res.locals.buildUrl('/users/login'));
  next();
}

function requireRole(role) {
  return async (req, res, next) => {
    if (!req.session.userId) return res.redirect(res.locals.buildUrl('/users/login'));

    const [rows] = await db.execute(
      'SELECT role FROM users WHERE id = ?',
      [req.session.userId]
    );

    if (!rows.length) return res.redirect(res.locals.buildUrl('/users/login'));

    if (rows[0].role !== role)
      return res.status(403).send(`Forbidden: ${role} only`);

    next();
  };
}

const requireAdmin = requireRole('admin');

/* --------------------------------------------------------------
   Admin: view all users
--------------------------------------------------------------- */
router.get('/admin/users', requireAdmin, async (req, res, next) => {
  try {
    const [rows] = await db.execute(
      'SELECT id, username, email, role, is_verified, created_at FROM users ORDER BY id'
    );
    res.render('admin_users', { users: rows, pageTitle: 'Admin: Users' });
  } catch (err) {
    next(err);
  }
});

/* --------------------------------------------------------------
   Admin: update user role
--------------------------------------------------------------- */
router.post('/admin/users/:id/role', requireAdmin, async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    const allowed = ['user', 'admin', 'manager', 'trainer'];
    const requested = String(req.body.role || '').trim();

    // check if requested role is valid
    const role = allowed.includes(requested) ? requested : 'user';

    await db.execute('UPDATE users SET role = ? WHERE id = ?', [role, id]);

    res.redirect(res.locals.buildUrl('/users/admin/users'));
  } catch (err) {
    next(err);
  }
});

module.exports = router;
