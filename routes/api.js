// routes/api.js
// API endpoints for filtered workout lookups.

const express = require('express');
const router = express.Router();
const db = global.db;

// Return workouts matching query filters
router.get('/workouts', async (req, res, next) => {
  try {
    const user = (req.query.user || '').trim();
    const activity = (req.query.activity || '').trim();
    const dateFrom = req.query.date_from;
    const dateTo = req.query.date_to;

    // Base query joins workouts with user info
    let sql =
      'SELECT w.id, u.username, w.activity, w.activity_date, w.duration_mins, w.calories, w.notes ' +
      'FROM workouts w JOIN users u ON w.user_id = u.id';

    const where = [];
    const params = [];

    // Add filters if provided
    if (user) {
      where.push('u.username = ?');
      params.push(user);
    }
    if (activity) {
      where.push('w.activity LIKE ?');
      params.push(`%${activity}%`);
    }
    if (dateFrom) {
      where.push('w.activity_date >= ?');
      params.push(dateFrom);
    }
    if (dateTo) {
      where.push('w.activity_date <= ?');
      params.push(dateTo);
    }

    // Attach WHERE clause if needed
    if (where.length) sql += ' WHERE ' + where.join(' AND ');

    sql += ' ORDER BY w.activity_date DESC LIMIT 500';

    const [rows] = await db.execute(sql, params);
    res.json(rows);
  } catch (err) {
    next(err); // pass DB or query errors to Express handler
  }
});

module.exports = router;
