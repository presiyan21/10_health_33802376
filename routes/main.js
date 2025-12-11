// routes/main.js
const express = require('express');
const router = express.Router();

// Home
router.get('/', (req, res) => {
  res.render('index', { pageTitle: 'Home' });
});

// About
router.get('/about', (req, res) => {
  res.render('about', { pageTitle: 'About' });
});

module.exports = router;
