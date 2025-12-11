// routes/posts.js
// Routes for community posts and comments.

const express = require('express');
const router = express.Router();
const db = global.db;

// Check if user is logged in before continuing
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect('/users/login');
  next();
}

// Check if current user has admin role
async function isAdmin(req) {
  if (!req.session.userId) return false;
  try {
    const [rows] = await db.execute('SELECT role FROM users WHERE id = ?', [req.session.userId]);
    return rows.length && rows[0].role === 'admin';
  } catch (err) {
    console.error('isAdmin error', err);
    return false;
  }
}

// List all posts
router.get('/', async (req, res, next) => {
  try {
    const [rows] = await db.execute(
      `SELECT p.id, p.title, p.content, p.created_at, u.username
       FROM posts p
       JOIN users u ON p.user_id = u.id
       ORDER BY p.created_at DESC`
    );

    res.render('posts_list', {
      posts: rows,
      pageTitle: 'Community Posts',
      csrfToken: req.csrfToken()
    });
  } catch (err) {
    next(err);
  }
});

// Form to create a new post
router.get('/new', requireLogin, (req, res) => {
  res.render('post_new', {
    pageTitle: 'New Post',
    csrfToken: req.csrfToken(),
    formData: {}
  });
});

// Handle new post submission
router.post('/new', requireLogin, async (req, res, next) => {
  try {
    // Sanitise inputs when middleware is available
    const title = req.sanitize ? req.sanitize(req.body.title || '') : (req.body.title || '');
    const content = req.sanitize ? req.sanitize(req.body.content || '') : (req.body.content || '');

    if (!title || !content) {
      return res.render('post_new', {
        pageTitle: 'New Post',
        error: 'Title and content required',
        formData: { title, content },
        csrfToken: req.csrfToken()
      });
    }

    await db.execute(
      'INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)',
      [req.session.userId, title, content]
    );

    res.redirect('/posts');
  } catch (err) {
    next(err);
  }
});

// View a single post with comments
router.get('/:id', async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) return res.status(400).render('error', { error: 'Invalid post id' });

    // Load post
    const [pRows] = await db.execute(
      `SELECT p.*, u.username
       FROM posts p
       JOIN users u ON p.user_id = u.id
       WHERE p.id = ?`,
      [id]
    );

    if (!pRows.length) return res.status(404).render('error', { error: 'Post not found' });

    const post = pRows[0];

    // Load comments for the post
    const [comments] = await db.execute(
      `SELECT c.*, u.username
       FROM comments c
       LEFT JOIN users u ON c.user_id = u.id
       WHERE c.post_id = ?
       ORDER BY c.created_at ASC`,
      [id]
    );

    res.render('post_view', {
      post,
      comments,
      pageTitle: post.title,
      csrfToken: req.csrfToken()
    });
  } catch (err) {
    next(err);
  }
});

// Add a comment 
router.post('/:id/comment', requireLogin, async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) return res.status(400).json({ success: false, error: 'Invalid post id' });

    const content = req.sanitize ? req.sanitize(req.body.content || '') : (req.body.content || '');
    if (!content.trim()) {
      // JSON clients for structured errors
      if (req.headers.accept?.includes('application/json')) {
        return res.status(400).json({ success: false, error: 'Comment required' });
      }
      return res.redirect(`/posts/${id}`);
    }

    // Insert comment
    const [result] = await db.execute(
      'INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
      [id, req.session.userId, content]
    );

    const commentId = result.insertId;

    // Respond with JSON when requested
    if (req.headers.accept?.includes('application/json')) {
      const [[created]] = await db.execute(
        `SELECT c.id, c.content, c.created_at, u.username
         FROM comments c
         LEFT JOIN users u ON u.id = c.user_id
         WHERE c.id = ?`,
        [commentId]
      );
      return res.json({ success: true, comment: created });
    }

    res.redirect(`/posts/${id}#comments`);
  } catch (err) {
    next(err);
  }
});

// Delete a post, allowed for owner or admin only
router.post('/:id/delete', requireLogin, async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) return res.status(400).render('error', { error: 'Invalid id' });

    // Verify the post exists and find its owner
    const [rows] = await db.execute('SELECT user_id FROM posts WHERE id = ?', [id]);
    if (!rows.length) return res.status(404).render('error', { error: 'Post not found' });

    const ownerId = rows[0].user_id;
    const admin = await isAdmin(req);

    // Only owner or admin may delete
    if (req.session.userId !== ownerId && !admin) {
      return res.status(403).render('error', { error: 'Forbidden' });
    }

    await db.execute('DELETE FROM posts WHERE id = ?', [id]);
    res.redirect('/posts');
  } catch (err) {
    next(err);
  }
});

module.exports = router;
