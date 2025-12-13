// routes/workouts.js – workout CRUD, search, feed, comments, attachments, GPX import, CSV export
const express = require('express')
const router = express.Router()
const { check, validationResult } = require('express-validator')
const multer = require('multer')
const fs = require('fs')
const path = require('path')
const xml2js = require('xml2js')

const db = global.db
const uploadDir = path.join(__dirname, '..', 'uploads')

// Uploads folder exists on cold start
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir)

// GPX upload handler (GPX/XML only)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    // prefix with timestamp so names don't collide
    const name = Date.now() + '-' + file.originalname.replace(/\s+/g, '-')
    cb(null, name)
  }
})
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    // only accept GPX/XML so parser doesn't choke
    if (!file.originalname.match(/\.(gpx|xml)$/i)) return cb(new Error('Only GPX or XML files allowed'))
    cb(null, true)
  }
})

// simple int coercer with sane defaults
function parsePositiveInt(val, defaultVal) {
  const n = Number.parseInt(val, 10)
  return Number.isFinite(n) && n > 0 ? n : defaultVal
}

// user must be logged in for all private pages
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect(res.locals.buildUrl('/users/login'))
  next()
}

// admin-gate for privileged routes
async function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.redirect(res.locals.buildUrl('/users/login'))
  try {
    const [rows] = await db.execute('SELECT role FROM users WHERE id = ?', [req.session.userId])
    if (!rows.length || rows[0].role !== 'admin') return res.status(403).send('Forbidden: admin only')
    next()
  } catch (err) {
    next(err)
  }
}

/* --------------------------------------------------
   Dashboard – paginated per-user workout list
----------------------------------------------------- */
router.get('/dashboard', requireLogin, async (req, res, next) => {
  try {
    const userId = Number(req.session.userId)
    if (!Number.isFinite(userId)) return res.redirect(res.locals.buildUrl('/users/login'))

    // clamp paging to avoid silly values
    const page = Math.max(1, parsePositiveInt(req.query.page, 1))
    const pageSize = Math.min(50, Math.max(1, parsePositiveInt(req.query.pageSize, 10)))
    const offset = (page - 1) * pageSize

    const [countRows] = await db.execute(
      'SELECT COUNT(*) AS total FROM workouts WHERE user_id = ?',
      [userId]
    )
    const total = Number(countRows[0]?.total || 0)
    const totalPages = Math.max(1, Math.ceil(total / pageSize))

    // pagination limits must be interpolated, parameters only for the userId
    const sql = `SELECT * FROM workouts WHERE user_id = ? ORDER BY activity_date DESC LIMIT ${pageSize} OFFSET ${offset}`
    const [rows] = await db.execute(sql, [userId])

    res.render('dashboard', { workouts: rows, pageTitle: 'Dashboard', page, totalPages })
  } catch (err) {
    console.error('[dashboard] error', err)
    next(err)
  }
})

/* --------------------------------------------------
   Add workout (form)
----------------------------------------------------- */
router.get('/add', requireLogin, (req, res) => {
  res.render('workout_add', {
    pageTitle: 'Add Workout',
    formData: {},
    errors: [],
    csrfToken: req.csrfToken ? req.csrfToken() : ''
  })
})

/* --------------------------------------------------
   Add workout (POST)
----------------------------------------------------- */
router.post(
  '/add',
  requireLogin,
  [
    // baseline validation to avoid junk inserts
    check('activity').isLength({ min: 2 }).withMessage('Activity name is required'),
    check('activity_date').isISO8601().withMessage('Valid date required'),
    check('duration_mins').isInt({ min: 1 }).withMessage('Duration must be positive'),
    check('calories').optional({ checkFalsy: true }).isInt({ min: 0 }).withMessage('Calories must be non-negative')
  ],
  async (req, res, next) => {
    try {
      const errors = validationResult(req)
      const formData = req.body

      if (!errors.isEmpty()) {
        return res.render('workout_add', {
          errors: errors.array(),
          formData,
          pageTitle: 'Add Workout',
          csrfToken: req.csrfToken ? req.csrfToken() : ''
        })
      }

      // allow sanitise middleware 
      const activity = req.sanitize ? req.sanitize(req.body.activity) : req.body.activity
      const activity_date = req.sanitize ? req.sanitize(req.body.activity_date) : req.body.activity_date
      const duration_mins = parseInt(req.body.duration_mins, 10)
      const calories = req.body.calories ? parseInt(req.body.calories, 10) : null
      const notes = req.sanitize ? req.sanitize(req.body.notes || '') : (req.body.notes || '')
      const is_public = req.body.is_public ? 1 : 0

      await db.execute(
        `INSERT INTO workouts (user_id, activity, activity_date, duration_mins, calories, notes, source, is_public)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [req.session.userId, activity, activity_date, duration_mins, calories, notes, 'manual', is_public]
      )

      res.redirect(res.locals.buildUrl('/workouts/dashboard'))
    } catch (err) {
      next(err)
    }
  }
)

/* --------------------------------------------------
   Search (form)
----------------------------------------------------- */
router.get('/search', (req, res) => {
  res.render('search', { pageTitle: 'Search Workouts' })
})

/* --------------------------------------------------
   Search (results)
----------------------------------------------------- */
router.get('/search-results', async (req, res, next) => {
  try {
    let q = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 200) : ''

    const page = Math.max(1, parsePositiveInt(req.query.page, 1))
    const pageSize = Math.min(100, Math.max(1, parsePositiveInt(req.query.pageSize, 20)))
    const offset = (page - 1) * pageSize

    // both queries assembled in sync so total count matches the paged query
    let countSql = 'SELECT COUNT(*) AS total FROM workouts w JOIN users u ON w.user_id = u.id'
    let sql = 'SELECT w.*, u.username FROM workouts w JOIN users u ON w.user_id = u.id'
    const params = []
    const where = []

    if (q.length) {
      where.push('w.activity LIKE ?')
      params.push('%' + q + '%')
    }

    if (where.length) {
      const clause = ' WHERE ' + where.join(' AND ')
      sql += clause
      countSql += clause
    }

    sql += ` ORDER BY w.activity_date DESC LIMIT ${pageSize} OFFSET ${offset}`

    const [countRows] = await db.execute(countSql, params.slice())
    const total = Number(countRows[0]?.total || 0)
    const totalPages = Math.max(1, Math.ceil(total / pageSize))

    const [rows] = await db.execute(sql, params)

    res.render('workouts_list', {
      workouts: rows,
      pageTitle: 'Search Results',
      page,
      totalPages,
      q
    })
  } catch (err) {
    console.error('[search-results] error', err)
    next(err)
  }
})

/* --------------------------------------------------
   Public feed – global visible workouts
----------------------------------------------------- */
router.get('/feed', async (req, res, next) => {
  try {
    const page = Math.max(1, parsePositiveInt(req.query.page, 1))
    const pageSize = Math.min(20, Math.max(1, parsePositiveInt(req.query.pageSize, 10)))
    const offset = (page - 1) * pageSize

    const [countRows] = await db.execute(
      'SELECT COUNT(*) AS total FROM workouts WHERE is_public = 1'
    )
    const total = Number(countRows[0]?.total || 0)
    const totalPages = Math.max(1, Math.ceil(total / pageSize))

    const sql = `
      SELECT w.*, u.username
      FROM workouts w
      JOIN users u ON w.user_id = u.id
      WHERE w.is_public = 1
      ORDER BY w.activity_date DESC
      LIMIT ${pageSize} OFFSET ${offset}`
    const [rows] = await db.execute(sql)

    res.render('feed', {
      workouts: rows,
      page,
      totalPages,
      pageTitle: 'Public Feed',
      csrfToken: req.csrfToken ? req.csrfToken() : ''
    })
  } catch (err) {
    console.error('[feed] error', err)
    next(err)
  }
})

/* --------------------------------------------------
   Single public post (workout page)
----------------------------------------------------- */
router.get('/post/:id', async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10)
    if (Number.isNaN(id)) return res.status(400).send('Invalid post id')

    // check if the workout is public
    const [wrows] = await db.execute(
      `SELECT w.*, u.username
       FROM workouts w
       JOIN users u ON w.user_id = u.id
       WHERE w.id = ? AND w.is_public = 1`,
      [id]
    )
    if (!wrows.length) return res.status(404).send('Post not found or not public')

    const workout = wrows[0]

    // main post attachments
    const [attachments] = await db.execute(
      'SELECT * FROM attachments WHERE workout_id = ? ORDER BY created_at ASC',
      [id]
    )

    // comments + user info
    const [comments] = await db.execute(
      `SELECT c.id, c.user_id, c.content AS comment, c.created_at, u.username
       FROM comments c
       LEFT JOIN users u ON u.id = c.user_id
       WHERE c.workout_id = ?
       ORDER BY c.created_at ASC`,
      [id]
    )

    // gather attachment lists per comment
    const [allAtts] = await db.execute(
      'SELECT * FROM attachments WHERE workout_id = ?', [id]
    )
    const attsByComment = {}
    allAtts.forEach(a => {
      const key = a.comment_id ? String(a.comment_id) : 'post'
      ;(attsByComment[key] ||= []).push(a)
    })

    res.render('post', {
      workout,
      attachments,
      comments,
      attsByComment,
      pageTitle: `Post: ${workout.activity}`,
      csrfToken: req.csrfToken ? req.csrfToken() : ''
    })
  } catch (err) {
    console.error('[post] error', err)
    next(err)
  }
})

/* --------------------------------------------------
   Comment submission + attachment
----------------------------------------------------- */
// separate storage config 
const attachStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const name = Date.now() + '-' + file.originalname.replace(/\s+/g, '-')
    cb(null, name)
  }
})
const attachUpload = multer({
  storage: attachStorage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /\.(jpg|jpeg|png|gif|pdf|txt|csv|gpx)$/i
    if (!file.originalname.match(allowed)) {
      return cb(new Error('Attachment type not allowed (images, pdf, txt, csv, gpx)'))
    }
    cb(null, true)
  }
})

router.post('/post/:id/comment', requireLogin, attachUpload.single('attachment'), async (req, res, next) => {
  const workoutId = parseInt(req.params.id, 10)
  if (Number.isNaN(workoutId)) return res.status(400).send('Invalid post id')

  const text = req.sanitize ? req.sanitize(req.body.comment || '') : (req.body.comment || '')
  if (!text.trim()) {
    if (req.headers.accept?.includes('application/json')) {
      return res.status(400).json({ error: 'Comment required' })
    }
    return res.redirect(res.locals.buildUrl(`/workouts/post/${workoutId}`))
  }

  const conn = await db.getConnection()
  try {
    // transaction to keep comment + attachment 
    await conn.beginTransaction()

    const [result] = await conn.execute(
      'INSERT INTO comments (workout_id, user_id, content) VALUES (?, ?, ?)',
      [workoutId, req.session.userId, text]
    )
    const commentId = result.insertId

    // store file if provided
    if (req.file) {
      const file = req.file
      await conn.execute(
        `INSERT INTO attachments (workout_id, comment_id, user_id, filename, original_name, mime, size)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [workoutId, commentId, req.session.userId, file.filename, file.originalname, file.mimetype, file.size]
      )
    }

    await conn.commit()

    // JSON clients get the new comment immediately
    if (req.headers.accept?.includes('application/json')) {
      const [[comment]] = await db.execute(
        `SELECT c.id, c.content AS comment, c.created_at, u.username
         FROM comments c
         LEFT JOIN users u ON u.id = c.user_id
         WHERE c.id = ?`,
        [commentId]
      )
      const [atts] = await db.execute(
        'SELECT * FROM attachments WHERE comment_id = ?', [commentId]
      )
      return res.json({ success: true, comment, attachments: atts })
    }

    // fallback: reload the post page
    res.redirect(res.locals.buildUrl(`/workouts/post/${workoutId}`) + '#comments')
  } catch (err) {
    try { await conn.rollback() } catch {}
    console.error('[post comment] error', err)
    next(err)
  } finally {
    conn.release()
  }
})

/* --------------------------------------------------
   CSV export 
----------------------------------------------------- */
router.get('/export', requireLogin, async (req, res, next) => {
  try {
    const userId = req.session.userId

    // export only essential fields
    const [rows] = await db.execute(
      `SELECT activity_date, activity, duration_mins, calories, notes, source
       FROM workouts
       WHERE user_id = ?
       ORDER BY activity_date DESC`,
      [userId]
    )

    // build CSV manually
    const header = ['activity_date', 'activity', 'duration_mins', 'calories', 'notes', 'source']
    const lines = [header.join(',')]

    rows.forEach(r => {
      // date handling
      const dateStr = r.activity_date?.toISOString?.()
        ? r.activity_date.toISOString().slice(0, 10)
        : String(r.activity_date || '')

      const activityEsc = `"${(r.activity || '').replace(/"/g, '""')}"`
      const notesEsc = `"${(r.notes || '').replace(/"/g, '""')}"`

      const row = [
        dateStr,
        activityEsc,
        r.duration_mins ?? '',
        r.calories ?? '',
        notesEsc,
        r.source || ''
      ]
      lines.push(row.join(','))
    })

    const csv = lines.join('\n')

    res.setHeader('Content-Type', 'text/csv')
    res.setHeader('Content-Disposition', `attachment; filename="workouts_user_${userId}.csv"`)
    res.send(csv)
  } catch (err) {
    next(err)
  }
})

/* --------------------------------------------------
   GPX upload + parsing (tracks, waypoints, plain text)
----------------------------------------------------- */
const csurf = require('csurf')
const csrfProtection = csurf()

// upload form
router.get('/upload', requireLogin, csrfProtection, (req, res) => {
  res.render('upload_gpx', {
    pageTitle: 'Upload GPX',
    csrfToken: req.csrfToken ? req.csrfToken() : ''
  })
})

// GPX upload handler
router.post(
  '/upload',
  requireLogin,
  upload.single('gpxfile'),
  csrfProtection,
  async (req, res, next) => {
    if (!req.file) return res.status(400).render('error', { error: 'No file uploaded' })

    const filePath = req.file.path
    let content = ''

    // trim BOM + junk ahead 
    const sanitizeXml = s => (s || '').replace(/^\uFEFF/, '').replace(/^[^<]+/, '')

    const escapeAmp = s =>
      s.replace(/&(?!(?:amp|lt|gt|apos|quot|#[0-9]+|#x[0-9a-fA-F]+);)/g, '&amp;')

    // parser for text exports from phone apps
    const plainTextToInserts = text => {
      const toIso = d => {
        const p = d.split('/')
        if (p.length !== 3) return null
        return `${p[2].padStart(4)}-${p[1].padStart(2, '0')}-${p[0].padStart(2, '0')}`
      }

      // treat blank lines as record separators
      const blocks = text
        .split(/\n\s*\n/)
        .map(b => b.trim())
        .filter(Boolean)

      return blocks.map(block => {
        const norm = block.replace(/\r/g, '').replace(/\n+/g, ' ').replace(/\s+/g, ' ').trim()
        const activity =
          (norm.match(/Activity:\s*(.*?)\s*(?:Date:|Duration|Calories|Notes|$)/i) || [])[1] ||
          'Imported Activity'

        const dateMatch1 = norm.match(/Date:\s*([0-3]?\d\/[0-1]?\d\/\d{4})/i)
        const dateMatch2 = norm.match(/Date:\s*(\d{4}-\d{2}-\d{2})/i)
        const dateIso = dateMatch2
          ? dateMatch2[1]
          : dateMatch1
          ? toIso(dateMatch1[1])
          : new Date().toISOString().slice(0, 10)

        const duration = +(norm.match(/Duration\s*\(mins\):\s*(\d+)/i)?.[1] || 0)
        const calories = +(norm.match(/Calories:\s*(\d+)/i)?.[1] || null)
        const notes = (norm.match(/Notes:\s*(.*)$/i)?.[1] || '').trim()

        return {
          activity,
          dateIso,
          durationMins: duration,
          calories: isNaN(calories) ? null : calories,
          notes: notes || `Imported from text: ${activity}`
        }
      })
    }

    // DB insert so both GPX and text reuse the same path
    const insertOne = async ({ activity, dateIso, durationMins, calories, notes, source = 'gpx' }) => {
      await db.execute(
        `INSERT INTO workouts (user_id, activity, activity_date, duration_mins, calories, notes, source)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [req.session.userId, activity, dateIso, durationMins ?? 0, calories ?? null, notes ?? '', source]
      )
    }

    try {
      const buf = await fs.promises.readFile(filePath)
      if (!buf || buf.length === 0) throw new Error('Uploaded file is empty')

      content = buf.toString('utf8')

      // try GPX/XML first
      let xml = escapeAmp(sanitizeXml(content))

      if (xml.trim().startsWith('<')) {
        const parser = new xml2js.Parser({ explicitArray: true, trim: true })
        const parsed = await parser.parseStringPromise(xml)

        const inserts = []

        // GPX <trk> 
        if (parsed.gpx?.trk) {
          parsed.gpx.trk.forEach(trk => {
            const name =
              trk.name?.[0] ||
              path.basename(req.file.originalname, path.extname(req.file.originalname))

            const times = []
            trk.trkseg?.forEach(seg =>
              seg.trkpt?.forEach(pt => {
                if (pt.time?.[0]) times.push(new Date(pt.time[0]))
              })
            )

            // track duration = first→last timestamp
            let dateIso = new Date().toISOString().slice(0, 10)
            let durationMins = 0
            if (times.length) {
              const sorted = times.sort((a, b) => a - b)
              dateIso = sorted[0].toISOString().slice(0, 10)
              durationMins = Math.max(
                1,
                Math.round((sorted[sorted.length - 1] - sorted[0]) / 60000)
              )
            }

            inserts.push({
              activity: name,
              dateIso,
              durationMins,
              calories: null,
              notes: `Imported from GPX track: ${req.file.originalname}`
            })
          })
        }

        // GPX <wpt> 
        if (parsed.gpx?.wpt) {
          parsed.gpx.wpt.forEach(wpt => {
            const name =
              wpt.name?.[0] ||
              path.basename(req.file.originalname, path.extname(req.file.originalname))

            const desc = (wpt.desc?.[0] || '').toString()

            // waypoint exports embed metadata inside
            const dateMatch1 = desc.match(/Date:\s*([0-3]?\d\/[0-1]?\d\/\d{4})/i)
            const dateMatch2 = desc.match(/Date:\s*(\d{4}-\d{2}-\d{2})/i)
            const dateIso = dateMatch2
              ? dateMatch2[1]
              : dateMatch1
              ? (() => {
                  const p = dateMatch1[1].split('/')
                  return `${p[2]}-${p[1].padStart(2, '0')}-${p[0].padStart(2, '0')}`
                })()
              : new Date().toISOString().slice(0, 10)

            const durationMins = +(desc.match(/Duration\s*\(mins\):\s*(\d+)/i)?.[1] || 0)
            const calories = +(desc.match(/Calories:\s*(\d+)/i)?.[1] || null)
            const notes = (desc.match(/Notes:\s*([\s\S]*)/i)?.[1] || '').trim()

            inserts.push({
              activity: name,
              dateIso,
              durationMins,
              calories: isNaN(calories) ? null : calories,
              notes: notes || `Imported from GPX waypoint: ${req.file.originalname}`
            })
          })
        }

        // track if XML parsed but contained neither trk nor wpt
        if (!inserts.length) {
          inserts.push({
            activity: path.basename(req.file.originalname, path.extname(req.file.originalname)),
            dateIso: new Date().toISOString().slice(0, 10),
            durationMins: 0,
            calories: null,
            notes: `Imported from GPX: ${req.file.originalname}`
          })
        }

        for (const it of inserts) await insertOne(it)
        return res.send(
          `GPX uploaded and parsed – ${inserts.length} workout(s) imported <a href="${res.locals.buildUrl('/workouts/dashboard')}">Back</a>`
        )
      }

      // treat file as plaintext export
      const plain = plainTextToInserts(content)
      if (!plain.length) throw new Error('File is neither valid GPX XML nor recognizable text export')

      for (const it of plain)
        await insertOne({ ...it, source: 'gpx-text' })

      return res.send(
        `Text file parsed – ${plain.length} workout(s) imported <a href="${res.locals.buildUrl('/workouts/dashboard')}">Back</a>`
      )
    } catch (err) {
      console.error('GPX import error:', err.message || err)
      return res.status(400).render('error', { error: err.message || 'GPX parse error' })
    } finally {
      // clean up uploaded file after parse
      try {
        if (filePath) await fs.promises.unlink(filePath)
      } catch (_) {}
    }
  }
)

/* --------------------------------------------------
   Weekly totals – used by frontend chart.js
----------------------------------------------------- */
router.get('/weekly-totals', requireLogin, async (req, res, next) => {
  try {
    const userId = req.session.userId

    // aggregate last 2 months by ISO week
    const [rows] = await db.execute(
      `SELECT YEARWEEK(activity_date, 1) AS yw, MIN(activity_date) AS week_start,
              SUM(duration_mins) AS total_mins
       FROM workouts
       WHERE user_id = ? AND activity_date >= DATE_SUB(CURDATE(), INTERVAL 8 WEEK)
       GROUP BY yw
       ORDER BY yw ASC`,
      [userId]
    )

    const labels = []
    const totals = []
    const mapByStart = {}

    // rows into lookup by week_start
    rows.forEach(r => {
      const ws = r.week_start?.toISOString?.()
        ? r.week_start.toISOString().slice(0, 10)
        : String(r.week_start)
      mapByStart[ws] = Number(r.total_mins || 0)
    })

    // 8 buckets in order
    for (let i = 7; i >= 0; i--) {
      const d = new Date()
      d.setDate(d.getDate() - i * 7)
      const weekStartStr = d.toISOString().slice(0, 10)
      labels.push(weekStartStr)
      totals.push(mapByStart[weekStartStr] || 0)
    }

    res.json({ labels, totals })
  } catch (err) {
    next(err)
  }
})

module.exports = router
