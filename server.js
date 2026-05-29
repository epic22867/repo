import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pkg from 'pg';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const { Pool } = pkg;
const app = express();
const SECRET = process.env.JWT_SECRET || 'changeme';
const __dirname = dirname(fileURLToPath(import.meta.url));

const connStr = (() => {
  const internal = process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.POSTGRESQL_URL;
  const pub = process.env.DATABASE_PUBLIC_URL || process.env.POSTGRES_PUBLIC_URL;
  // Prefer public URL if internal hostname is a .railway.internal address,
  // since private networking may not be available in all Railway environments.
  if (internal && internal.includes('.railway.internal') && pub) return pub;
  return internal || pub;
})();

if (!connStr) {
  console.error('ERROR: No database URL found. Set DATABASE_URL or DATABASE_PUBLIC_URL variable.');
  process.exit(1);
}

const isInternal = connStr.includes('.railway.internal');
const pool = new Pool({
  connectionString: connStr,
  ...(isInternal ? {} : { ssl: { rejectUnauthorized: false } })
});

await pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    bio TEXT DEFAULT '',
    banner_url TEXT DEFAULT '',
    profile_background TEXT DEFAULT '',
    accent_color TEXT DEFAULT '#4da3ff',
    profile_theme TEXT DEFAULT 'aero',
    profile_widgets JSONB DEFAULT '[]'::jsonb,
    userbars JSONB DEFAULT '[]'::jsonb,
    avatar_url TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS posts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    content TEXT NOT NULL DEFAULT '',
    media_url TEXT DEFAULT '',
    media_type TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS follows (
    follower INTEGER REFERENCES users(id) ON DELETE CASCADE,
    following INTEGER REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (follower, following)
  );

  CREATE TABLE IF NOT EXISTS timeouts (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    reason TEXT DEFAULT ''
  );

  CREATE TABLE IF NOT EXISTS likes (
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, post_id)
  );

  CREATE TABLE IF NOT EXISTS comments (
    id SERIAL PRIMARY KEY,
    post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
  );
`);

// In-memory rate limit tracker: userId -> array of post timestamps (ms)
const postTimestamps = new Map();
const RATE_WINDOW_MS = 20 * 1000;   // 20 seconds
const RATE_MAX_POSTS = 4;            // max posts per window
const AUTO_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

const safeAlterQueries = [
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS banner_url TEXT DEFAULT ''`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_background TEXT DEFAULT ''`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS accent_color TEXT DEFAULT '#4da3ff'`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_theme TEXT DEFAULT 'aero'`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_widgets JSONB DEFAULT '[]'::jsonb`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS userbars JSONB DEFAULT '[]'::jsonb`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT DEFAULT ''`,
  `ALTER TABLE posts ADD COLUMN IF NOT EXISTS media_url TEXT DEFAULT ''`,
  `ALTER TABLE posts ADD COLUMN IF NOT EXISTS media_type TEXT DEFAULT ''`,
  `ALTER TABLE posts ADD COLUMN IF NOT EXISTS is_sticker BOOLEAN DEFAULT FALSE`
];

for (const q of safeAlterQueries) {
  await pool.query(q);
}

app.use(express.json({ limit: '35mb' }));
app.use(express.static('public'));

app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'index.html'));
});

const auth = (req, res, next) => {
  try {
    req.user = jwt.verify((req.headers.authorization || '').split(' ')[1], SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Required fields missing' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);

    const { rows } = await pool.query(
      `INSERT INTO users (username, password)
       VALUES ($1, $2)
       RETURNING id, username, bio, banner_url, profile_background,
       accent_color, profile_theme, profile_widgets, userbars, avatar_url, created_at`,
      [username, hash]
    );

    const user = rows[0];

    res.json({
      token: jwt.sign(user, SECRET, { expiresIn: '30d' }),
      user
    });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(409).json({ error: 'Username already taken' });
    }

    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  const { rows } = await pool.query(
    'SELECT * FROM users WHERE username=$1',
    [username]
  );

  const user = rows[0];

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const { password: _, ...safe } = user;

  res.json({
    token: jwt.sign(safe, SECRET, { expiresIn: '30d' }),
    user: safe
  });
});

app.get('/api/feed', auth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT p.*, u.username, u.accent_color, u.banner_url,
           COUNT(DISTINCT l.user_id)::int AS like_count,
           BOOL_OR(l.user_id = $1) AS liked,
           COUNT(DISTINCT c.id)::int AS comment_count
    FROM posts p
    JOIN users u ON u.id = p.user_id
    LEFT JOIN likes l ON l.post_id = p.id
    LEFT JOIN comments c ON c.post_id = p.id
    WHERE p.user_id = $1
       OR p.user_id IN (SELECT following FROM follows WHERE follower = $1)
    GROUP BY p.id, u.username, u.accent_color, u.banner_url
    ORDER BY p.id DESC
    LIMIT 100
  `, [req.user.id]);
  res.json(rows);
});

app.get('/api/explore', auth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT p.*, u.username, u.accent_color, u.banner_url,
           COUNT(DISTINCT l.user_id)::int AS like_count,
           BOOL_OR(l.user_id = $1) AS liked,
           COUNT(DISTINCT c.id)::int AS comment_count
    FROM posts p
    JOIN users u ON u.id = p.user_id
    LEFT JOIN likes l ON l.post_id = p.id
    LEFT JOIN comments c ON c.post_id = p.id
    GROUP BY p.id, u.username, u.accent_color, u.banner_url
    ORDER BY p.id DESC
    LIMIT 50
  `, [req.user.id]);
  res.json(rows);
});

// Helper: check if user is currently timed out. Returns { timedOut, expiresAt, reason } or null.
async function getUserTimeout(userId) {
  const { rows } = await pool.query(
    'SELECT expires_at, reason FROM timeouts WHERE user_id=$1 AND expires_at > NOW()',
    [userId]
  );
  if (!rows[0]) return null;
  return { expiresAt: rows[0].expires_at, reason: rows[0].reason };
}

// Helper: apply a timeout to a user
async function applyTimeout(userId, durationMs, reason = '') {
  const expiresAt = new Date(Date.now() + durationMs);
  await pool.query(
    `INSERT INTO timeouts (user_id, expires_at, reason)
     VALUES ($1, $2, $3)
     ON CONFLICT (user_id) DO UPDATE SET expires_at=$2, reason=$3`,
    [userId, expiresAt, reason]
  );
}

// GET /api/me/timeout — frontend polls this to know if user is timed out
app.get('/api/me/timeout', auth, async (req, res) => {
  const t = await getUserTimeout(req.user.id);
  res.json(t ? { timedOut: true, expiresAt: t.expiresAt, reason: t.reason } : { timedOut: false });
});

// POST /api/admin/timeout — manually time out a user (requires admin secret header)
app.post('/api/admin/timeout', async (req, res) => {
  const adminSecret = process.env.ADMIN_SECRET || 'admin-secret-changeme';
  if (req.headers['x-admin-secret'] !== adminSecret) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const { username, duration_minutes, reason } = req.body;
  if (!username || !duration_minutes) {
    return res.status(400).json({ error: 'username and duration_minutes required' });
  }
  const { rows } = await pool.query('SELECT id FROM users WHERE username=$1', [username]);
  if (!rows[0]) return res.status(404).json({ error: 'User not found' });
  const ms = parseInt(duration_minutes) * 60 * 1000;
  await applyTimeout(rows[0].id, ms, reason || '');
  res.json({ ok: true, username, expires_at: new Date(Date.now() + ms) });
});

// DELETE /api/admin/timeout — remove a timeout early
app.delete('/api/admin/timeout', async (req, res) => {
  const adminSecret = process.env.ADMIN_SECRET || 'admin-secret-changeme';
  if (req.headers['x-admin-secret'] !== adminSecret) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'username required' });
  const { rows } = await pool.query('SELECT id FROM users WHERE username=$1', [username]);
  if (!rows[0]) return res.status(404).json({ error: 'User not found' });
  await pool.query('DELETE FROM timeouts WHERE user_id=$1', [rows[0].id]);
  res.json({ ok: true });
});

app.post('/api/posts', auth, async (req, res) => {
  // 1. Check for active manual/auto timeout in DB
  const activeTimeout = await getUserTimeout(req.user.id);
  if (activeTimeout) {
    return res.status(429).json({
      error: 'timeout',
      expiresAt: activeTimeout.expiresAt,
      reason: activeTimeout.reason || ''
    });
  }

  // 2. Rate-limit: max 4 posts per 20 seconds → auto 5-min timeout
  const now = Date.now();
  const uid = req.user.id;
  const stamps = (postTimestamps.get(uid) || []).filter(t => now - t < RATE_WINDOW_MS);
  if (stamps.length >= RATE_MAX_POSTS) {
    await applyTimeout(uid, AUTO_TIMEOUT_MS, 'Posting too fast');
    postTimestamps.delete(uid);
    return res.status(429).json({
      error: 'timeout',
      expiresAt: new Date(now + AUTO_TIMEOUT_MS),
      reason: 'Posting too fast'
    });
  }
  stamps.push(now);
  postTimestamps.set(uid, stamps);

  const { content, media_url, media_type, is_sticker } = req.body;

  if (!content?.trim() && !media_url) {
    return res.status(400).json({ error: 'Post is empty' });
  }

  // Stickers are remote URLs from GitHub — skip base64 size check
  if (media_url && !is_sticker && media_url.length > 34 * 1024 * 1024) {
    return res.status(400).json({ error: 'Media too large (max 25 MB)' });
  }

  const ALLOWED = ['image/png','image/jpeg','image/gif','video/mp4'];
  if (media_type && !ALLOWED.includes(media_type)) {
    return res.status(400).json({ error: 'Unsupported media type' });
  }

  const { rows } = await pool.query(
    `INSERT INTO posts (user_id, content, media_url, media_type, is_sticker)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING *`,
    [req.user.id, (content || '').trim(), media_url || '', media_type || '', !!is_sticker]
  );

  res.json({ ...rows[0], username: req.user.username });
});

// ── LIKES ────────────────────────────────────────────────────
app.post('/api/posts/:id/like', auth, async (req, res) => {
  const postId = parseInt(req.params.id);
  const userId = req.user.id;
  const { rows } = await pool.query(
    'SELECT 1 FROM likes WHERE user_id=$1 AND post_id=$2', [userId, postId]
  );
  if (rows.length) {
    await pool.query('DELETE FROM likes WHERE user_id=$1 AND post_id=$2', [userId, postId]);
  } else {
    await pool.query('INSERT INTO likes (user_id, post_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [userId, postId]);
  }
  const { rows: cnt } = await pool.query(
    'SELECT COUNT(*)::int AS like_count FROM likes WHERE post_id=$1', [postId]
  );
  res.json({ liked: !rows.length, like_count: cnt[0].like_count });
});

// ── COMMENTS ─────────────────────────────────────────────────
app.get('/api/posts/:id/comments', auth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT c.*, u.username, u.avatar_url, u.accent_color
    FROM comments c
    JOIN users u ON u.id = c.user_id
    WHERE c.post_id = $1
    ORDER BY c.id ASC
  `, [parseInt(req.params.id)]);
  res.json(rows);
});

app.post('/api/posts/:id/comments', auth, async (req, res) => {
  const content = (req.body.content || '').trim().slice(0, 500);
  if (!content) return res.status(400).json({ error: 'Empty comment' });
  const { rows } = await pool.query(
    `INSERT INTO comments (post_id, user_id, content)
     VALUES ($1, $2, $3) RETURNING *`,
    [parseInt(req.params.id), req.user.id, content]
  );
  res.json({ ...rows[0], username: req.user.username, avatar_url: req.user.avatar_url || '', accent_color: req.user.accent_color || '#4da3ff' });
});

app.delete('/api/comments/:id', auth, async (req, res) => {
  await pool.query(
    'DELETE FROM comments WHERE id=$1 AND user_id=$2',
    [parseInt(req.params.id), req.user.id]
  );
  res.json({ ok: true });
});

app.delete('/api/posts/:id', auth, async (req, res) => {
  await pool.query(
    'DELETE FROM posts WHERE id=$1 AND user_id=$2',
    [req.params.id, req.user.id]
  );

  res.json({ ok: true });
});

app.get('/api/users/:username', auth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, username, bio,
            banner_url,
            profile_background,
            accent_color,
            profile_theme,
            profile_widgets,
            userbars,
            avatar_url,
            created_at
     FROM users
     WHERE username=$1`,
    [req.params.username]
  );

  if (!rows[0]) {
    return res.status(404).json({ error: 'User not found' });
  }

  const user = rows[0];

  const [postsR, followersR, followingR, isFollowingR] = await Promise.all([
    pool.query(`
      SELECT p.*, COUNT(DISTINCT l.user_id)::int AS like_count,
             BOOL_OR(l.user_id = $2) AS liked,
             COUNT(DISTINCT c.id)::int AS comment_count
      FROM posts p
      LEFT JOIN likes l ON l.post_id = p.id
      LEFT JOIN comments c ON c.post_id = p.id
      WHERE p.user_id = $1
      GROUP BY p.id
      ORDER BY p.id DESC
    `, [user.id, req.user.id]),
    pool.query('SELECT COUNT(*) FROM follows WHERE following=$1', [user.id]),
    pool.query('SELECT COUNT(*) FROM follows WHERE follower=$1', [user.id]),
    pool.query('SELECT 1 FROM follows WHERE follower=$1 AND following=$2', [req.user.id, user.id])
  ]);

  res.json({
    ...user,
    posts: postsR.rows,
    followers: parseInt(followersR.rows[0].count),
    following: parseInt(followingR.rows[0].count),
    isFollowing: isFollowingR.rows.length > 0
  });
});

app.post('/api/follow/:id', auth, async (req, res) => {
  const id = parseInt(req.params.id);

  const { rows } = await pool.query(
    'SELECT 1 FROM follows WHERE follower=$1 AND following=$2',
    [req.user.id, id]
  );

  if (rows.length) {
    await pool.query(
      'DELETE FROM follows WHERE follower=$1 AND following=$2',
      [req.user.id, id]
    );
  } else {
    await pool.query(
      'INSERT INTO follows (follower, following) VALUES ($1,$2)',
      [req.user.id, id]
    );
  }

  res.json({ ok: true });
});

app.get('/api/me', auth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, username, bio,
            banner_url,
            profile_background,
            accent_color,
            profile_theme,
            profile_widgets,
            userbars,
            avatar_url,
            created_at
     FROM users
     WHERE id=$1`,
    [req.user.id]
  );

  if (!rows[0]) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json(rows[0]);
});

app.patch('/api/me', auth, async (req, res) => {
  try {
    const {
      bio,
      banner_url,
      profile_background,
      accent_color,
      profile_theme,
      profile_widgets,
      userbars,
      avatar_url
    } = req.body || {};

    const safeWidgets = Array.isArray(profile_widgets)
      ? profile_widgets.slice(0, 12)
      : [];

    const safeUserbars = Array.isArray(userbars)
      ? userbars.slice(0, 12)
      : [];

    await pool.query(
      `UPDATE users
       SET bio = $1,
           banner_url = $2,
           profile_background = $3,
           accent_color = $4,
           profile_theme = $5,
           profile_widgets = $6::jsonb,
           userbars = $7::jsonb,
           avatar_url = $8
       WHERE id = $9`,
      [
        typeof bio === 'string' ? bio.slice(0, 300) : '',
        typeof banner_url === 'string' ? banner_url.slice(0, 2000) : '',
        typeof profile_background === 'string' ? profile_background.slice(0, 2000) : '',
        typeof accent_color === 'string' ? accent_color : '#4da3ff',
        typeof profile_theme === 'string' ? profile_theme : 'aero',
        JSON.stringify(safeWidgets),
        JSON.stringify(safeUserbars),
        typeof avatar_url === 'string' ? avatar_url.slice(0, 2000) : '',
        req.user.id
      ]
    );

    const { rows } = await pool.query(
      `SELECT id, username, bio,
              banner_url,
              profile_background,
              accent_color,
              profile_theme,
              profile_widgets,
              userbars,
              avatar_url,
              created_at
       FROM users
       WHERE id=$1`,
      [req.user.id]
    );

    res.json({ ok: true, user: rows[0] });
  } catch (e) {
    console.error('PROFILE_UPDATE_ERROR', e);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

app.get('/api/search', auth, async (req, res) => {
  const q = `%${(req.query.q || '').toLowerCase()}%`;

  const { rows } = await pool.query(
    `SELECT id,
            username,
            bio,
            banner_url,
            accent_color,
            created_at
     FROM users
     WHERE LOWER(username) LIKE $1
     LIMIT 20`,
    [q]
  );

  res.json(rows);
});

app.listen(process.env.PORT || 8080, () => {
  console.log('Listening on', process.env.PORT || 8080);
  console.log('DB host:', connStr.replace(/\/\/.*@/, '//***@'));
});
