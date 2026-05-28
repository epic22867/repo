import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pkg from 'pg';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const { Pool } = pkg;
const app = express();
const SECRET = process.env.JWT_SECRET || 'changeme';
const __dirname = dirname(fileURLToPath(import.meta.url));

const pool = new Pool({ connectionString: process.env.POSTGRES_URL, ssl: { rejectUnauthorized: false } });

// Init tables
await pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    bio TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS posts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS follows (
    follower INTEGER REFERENCES users(id) ON DELETE CASCADE,
    following INTEGER REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (follower, following)
  );
`);

app.use(express.json());

// Serve index.html at root
app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'index.html'));
});
app.use(express.static('public'));

const auth = (req, res, next) => {
  try { req.user = jwt.verify((req.headers.authorization || '').split(' ')[1], SECRET); next(); }
  catch { res.status(401).json({ error: 'Unauthorized' }); }
};

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Required' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username, bio, created_at',
      [username, hash]
    );
    const user = rows[0];
    res.json({ token: jwt.sign(user, SECRET, { expiresIn: '30d' }), user });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Username taken' });
    throw e;
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
  const user = rows[0];
  if (!user || !await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
  const { password: _, ...safe } = user;
  res.json({ token: jwt.sign(safe, SECRET, { expiresIn: '30d' }), user: safe });
});

app.get('/api/feed', auth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT p.*, u.username FROM posts p
    JOIN users u ON u.id = p.user_id
    WHERE p.user_id = $1 OR p.user_id IN (SELECT following FROM follows WHERE follower=$1)
    ORDER BY p.id DESC LIMIT 100
  `, [req.user.id]);
  res.json(rows);
});

app.get('/api/explore', auth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT p.*, u.username FROM posts p
    JOIN users u ON u.id = p.user_id
    ORDER BY p.id DESC LIMIT 50
  `);
  res.json(rows);
});

app.post('/api/posts', auth, async (req, res) => {
  const { content } = req.body;
  if (!content?.trim()) return res.status(400).json({ error: 'Empty' });
  const { rows } = await pool.query(
    'INSERT INTO posts (user_id, content) VALUES ($1, $2) RETURNING *',
    [req.user.id, content.trim()]
  );
  res.json({ ...rows[0], username: req.user.username });
});

app.delete('/api/posts/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM posts WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  res.json({ ok: true });
});

app.get('/api/users/:username', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [req.params.username]);
  if (!rows[0]) return res.status(404).json({ error: 'Not found' });
  const { password: _, ...user } = rows[0];
  const [postsR, followersR, followingR, isFollowingR] = await Promise.all([
    pool.query('SELECT * FROM posts WHERE user_id=$1 ORDER BY id DESC', [user.id]),
    pool.query('SELECT COUNT(*) FROM follows WHERE following=$1', [user.id]),
    pool.query('SELECT COUNT(*) FROM follows WHERE follower=$1', [user.id]),
    pool.query('SELECT 1 FROM follows WHERE follower=$1 AND following=$2', [req.user.id, user.id]),
  ]);
  res.json({
    ...user,
    posts: postsR.rows,
    followers: parseInt(followersR.rows[0].count),
    following: parseInt(followingR.rows[0].count),
    isFollowing: isFollowingR.rows.length > 0,
  });
});

app.post('/api/follow/:id', auth, async (req, res) => {
  const id = parseInt(req.params.id);
  const { rows } = await pool.query('SELECT 1 FROM follows WHERE follower=$1 AND following=$2', [req.user.id, id]);
  if (rows.length) await pool.query('DELETE FROM follows WHERE follower=$1 AND following=$2', [req.user.id, id]);
  else await pool.query('INSERT INTO follows (follower, following) VALUES ($1,$2)', [req.user.id, id]);
  res.json({ ok: true });
});

app.patch('/api/me', auth, async (req, res) => {
  await pool.query('UPDATE users SET bio=$1 WHERE id=$2', [req.body.bio || '', req.user.id]);
  res.json({ ok: true });
});

app.get('/api/search', auth, async (req, res) => {
  const q = `%${(req.query.q || '').toLowerCase()}%`;
  const { rows } = await pool.query(
    'SELECT id, username, bio, created_at FROM users WHERE LOWER(username) LIKE $1 LIMIT 20',
    [q]
  );
  res.json(rows);
});

app.listen(process.env.PORT || 3000, () => console.log('Listening on', process.env.PORT || 3000));
