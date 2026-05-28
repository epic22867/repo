import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { JSONFilePreset } from 'lowdb/node';

const app = express();
const SECRET = process.env.JWT_SECRET || 'changeme';
const db = await JSONFilePreset('db.json', { users: [], posts: [], follows: [] });

app.use(express.json()).use(express.static('public'));

const auth = (req, res, next) => {
  try { req.user = jwt.verify((req.headers.authorization||'').split(' ')[1], SECRET); next(); }
  catch { res.status(401).json({ error: 'Unauthorized' }); }
};

const nextId = arr => arr.length ? Math.max(...arr.map(x=>x.id)) + 1 : 1;
const now = () => new Date().toISOString();

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Required' });
  if (db.data.users.find(u=>u.username===username)) return res.status(409).json({ error: 'Username taken' });
  const user = { id: nextId(db.data.users), username, password: await bcrypt.hash(password, 10), bio: '', created_at: now() };
  db.data.users.push(user); await db.write();
  const { password: _, ...safe } = user;
  res.json({ token: jwt.sign(safe, SECRET, { expiresIn: '30d' }), user: safe });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = db.data.users.find(u=>u.username===username);
  if (!user || !await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
  const { password: _, ...safe } = user;
  res.json({ token: jwt.sign(safe, SECRET, { expiresIn: '30d' }), user: safe });
});

app.get('/api/feed', auth, (req, res) => {
  const following = db.data.follows.filter(f=>f.follower===req.user.id).map(f=>f.following);
  const ids = [req.user.id, ...following];
  const posts = db.data.posts.filter(p=>ids.includes(p.user_id)).sort((a,b)=>b.id-a.id).slice(0,100);
  res.json(posts.map(p=>({...p, username: db.data.users.find(u=>u.id===p.user_id)?.username})));
});

app.get('/api/explore', auth, (req, res) => {
  const posts = [...db.data.posts].sort((a,b)=>b.id-a.id).slice(0,50);
  res.json(posts.map(p=>({...p, username: db.data.users.find(u=>u.id===p.user_id)?.username})));
});

app.post('/api/posts', auth, async (req, res) => {
  const { content } = req.body;
  if (!content?.trim()) return res.status(400).json({ error: 'Empty' });
  const post = { id: nextId(db.data.posts), user_id: req.user.id, content: content.trim(), created_at: now() };
  db.data.posts.push(post); await db.write();
  res.json({ ...post, username: req.user.username });
});

app.delete('/api/posts/:id', auth, async (req, res) => {
  db.data.posts = db.data.posts.filter(p=>!(p.id==req.params.id && p.user_id===req.user.id));
  await db.write(); res.json({ ok: true });
});

app.get('/api/users/:username', auth, (req, res) => {
  const user = db.data.users.find(u=>u.username===req.params.username);
  if (!user) return res.status(404).json({ error: 'Not found' });
  const { password: _, ...safe } = user;
  const posts = db.data.posts.filter(p=>p.user_id===user.id).sort((a,b)=>b.id-a.id);
  const followers = db.data.follows.filter(f=>f.following===user.id).length;
  const following = db.data.follows.filter(f=>f.follower===user.id).length;
  const isFollowing = !!db.data.follows.find(f=>f.follower===req.user.id && f.following===user.id);
  res.json({ ...safe, posts, followers, following, isFollowing });
});

app.post('/api/follow/:id', auth, async (req, res) => {
  const id = parseInt(req.params.id);
  const existing = db.data.follows.findIndex(f=>f.follower===req.user.id && f.following===id);
  if (existing>=0) db.data.follows.splice(existing,1);
  else db.data.follows.push({ follower: req.user.id, following: id });
  await db.write(); res.json({ ok: true });
});

app.patch('/api/me', auth, async (req, res) => {
  const user = db.data.users.find(u=>u.id===req.user.id);
  if (user) { user.bio = req.body.bio||''; await db.write(); }
  res.json({ ok: true });
});

app.get('/api/search', auth, (req, res) => {
  const q = (req.query.q||'').toLowerCase();
  res.json(db.data.users.filter(u=>u.username.toLowerCase().includes(q)).slice(0,20).map(({password:_,...u})=>u));
});

app.listen(process.env.PORT||3000, ()=>console.log('Listening on', process.env.PORT||3000));
