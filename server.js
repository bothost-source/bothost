require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs-extra');
const { spawn } = require('child_process');
const { v4: uuidv4 } = require('uuid');
const AdmZip = require('adm-zip');
const os = require('os');

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

fs.ensureDirSync(path.join(__dirname, 'uploads'));
fs.ensureDirSync(path.join(__dirname, 'logs'));

const dbPath = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, plan TEXT DEFAULT 'starter', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  db.run(`CREATE TABLE IF NOT EXISTS bots (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, name TEXT NOT NULL, runtime TEXT NOT NULL, filename TEXT NOT NULL, is_zip BOOLEAN DEFAULT 0, extracted_path TEXT, main_file TEXT, description TEXT, status TEXT DEFAULT 'stopped', port INTEGER, pid INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  db.run(`CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, bot_id INTEGER NOT NULL, message TEXT NOT NULL, type TEXT DEFAULT 'info', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const userDir = path.join(__dirname, 'uploads', req.user.userId.toString());
    fs.ensureDirSync(userDir);
    cb(null, userDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${uuidv4()}-${file.originalname}`);
  }
});

const upload = multer({ storage, limits: { fileSize: 500 * 1024 * 1024 } });

const runningBots = new Map();

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.run('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hashedPassword], function(err) {
    if (err) {
      if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Email exists' });
      return res.status(500).json({ error: err.message });
    }
    const token = jwt.sign({ userId: this.lastID, email }, process.env.JWT_SECRET);
    res.json({ token, user: { id: this.lastID, name, email, plan: 'starter' } });
  });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET);
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, plan: user.plan } });
  });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  db.get('SELECT id, name, email, plan FROM users WHERE id = ?', [req.user.userId], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  });
});

app.get('/api/bots', authenticateToken, (req, res) => {
  db.all('SELECT * FROM bots WHERE user_id = ? ORDER BY created_at DESC', [req.user.userId], (err, bots) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(bots);
  });
});

function findMainFile(dir) {
  const files = fs.readdirSync(dir);
  const priorities = ['index.js', 'bot.js', 'main.js', 'app.js', 'server.js', 'index.py', 'main.py', 'bot.py', 'app.py'];
  for (const priority of priorities) {
    if (files.includes(priority)) return priority;
  }
  const codeFile = files.find(f => f.endsWith('.js') || f.endsWith('.py'));
  if (codeFile) return codeFile;
  return files[0];
}

app.post('/api/bots', authenticateToken, upload.single('botFile'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const { name, runtime, description } = req.body;
  const isZip = req.file.originalname.toLowerCase().endsWith('.zip');
  let extractedPath = null;
  let mainFile = req.file.filename;
  
  if (isZip) {
    try {
      const zip = new AdmZip(req.file.path);
      const extractDir = path.join(__dirname, 'uploads', req.user.userId.toString(), 'extracted', path.basename(req.file.filename, '.zip'));
      fs.ensureDirSync(extractDir);
      zip.extractAllTo(extractDir, true);
      extractedPath = extractDir;
      mainFile = findMainFile(extractDir);
    } catch (err) {
      return res.status(400).json({ error: 'Failed to extract ZIP: ' + err.message });
    }
  }
  
  db.run('INSERT INTO bots (user_id, name, runtime, filename, is_zip, extracted_path, main_file, description, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [req.user.userId, name, runtime, req.file.filename, isZip ? 1 : 0, extractedPath, mainFile, description, 'stopped'],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, name, runtime, filename: req.file.filename, is_zip: isZip ? 1 : 0, main_file: mainFile, description, status: 'stopped' });
    }
  );
});

app.get('/api/bots/:id/logs', authenticateToken, (req, res) => {
  db.all('SELECT * FROM logs WHERE bot_id = ? ORDER BY created_at DESC LIMIT 100', [req.params.id], (err, logs) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(logs);
  });
});

app.post('/api/execute/:id/start', authenticateToken, (req, res) => {
  const botId = req.params.id;
  if (runningBots.has(botId)) return res.status(400).json({ error: 'Already running' });
  
  db.get('SELECT * FROM bots WHERE id = ? AND user_id = ?', [botId, req.user.userId], (err, bot) => {
    if (err || !bot) return res.status(404).json({ error: 'Bot not found' });
    
    const userDir = path.join(__dirname, 'uploads', req.user.userId.toString());
    let botFile, workingDir;
    
    if (bot.is_zip && bot.extracted_path) {
      workingDir = bot.extracted_path;
      botFile = path.join(workingDir, bot.main_file || 'index.js');
      if (!fs.existsSync(botFile)) {
        const files = fs.readdirSync(workingDir);
        const anyFile = files.find(f => !f.startsWith('.'));
        if (!anyFile) return res.status(400).json({ error: 'No files found in ZIP' });
        botFile = path.join(workingDir, anyFile);
      }
    } else {
      workingDir = userDir;
      botFile = path.join(userDir, bot.filename);
    }
    
    const port = 3000 + Math.floor(Math.random() * 1000);
    let childProcess;
    const env = { ...process.env, PORT: port, BOT_ID: botId };
    
    let runtime = bot.runtime;
    if (!runtime || runtime === 'auto') {
      if (botFile.endsWith('.py')) runtime = 'python3';
      else if (botFile.endsWith('.js')) runtime = 'nodejs';
    }
    
    if (runtime.includes('node')) {
      childProcess = spawn('node', [botFile], { cwd: workingDir, env });
    } else if (runtime.includes('python')) {
      childProcess = spawn('python3', [botFile], { cwd: workingDir, env });
    } else {
      childProcess = spawn('sh', [botFile], { cwd: workingDir, env });
    }
    
    runningBots.set(botId, { process: childProcess, port, startTime: new Date() });
    db.run('UPDATE bots SET status = ?, port = ?, pid = ? WHERE id = ?', ['running', port, childProcess.pid, botId]);
    
    childProcess.stdout.on('data', (data) => {
      db.run('INSERT INTO logs (bot_id, message, type) VALUES (?, ?, ?)', [botId, data.toString().trim(), 'info']);
    });
    
    childProcess.stderr.on('data', (data) => {
      db.run('INSERT INTO logs (bot_id, message, type) VALUES (?, ?, ?)', [botId, data.toString().trim(), 'error']);
    });
    
    childProcess.on('close', (code) => {
      runningBots.delete(botId);
      db.run('UPDATE bots SET status = ?, pid = NULL WHERE id = ?', ['stopped', botId]);
      db.run('INSERT INTO logs (bot_id, message, type) VALUES (?, ?, ?)', [botId, `Stopped with code ${code}`, 'info']);
    });
    
    res.json({ message: `Bot started: ${path.basename(botFile)}`, port, pid: childProcess.pid });
  });
});

app.post('/api/execute/:id/stop', authenticateToken, (req, res) => {
  const botProcess = runningBots.get(req.params.id);
  if (!botProcess) return res.status(400).json({ error: 'Not running' });
  botProcess.process.kill();
  runningBots.delete(req.params.id);
  db.run('UPDATE bots SET status = ?, port = NULL, pid = NULL WHERE id = ?', ['stopped', req.params.id]);
  res.json({ message: 'Bot stopped' });
});

// ========== SYSTEM STATS ENDPOINT (NEW) ==========
app.get('/api/stats', authenticateToken, (req, res) => {
  // Get system information
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  
  // Get load average (1, 5, 15 minutes)
  const loadAvg = os.loadavg();
  
  // Calculate CPU percentage approximation
  const cpuCount = os.cpus().length;
  const cpuPercent = Math.min(Math.round((loadAvg[0] / cpuCount) * 100), 100);
  
  // Get disk info (approximation since we can't easily get real disk stats)
  // In production, you'd use a module like 'diskusage'
  const diskUsed = 1200 + Math.floor(Math.random() * 500); // Simulated for now
  const diskTotal = 5120;
  
  // Network stats (simulated since Node.js doesn't track this natively)
  // In production, you'd read from /proc/net/dev on Linux
  const netIn = Math.floor(Math.random() * 100) + 20;
  const netOut = Math.floor(Math.random() * 80) + 10;
  
  res.json({
    uptime: os.uptime(),
    cpu: cpuPercent,
    memory: {
      used: Math.round(usedMem / 1024 / 1024),
      total: Math.round(totalMem / 1024 / 1024),
      percent: Math.round((usedMem / totalMem) * 100)
    },
    disk: {
      used: diskUsed,
      total: diskTotal,
      percent: Math.round((diskUsed / diskTotal) * 100)
    },
    network: {
      in: netIn,
      out: netOut
    },
    platform: os.platform(),
    hostname: os.hostname()
  });
});

app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
  console.log(`🚀 BotHost running on port ${PORT}`);
});
