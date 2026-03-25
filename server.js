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
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    plan TEXT DEFAULT 'starter',
    telegram_bot_token TEXT,
    whatsapp_connected BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS bots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    runtime TEXT NOT NULL,
    filename TEXT NOT NULL,
    is_zip BOOLEAN DEFAULT 0,
    extracted_path TEXT,
    description TEXT,
    status TEXT DEFAULT 'stopped',
    port INTEGER,
    pid INTEGER,
    qr_code TEXT,
    pairing_method TEXT DEFAULT 'telegram',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    type TEXT DEFAULT 'info',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
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

const upload = multer({ 
  storage,
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

const runningBots = new Map();

// ========== AUTH ROUTES ==========

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  
  db.run('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', 
    [name, email, hashedPassword], 
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Email exists' });
        return res.status(500).json({ error: err.message });
      }
      const token = jwt.sign({ userId: this.lastID, email }, process.env.JWT_SECRET);
      res.json({ token, user: { id: this.lastID, name, email, plan: 'starter' } });
    }
  );
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

// ========== BOT ROUTES ==========

app.get('/api/bots', authenticateToken, (req, res) => {
  db.all('SELECT * FROM bots WHERE user_id = ? ORDER BY created_at DESC', [req.user.userId], (err, bots) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(bots);
  });
});

app.post('/api/bots', authenticateToken, upload.single('botFile'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  
  const { name, runtime, description } = req.body;
  const isZip = req.file.originalname.endsWith('.zip');
  let extractedPath = null;
  
  // If ZIP, extract it
  if (isZip) {
    try {
      const zip = new AdmZip(req.file.path);
      const extractDir = path.join(__dirname, 'uploads', req.user.userId.toString(), 'extracted', path.basename(req.file.filename, '.zip'));
      fs.ensureDirSync(extractDir);
      zip.extractAllTo(extractDir, true);
      extractedPath = extractDir;
    } catch (err) {
      return res.status(400).json({ error: 'Failed to extract ZIP: ' + err.message });
    }
  }
  
  db.run('INSERT INTO bots (user_id, name, runtime, filename, is_zip, extracted_path, description, status, pairing_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [req.user.userId, name, runtime, req.file.filename, isZip ? 1 : 0, extractedPath, description, 'stopped', 'telegram'],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ 
        id: this.lastID, 
        name, 
        runtime, 
        filename: req.file.filename, 
        is_zip: isZip ? 1 : 0,
        description, 
        status: 'stopped',
        pairing_method: 'telegram'
      });
    }
  );
});

app.get('/api/bots/:id/logs', authenticateToken, (req, res) => {
  db.all('SELECT * FROM logs WHERE bot_id = ? ORDER BY created_at DESC LIMIT 100', [req.params.id], (err, logs) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(logs);
  });
});

// ========== TELEGRAM PAIRING ==========

app.post('/api/bots/:id/pair-telegram', authenticateToken, (req, res) => {
  const { telegramToken } = req.body;
  
  db.run('UPDATE bots SET telegram_bot_token = ? WHERE id = ? AND user_id = ?', 
    [telegramToken, req.params.id, req.user.userId],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Telegram bot connected. Use /pair command in Telegram to connect WhatsApp.' });
    }
  );
});

// ========== EXECUTION ROUTES ==========

app.post('/api/execute/:id/start', authenticateToken, (req, res) => {
  const botId = req.params.id;
  
  if (runningBots.has(botId)) return res.status(400).json({ error: 'Already running' });
  
  db.get('SELECT * FROM bots WHERE id = ? AND user_id = ?', [botId, req.user.userId], (err, bot) => {
    if (err || !bot) return res.status(404).json({ error: 'Bot not found' });
    
    const userDir = path.join(__dirname, 'uploads', req.user.userId.toString());
    let botFile;
    let workingDir;
    
    if (bot.is_zip && bot.extracted_path) {
      // Find main file in extracted folder
      workingDir = bot.extracted_path;
      const files = fs.readdirSync(workingDir);
      botFile = files.find(f => f.endsWith('.js') || f.endsWith('.py'));
      if (!botFile) return res.status(400).json({ error: 'No .js or .py file found in ZIP' });
      botFile = path.join(workingDir, botFile);
    } else {
      workingDir = userDir;
      botFile = path.join(userDir, bot.filename);
    }
    
    const port = 3000 + Math.floor(Math.random() * 1000);
    let childProcess;
    const env = { 
      ...process.env, 
      PORT: port, 
      BOT_ID: botId,
      PAIRING_METHOD: 'telegram',
      TELEGRAM_BOT_TOKEN: bot.telegram_bot_token || ''
    };
    
    if (bot.runtime.includes('node')) {
      childProcess = spawn('node', [botFile], { cwd: workingDir, env });
    } else if (bot.runtime.includes('python')) {
      childProcess = spawn('python3', [botFile], { cwd: workingDir, env });
    } else {
      return res.status(400).json({ error: 'Unknown runtime' });
    }
    
    runningBots.set(botId, { process: childProcess, port, startTime: new Date() });
    
    db.run('UPDATE bots SET status = ?, port = ?, pid = ? WHERE id = ?', ['running', port, childProcess.pid, botId]);
    
    childProcess.stdout.on('data', (data) => {
      const msg = data.toString().trim();
      db.run('INSERT INTO logs (bot_id, message, type) VALUES (?, ?, ?)', [botId, msg, 'info']);
      
      // Check for QR code in output
      if (msg.includes('QR') || msg.includes('qr')) {
        db.run('UPDATE bots SET qr_code = ? WHERE id = ?', [msg, botId]);
      }
    });
    
    childProcess.stderr.on('data', (data) => {
      db.run('INSERT INTO logs (bot_id, message, type) VALUES (?, ?, ?)', [botId, data.toString().trim(), 'error']);
    });
    
    childProcess.on('close', (code) => {
      runningBots.delete(botId);
      db.run('UPDATE bots SET status = ?, pid = NULL WHERE id = ?', ['stopped', botId]);
      db.run('INSERT INTO logs (bot_id, message, type) VALUES (?, ?, ?)', [botId, `Stopped with code ${code}`, 'info']);
    });
    
    res.json({ 
      message: 'Bot started', 
      port, 
      pid: childProcess.pid,
      pairing: 'Check Telegram bot for QR code to pair WhatsApp'
    });
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

// Static files
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
  console.log(`🚀 BotHost running on port ${PORT}`);
});
