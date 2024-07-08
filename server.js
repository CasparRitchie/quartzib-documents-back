const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Storage } = require('@google-cloud/storage');
require('dotenv').config();

const app = express();
app.use(cors({
  origin: 'https://quartzib-documents-front-6d31bbce3648.herokuapp.com' // Replace with your actual frontend URL
}));
app.use(express.json());

// MySQL Connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect(err => {
  if (err) {
    console.error('Database connection failed:', err.stack);
    return;
  }
  console.log('Connected to database.');
});

// Google Cloud Storage
const storage = new Storage({ keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS });
const bucket = storage.bucket(process.env.BUCKET_NAME);

// Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Routes
app.post('/login', async (req, res) => {
  const { companyId, username, password } = req.body;

  db.query('SELECT * FROM users WHERE company_id = ? AND username = ?', [companyId, username], async (err, results) => {
    if (err) throw err;
    if (results.length === 0) return res.status(400).send('Invalid credentials');

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).send('Invalid credentials');

    const token = jwt.sign({ userId: user.id, companyId: user.company_id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.send({ token });
  });
});

app.get('/tables', authenticateToken, (req, res) => {
  db.query('SHOW TABLES', (err, results) => {
    if (err) throw err;
    res.send(results);
  });
});

app.get('/productions', authenticateToken, (req, res) => {
  const companyId = req.user.companyId;
  db.query('SELECT * FROM productions WHERE company_id = ?', [companyId], (err, results) => {
    if (err) throw err;
    res.send(results);
  });
});

app.get('/productions/:productionId', authenticateToken, (req, res) => {
  const { productionId } = req.params;
  const prefix = `productions/${productionId}/`;

  bucket.getFiles({ prefix }, (err, files) => {
    if (err) throw err;
    res.send(files.map(file => file.name));
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
