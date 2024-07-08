const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors({ origin: 'https://quartzib-documents-front-6d31bbce3648.herokuapp.com' })); // Replace with your frontend URL
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

  // Query to show tables immediately after connection
  db.query('SHOW TABLES', (err, results) => {
    if (err) {
      console.error('Error fetching tables:', err);
      return;
    }
    console.log('Tables in database:', results);
  });
});

// Authentication Middleware
const checkJwt = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    console.error('No token provided');
    return res.sendStatus(401);
  }

  const client = jwksRsa({
    jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`
  });

  const getKey = (header, callback) => {
    client.getSigningKey(header.kid, (err, key) => {
      if (err) {
        console.error('Error getting signing key:', err);
        return res.sendStatus(500);
      }
      const signingKey = key.publicKey || key.rsaPublicKey;
      callback(null, signingKey);
    });
  };

  jwt.verify(token, getKey, { algorithms: ['RS256'], audience: process.env.AUTH0_AUDIENCE, issuer: `https://${process.env.AUTH0_DOMAIN}/` }, (err, decoded) => {
    if (err) {
      console.error('Token verification failed:', err);
      return res.sendStatus(403);
    }
    console.log('Token verified successfully:', decoded);
    req.user = decoded;
    next();
  });
};

// Routes
app.get('/tables', checkJwt, (req, res) => {
  db.query('SHOW TABLES', (err, results) => {
    if (err) {
      console.error('Error fetching tables:', err);
      return res.status(500).send('Error fetching tables');
    }
    console.log('Tables fetched successfully:', results);
    res.send(results);
  });
});

app.get('/productions', checkJwt, (req, res) => {
  const companyId = req.user['https://quartzib-documents-front-6d31bbce3648.herokuapp.com/companyId']; // Adjust this based on your custom claim
  if (!companyId) {
    console.error('Company ID not found in token');
    return res.status(400).send('Company ID not found in token');
  }
  console.log('Company ID:', companyId);

  db.query('SELECT * FROM productions WHERE company_id = ?', [companyId], (err, results) => {
    if (err) {
      console.error('Error fetching productions:', err);
      return res.status(500).send('Error fetching productions');
    }
    console.log('Productions fetched successfully:', results);
    res.send(results);
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
