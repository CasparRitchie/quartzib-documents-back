const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors({ origin: 'https://your-frontend-app.herokuapp.com' })); // Replace with your frontend URL
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
    if (err) throw err;
    res.send(results);
  });
});

app.get('/productions', checkJwt, (req, res) => {
  const companyId = req.user['https://your-app.com/companyId']; // Adjust this based on your custom claim
  console.log('Company ID:', companyId);
  db.query('SELECT * FROM productions WHERE company_id = ?', [companyId], (err, results) => {
    if (err) throw err;
    res.send(results);
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
