const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');
const cors = require('cors');
require('dotenv').config();

const app = express();

const allowedOrigins = [
  'https://quartzib-documents-front-6d31bbce3648.herokuapp.com',
  'http://localhost:3000'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
}));
app.use(express.json());

// Initialize dbStatus
const dbStatus = {
  connected: false,
  tables: [],
  tableData: {}
};

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
    dbStatus.connected = false;
    return;
  }
  console.log('Connected to database.');
  dbStatus.connected = true;

  // Query to show tables immediately after connection
  db.query('SHOW TABLES', (err, results) => {
    if (err) {
      console.error('Error fetching tables:', err);
      dbStatus.tables = [];
      return;
    }
    console.log('Tables in database:', results);
    dbStatus.tables = results;

    // Fetch entries from each table
    results.forEach(table => {
      const tableName = table.Tables_in_quartzib;
      db.query(`SELECT * FROM ${tableName}`, (err, entries) => {
        if (err) {
          console.error(`Error fetching entries from ${tableName}:`, err);
          dbStatus.tableData[tableName] = [];
        } else {
          console.log(`Entries in ${tableName}:`);
          // console.log(`Entries in ${tableName}:`, entries);
          dbStatus.tableData[tableName] = entries;
        }
      });
    });
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

// Status route for debugging
app.get('/status', (req, res) => {
  res.json(dbStatus);
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Example user retrieval from database
  const userQuery = 'SELECT * FROM users WHERE email = ?';
  db.query(userQuery, [email], async (err, results) => {
    if (err) {
      console.error('Database query error:', err);
      return res.status(500).send('Database error');
    }

    if (results.length === 0) {
      return res.status(401).send('Invalid credentials');
    }

    const user = results[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).send('Invalid credentials');
    }

    // Add custom claim (companyId)
    const token = jwt.sign(
      {
        sub: user.id,
        email: user.email,
        companyId: user.company_id, // Add companyId here
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token });
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
