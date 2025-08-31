import 'dotenv/config';
import express from 'express';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';

// -------------------- Express App Setup --------------------
const app = express();
app.use(express.json());

// Middleware for debugging
app.use((req, res, next) => {
  console.log('---------- Request Start ----------');
  console.log('Timestamp:', new Date().toISOString());
  console.log('Method:', req.method);
  console.log('URL:', req.originalUrl);
  console.log('Headers:', JSON.stringify(req.headers, null, 2));
  console.log('Request Body:', JSON.stringify(req.body, null, 2));
  console.log('----------- Request End -----------');
  next();
});

// -------------------- Environment Variables --------------------
const { PORT = 3000, MCP_API_KEYS = '' } = process.env;

// -------------------- API Key Authentication --------------------
const apiKeys = new Map();
if (MCP_API_KEYS) {
  MCP_API_KEYS.split(',').forEach(pair => {
    const parts = pair.split(':');
    if (parts.length === 2) {
      const userId = parts[0].trim();
      const apiKey = parts[1].trim();
      if (userId && apiKey) apiKeys.set(apiKey, { userId });
    }
  });
}

const authenticateApiKey = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const apiKey = authHeader && authHeader.startsWith('Bearer ') && authHeader.split(' ')[1];
  if (!apiKey) return res.status(401).json({ success: false, message: 'API key is required.' });
  
  const userInfo = apiKeys.get(apiKey);
  if (!userInfo) return res.status(403).json({ success: false, message: 'Invalid API key.' });
  
  req.user = userInfo;
  next();
};

// -------------------- Database Setup --------------------
let db;

async function setupDatabase() {
  // Use an in-memory database for simplicity, or specify a file path e.g., './database.db'
  db = await open({
    filename: ':memory:',
    driver: sqlite3.Database
  });

  console.log('Connected to the in-memory SQLite database.');

  // Create a sample table and populate it with data
  await db.exec(`
    CREATE TABLE products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      category TEXT NOT NULL,
      name TEXT NOT NULL,
      price REAL NOT NULL,
      stock_quantity INTEGER NOT NULL
    );
  `);

  const products = [
    { category: 'Electronics', name: 'Laptop', price: 1200.50, stock: 35 },
    { category: 'Electronics', name: 'Smartphone', price: 800.00, stock: 150 },
    { category: 'Books', name: 'Programming Basics', price: 45.99, stock: 200 },
    { category: 'Books', name: 'Advanced Algorithms', price: 80.25, stock: 75 },
    { category: 'Office', name: 'Ergonomic Chair', price: 350.00, stock: 50 },
    { category: 'Electronics', name: 'Wireless Mouse', price: 25.50, stock: 300 }
  ];

  const stmt = await db.prepare('INSERT INTO products (category, name, price, stock_quantity) VALUES (?, ?, ?, ?)');
  for (const p of products) {
    await stmt.run(p.category, p.name, p.price, p.stock);
  }
  await stmt.finalize();

  console.log('Sample "products" table created and populated.');
}

// -------------------- API Endpoint: /aggregate --------------------
app.post('/aggregate', authenticateApiKey, async (req, res) => {
  const { sql, params = {} } = req.body;

  // --- Security Check 1: Basic validation ---
  if (!sql || typeof sql !== 'string') {
    return res.status(400).json({ success: false, message: 'SQL query string is required.' });
  }

  // --- Security Check 2: Allow only SELECT statements ---
  if (!sql.trim().toUpperCase().startsWith('SELECT')) {
    return res.status(403).json({ success: false, message: 'Only SELECT queries are allowed.' });
  }

  try {
    // --- Security Check 3: Use parameterized queries ---
    // The sqlite3 library handles parameter binding to prevent SQL injection.
    // Parameters in the query should be named (e.g., :category).
    const results = await db.all(sql, params);
    
    res.status(200).json({
      success: true,
      data: results,
      message: `Query executed successfully. Found ${results.length} rows.`
    });

  } catch (error) {
    console.error('SQL Execution Error:', error);
    res.status(500).json({
      success: false,
      data: [],
      message: `An error occurred while executing the query: ${error.message}`
    });
  }
});

// -------------------- Server Start --------------------
async function startServer() {
  try {
    await setupDatabase();
    app.listen(PORT, () => {
      console.log(`MCP SQL Aggregation API server listening on :${PORT}`);
      if (apiKeys.size > 0) {
        console.log('Loaded API keys for users:', Array.from(apiKeys.values()).map(u => u.userId).join(', '));
      } else {
        console.warn('Warning: No API keys loaded. Check your .env file.');
      }
    });
  } catch (error) {
    console.error('Failed to start the server:', error);
    process.exit(1);
  }
}

startServer();
