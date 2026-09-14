const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key_here';

// CORS middleware
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Rate Limiting for Security
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Database Setup
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to SQLite database.');
        
        // Users table
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )`);

        // Products table
        db.run(`CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            sku TEXT,
            barcode TEXT,
            sellingPrice REAL,
            costPrice REAL,
            stock INTEGER,
            status TEXT,
            itemLimit INTEGER,
            expiryDate TEXT,
            image TEXT
        )`);

        // Sales table
        db.run(`CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            total REAL,
            items TEXT,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
    }
});

// Root Route
app.get('/', (req, res) => {
    res.json({ message: "Vinco Supermarket API is running" });
});

// Authentication Routes
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function(err) {
            if (err) {
                return res.status(400).json({ error: 'Username already exists or database error' });
            }
            res.status(201).json({ message: 'User registered successfully', userId: this.lastID });
        });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Internal server error' });
        }
        if (!user) {
            return res.status(400).json({ error: 'Invalid username or password' });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(400).json({ error: 'Invalid username or password' });
        }

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Login successful', token });
    });
});

// Products API Routes
app.get('/api/products', (req, res) => {
    db.all(`SELECT * FROM products`, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

app.post('/api/products', (req, res) => {
    const { name, sku, barcode, sellingPrice, costPrice, stock, status, limit, expiryDate, image } = req.body;
    const query = `INSERT INTO products (name, sku, barcode, sellingPrice, costPrice, stock, status, itemLimit, expiryDate, image) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    db.run(query, [name, sku, barcode, sellingPrice, costPrice, stock, status, limit, expiryDate, image], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(201).json({ message: 'Product created', id: this.lastID });
    });
});

app.delete('/api/products/:id', (req, res) => {
    const { id } = req.params;
    db.run(`DELETE FROM products WHERE id = ?`, [id], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: 'Product deleted', changes: this.changes });
    });
});

// Sales API Routes
app.get('/api/sales', (req, res) => {
    db.all(`SELECT * FROM sales`, [], (err, rows) => {
        if (err) {
            if (err) return res.status(500).json({ error: err.message });
        }
        const parsedRows = rows.map(row => ({
            ...row,
            items: JSON.parse(row.items || '[]')
        }));
        res.json(parsedRows);
    });
});

app.post('/api/sales', (req, res) => {
    const { total, items } = req.body;
    const itemsString = JSON.stringify(items || []);
    db.run(`INSERT INTO sales (total, items) VALUES (?, ?)`, [total, itemsString], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(201).json({ message: 'Sale recorded', id: this.lastID });
    });
});

app.put('/api/products/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { name, sku, barcode, sellingPrice, costPrice, stock, status, limit, expiryDate, image, category } = req.body;
    
    db.run(
        `UPDATE products SET name = ?, sku = ?, barcode = ?, sellingPrice = ?, costPrice = ?, stock = ?, status = ?, limit = ?, expiryDate = ?, image = ?, category = ? WHERE id = ?`,
        [name, sku, barcode, sellingPrice, costPrice, stock, status, limit, expiryDate, image, category, id],
        function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Product not found' });
            }
            res.json({ message: 'Product updated successfully', id });
        }
    );
});

// Start Server
app.listen(PORT, () => {
    console.log(`Secure backend server running on http://localhost:${PORT}`);
});