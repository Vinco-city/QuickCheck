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
        
        // Users table (Updated with full profile columns)
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            fullname TEXT,
            role TEXT,
            picture TEXT,
            avatar TEXT,
            status TEXT DEFAULT 'active'
        )`);

        // Requests table (Added for tracking pending signups)
        db.run(`CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            fullname TEXT,
            role TEXT,
            picture TEXT,
            avatar TEXT,
            date DATETIME DEFAULT CURRENT_TIMESTAMP
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
            image TEXT,
            category TEXT
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

// Authentication Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Access token required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token' });
        req.user = user;
        next();
    });
}

// Root Route
app.get('/', (req, res) => {
    res.json({ message: "Vinco Supermarket API is running" });
});

// Authentication Routes
app.post('/api/register', async (req, res) => {
    const { username, password, fullname, role, picture, avatar } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        // Save incoming registrations directly to pending requests queue
        db.run(
            `INSERT INTO requests (username, password, fullname, role, picture, avatar) VALUES (?, ?, ?, ?, ?, ?)`,
            [username, hashedPassword, fullname || username, role || 'cashier', picture || '', avatar || '👤'],
            function(err) {
                if (err) {
                    return res.status(400).json({ error: 'Username already exists or database error' });
                }
                res.status(201).json({ message: 'Registration request submitted successfully', id: this.lastID });
            }
        );
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

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
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

app.post('/api/products', authenticateToken, (req, res) => {
    const { name, sku, barcode, sellingPrice, costPrice, stock, status, limit, expiryDate, image, category } = req.body;
    const query = `INSERT INTO products (name, sku, barcode, sellingPrice, costPrice, stock, status, itemLimit, expiryDate, image, category) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    db.run(query, [name, sku, barcode, sellingPrice, costPrice, stock, status, limit, expiryDate, image, category || 'General'], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(201).json({ message: 'Product created', id: this.lastID });
    });
});

app.delete('/api/products/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.run(`DELETE FROM products WHERE id = ?`, [id], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: 'Product deleted', changes: this.changes });
    });
});

app.put('/api/products/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { name, sku, barcode, sellingPrice, costPrice, stock, status, limit, expiryDate, image, category } = req.body;
    
    db.run(
        `UPDATE products SET name = ?, sku = ?, barcode = ?, sellingPrice = ?, costPrice = ?, stock = ?, status = ?, itemLimit = ?, expiryDate = ?, image = ?, category = ? WHERE id = ?`,
        [name, sku, barcode, sellingPrice, costPrice, stock, status, limit, expiryDate, image, category || 'General', id],
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

// Sales API Routes
app.get('/api/sales', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM sales`, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        const parsedRows = rows.map(row => ({
            ...row,
            items: JSON.parse(row.items || '[]')
        }));
        res.json(parsedRows);
    });
});

app.post('/api/sales', authenticateToken, (req, res) => {
    const { total, items } = req.body;
    const itemsString = JSON.stringify(items || []);
    db.run(`INSERT INTO sales (total, items) VALUES (?, ?)`, [total, itemsString], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(201).json({ message: 'Sale recorded', id: this.lastID });
    });
});

// Get all users and requests (Admin protected)
app.get('/api/users', authenticateToken, (req, res) => {
    db.all(`SELECT id, username, fullname, role, picture, avatar, status FROM users`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        
        db.all(`SELECT * FROM requests`, [], (reqErr, reqRows) => {
            res.json({
                users: rows,
                requests: reqErr ? [] : reqRows
            });
        });
    });
});

// Delete an active employee account
app.delete('/api/users/:id', authenticateToken, (req, res) => {
    const userId = req.params.id;
    db.run(`DELETE FROM users WHERE id = ?`, [userId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Employee deleted successfully" });
    });
});

// Approve a registration request
app.post('/api/requests/:id/approve', authenticateToken, (req, res) => {
    const requestId = req.params.id;
    
    db.get(`SELECT * FROM requests WHERE id = ?`, [requestId], (err, request) => {
        if (err || !request) return res.status(404).json({ error: "Request not found" });

        db.run(
            `INSERT INTO users (username, password, fullname, role, picture, avatar, status) VALUES (?, ?, ?, ?, ?, ?, 'active')`,
            [request.username, request.password, request.fullname, request.role, request.picture, request.avatar],
            function(insErr) {
                if (insErr) return res.status(500).json({ error: insErr.message });

                db.run(`DELETE FROM requests WHERE id = ?`, [requestId], (delErr) => {
                    if (delErr) return res.status(500).json({ error: delErr.message });
                    res.json({ message: "User approved successfully" });
                });
            }
        );
    });
});

// Reject/Delete a registration request
app.delete('/api/requests/:id', authenticateToken, (req, res) => {
    const requestId = req.params.id;
    db.run(`DELETE FROM requests WHERE id = ?`, [requestId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Request rejected successfully" });
    });
});

// Start Server
app.listen(PORT, () => {
    console.log(`Secure backend server running on http://localhost:${PORT}`);
});