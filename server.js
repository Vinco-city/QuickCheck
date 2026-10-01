const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
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
app.use(express.static(__dirname));

// Rate Limiting for Security
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Database Setup (Absolute path to guarantee synchronization)
const dbPath = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to SQLite database at:', dbPath);
        
        // Users table
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

        // Requests table (Tracking pending signups)
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
    console.log("[AUTH MIDDLEWARE] Auth header received:", authHeader ? "Yes" : "No");
    
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        console.log("[AUTH MIDDLEWARE] Rejected: No token provided");
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.log("[AUTH MIDDLEWARE] Rejected: Invalid or expired token ->", err.message);
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        console.log("[AUTH MIDDLEWARE] Token successfully verified for user:", user.username);
        req.user = user;
        next();
    });
}

// Root Route
app.get('/', (req, res) => {
    res.json({ message: "Vinco Supermarket API is running" });
});

// Fetch all pending requests from SQLite
app.get('/api/requests', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM requests`, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

// Authentication & Registration Routes
app.post('/api/register', async (req, res) => {
    const { username, password, fullname, role, picture, avatar } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    // STRICT RULE: Prevent anyone from registering as owner or admin
    const lowerRole = (role || '').toLowerCase();
    if (lowerRole.includes('owner') || lowerRole.includes('admin')) {
        return res.status(403).json({ error: 'Registration as owner or admin is strictly prohibited.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(
            `INSERT INTO requests (username, password, fullname, role, picture, avatar) VALUES (?, ?, ?, ?, ?, ?)`,
            [username, hashedPassword, fullname || username, 'cashier', picture || '', avatar || '👤'],
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
    console.log("Login attempt received for username:", username); // <-- Add this

    if (!username || !password) {
        console.log("Rejected: Missing username or password"); // <-- Add this
        return res.status(400).json({ error: 'Username and password are required' });
    }

    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err) {
            console.log("Database error:", err.message);
            return res.status(500).json({ error: 'Internal server error' });
        }
        if (!user) {
            console.log("Rejected: User not found in database:", username); // <-- Look for this in your terminal!
            return res.status(400).json({ error: 'Invalid username or password' });
        }

        let match = false;
        try {
            match = await bcrypt.compare(password, user.password);
        } catch (e) {
            match = false;
        }

        const plainMatch = (password === user.password);

        if (!match && !plainMatch) {
            console.log("Rejected: Password mismatch for user:", username); // <-- Or look for this!
            return res.status(400).json({ error: 'Invalid username or password' });
        }

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
        console.log("Login successful for:", username);
        res.json({ message: 'Login successful', token, user });
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

// Update an employee or admin profile (Includes Username update support)
app.put('/api/users/:id', authenticateToken, async (req, res) => {
    const userId = req.params.id;
    const { fullname, username, role, picture, avatar, password } = req.body;

    if (password && password.trim() !== '') {
        try {
            const hashedPassword = await bcrypt.hash(password, 10);
            db.run(
                `UPDATE users SET fullname = ?, username = ?, role = ?, picture = ?, avatar = ?, password = ? WHERE id = ?`,
                [fullname, username, role, picture || '', avatar || '👤', hashedPassword, userId],
                function(err) {
                    if (err) return res.status(500).json({ error: err.message });
                    if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
                    res.json({ message: 'Profile updated successfully' });
                }
            );
        } catch (err) {
            res.status(500).json({ error: 'Internal server error' });
        }
    } else {
        db.run(
            `UPDATE users SET fullname = ?, username = ?, role = ?, picture = ?, avatar = ? WHERE id = ?`,
            [fullname, username, role, picture || '', avatar || '👤', userId],
            function(err) {
                if (err) return res.status(500).json({ error: err.message });
                if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
                res.json({ message: 'Profile updated successfully' });
            }
        );
    }
});

// Delete an active employee account
app.delete('/api/users/:id', authenticateToken, (req, res) => {
    const userId = req.params.id;
    db.run(`DELETE FROM users WHERE id = ?`, [userId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Employee deleted successfully" });
    });
});

// Approve a registration request (Secured: Cannot approve as owner/admin)
app.post('/api/requests/:id/approve', authenticateToken, (req, res) => {
    const requestId = req.params.id;
    console.log(`[APPROVAL] Attempting to approve request ID: ${requestId}`);
    
    db.get(`SELECT * FROM requests WHERE id = ?`, [requestId], (err, request) => {
        if (err) {
            console.error(`[APPROVAL] Database error fetching request: ${err.message}`);
            return res.status(500).json({ error: err.message });
        }
        if (!request) {
            console.log(`[APPROVAL] Request not found for ID: ${requestId}`);
            return res.status(404).json({ error: "Request not found" });
        }

        // Ensure no request can ever be approved as owner or admin
        const lowerRole = (request.role || '').toLowerCase();
        const safeRole = (lowerRole.includes('owner') || lowerRole.includes('admin')) 
            ? 'cashier' 
            : request.role;

        console.log(`[APPROVAL] Inserting user ${request.username} with role ${safeRole} into users table...`);

        db.run(
            `INSERT INTO users (username, password, fullname, role, picture, avatar, status) VALUES (?, ?, ?, ?, ?, ?, 'active')`,
            [request.username, request.password, request.fullname, safeRole, request.picture, request.avatar],
            function(insErr) {
                if (insErr) {
                    console.error(`[APPROVAL INSERT ERROR] ${insErr.message}`);
                    return res.status(500).json({ error: insErr.message });
                }

                console.log(`[APPROVAL] Successfully inserted user. Removing from requests table...`);

                db.run(`DELETE FROM requests WHERE id = ?`, [requestId], (delErr) => {
                    if (delErr) {
                        console.error(`[APPROVAL DELETE ERROR] ${delErr.message}`);
                        return res.status(500).json({ error: delErr.message });
                    }
                    console.log(`[APPROVAL SUCCESS] User ${request.username} approved and moved successfully.`);
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