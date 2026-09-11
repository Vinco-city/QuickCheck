const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'vinco_supermarket_secret_key_2026';

app.use(cors());
// Allow local connections and bypass strict default-src restrictions
app.use((req, res, next) => {
    res.setHeader(
        "Content-Security-Policy",
        "default-src 'self' 'unsafe-inline' 'unsafe-eval' http://localhost:5000 http://127.0.0.1:5000; connect-src 'self' http://localhost:5000 http://127.0.0.1:5000;"
    );
    next();
});
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// Define rate limiter for login
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 10 login requests per windowMs
    message: { error: 'Too many login attempts from this IP, please try again after 15 minutes' }
});

// Initialize SQLite Database
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) console.error('Database opening error: ', err.message);
    else console.log('Connected to SQLite database.');
});

// Create Tables & Seed Default Admin
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT,
        avatar TEXT,
        picture TEXT,
        fullname TEXT,
        status TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT,
        avatar TEXT,
        picture TEXT,
        fullname TEXT,
        date TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY,
        barcode TEXT,
        name TEXT,
        category TEXT,
        sku TEXT,
        stock INTEGER,
        limit_val INTEGER,
        costPrice REAL,
        sellingPrice REAL,
        expiryDate TEXT,
        image TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS sales (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT,
        items TEXT,
        total REAL,
        paymentMethod TEXT
    )`);

    // Seed default admin if table is empty
    db.get(`SELECT COUNT(*) as count FROM users`, async (err, row) => {
        if (!err && row && row.count === 0) {
            const hashedAdminPassword = await bcrypt.hash('admin123', 10);
            db.run(`INSERT INTO users (username, password, role, avatar, picture, fullname, status) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                ['admin', hashedAdminPassword, 'admin', '👑', '', 'System Admin', 'active']);
            console.log('Default admin account created with hashed password.');
        }
    });
});

// JWT Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access token missing' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token' });
        req.user = user;
        next();
    });
}

// Login Endpoint
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(400).json({ error: 'Invalid username or password' });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ error: 'Invalid username or password' });

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
        res.json({ 
            success: true, 
            token, 
            user: { id: user.id, username: user.username, role: user.role, fullname: user.fullname, avatar: user.avatar, picture: user.picture } 
        });
    });
});

// Employee Self-Registration Request Endpoint
app.post('/api/auth/register', async (req, res) => {
    const { fullname, username, password, role, avatar, picture } = req.body;
    
    db.get(`SELECT username FROM users WHERE username = ? UNION SELECT username FROM requests WHERE username = ?`, [username, username], async (err, existing) => {
        if (err) return res.status(500).json({ error: err.message });
        if (existing) return res.status(400).json({ error: 'Username is already taken or pending approval.' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const date = new Date().toISOString();

        db.run(`INSERT INTO requests (username, password, role, avatar, picture, fullname, date) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [username, hashedPassword, role, avatar || '🧑‍💼', picture || '', fullname, date], function(err) {
                if (err) return res.status(500).json({ error: 'Database error saving request.' });
                res.json({ message: 'Account request submitted successfully. Pending admin approval.' });
            });
    });
});

// Update Profile Endpoint
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
    const { fullname, username, password, avatar, picture } = req.body;
    const userId = req.user.id;

    let hashedPassword = password;
    if (password && !password.startsWith('$2b$')) {
        hashedPassword = await bcrypt.hash(password, 10);
    }

    db.run(`UPDATE users SET fullname = ?, username = ?, password = ?, avatar = ?, picture = ? WHERE id = ?`,
        [fullname, username, hashedPassword, avatar, picture, userId], function(err) {
            if (err) return res.status(500).json({ error: 'Username already taken or database error.' });
            
            db.get(`SELECT id, username, role, fullname, avatar, picture FROM users WHERE id = ?`, [userId], (err, updatedUser) => {
                res.json({ message: 'Profile updated successfully', user: updatedUser });
            });
        });
});

// Approve or Reject Employee Registration Request
app.post('/api/admin/requests/:id/:action', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin' && req.user.role !== 'manager') {
        return res.status(403).json({ error: 'Unauthorized action' });
    }

    const { id, action } = req.params;

    db.get(`SELECT * FROM requests WHERE id = ?`, [id], (err, request) => {
        if (err || !request) return res.status(404).json({ error: 'Request not found' });

        if (action === 'approve') {
            db.run(`INSERT INTO users (username, password, role, avatar, picture, fullname, status) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [request.username, request.password, request.role, request.avatar, request.picture, request.fullname, 'active'], (err) => {
                    if (err) return res.status(500).json({ error: 'Failed to create user from request' });
                    db.run(`DELETE FROM requests WHERE id = ?`, [id], () => {
                        res.json({ message: 'User approved and account created successfully' });
                    });
                });
        } else {
            db.run(`DELETE FROM requests WHERE id = ?`, [id], () => {
                res.json({ message: 'Request rejected' });
            });
        }
    });
});

// Get all products
app.get('/api/products', (req, res) => {
    db.all(`SELECT * FROM products`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Add or Update Product Endpoint
app.post('/api/products', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin' && req.user.role !== 'manager' && req.user.role !== 'storekeeper') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const { id, barcode, name, category, sku, stock, limit_val, costPrice, sellingPrice, expiryDate, image } = req.body;
    
    db.get(`SELECT id FROM products WHERE id = ?`, [id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        
        if (row) {
            db.run(`UPDATE products SET barcode=?, name=?, category=?, sku=?, stock=?, limit_val=?, costPrice=?, sellingPrice=?, expiryDate=?, image=? WHERE id=?`,
                [barcode, name, category, sku, stock, limit_val, costPrice, sellingPrice, expiryDate, image, id],
                function(err) {
                    if (err) return res.status(500).json({ error: err.message });
                    res.json({ success: true, message: 'Product updated successfully' });
                }
            );
        } else {
            db.run(`INSERT INTO products (id, barcode, name, category, sku, stock, limit_val, costPrice, sellingPrice, expiryDate, image) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [id || Date.now(), barcode, name, category, sku, stock, limit_val, costPrice, sellingPrice, expiryDate, image],
                function(err) {
                    if (err) return res.status(500).json({ error: err.message });
                    res.json({ success: true, message: 'Product created successfully', id: this.lastID });
                }
            );
        }
    });
});

// Delete a product
app.delete('/api/products/:id', authenticateToken, (req, res) => {
    db.run(`DELETE FROM products WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, deletedCount: this.changes });
    });
});

// Get all sales
app.get('/api/sales', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM sales`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const parsedRows = rows.map(r => ({ ...r, items: JSON.parse(r.items || '[]') }));
        res.json(parsedRows);
    });
});

// Record a new sale
app.post('/api/sales', authenticateToken, (req, res) => {
    const { date, items, total, paymentMethod } = req.body;
    const itemsJson = JSON.stringify(items || []);

    db.run(`INSERT INTO sales (date, items, total, paymentMethod) VALUES (?, ?, ?, ?)`,
        [date || new Date().toISOString(), itemsJson, total, paymentMethod || 'Cash'],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            
            if (Array.isArray(items)) {
                items.forEach(item => {
                    db.run(`UPDATE products SET stock = stock - ? WHERE id = ?`, [item.qty, item.id]);
                });
            }

            res.json({ success: true, saleId: this.lastID, message: 'Sale completed successfully' });
        }
    );
});

// Get Database State Endpoint
app.get('/api/sync', authenticateToken, (req, res) => {
    db.all(`SELECT id, username, role, avatar, picture, fullname, status FROM users`, [], (err, users) => {
        db.all(`SELECT * FROM products`, [], (err, products) => {
            db.all(`SELECT * FROM sales`, [], (err, sales) => {
                db.all(`SELECT * FROM requests`, [], (err, requests) => {
                    const parsedSales = sales.map(r => ({ ...r, items: JSON.parse(r.items || '[]') }));
                    res.json({ users, products, sales: parsedSales, requests });
                });
            });
        });
    });
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'online', timestamp: new Date() });
});

app.get('/', (req, res) => {
    res.json({ message: 'Vinco Supermarket API is running' });
});
app.get('/.well-known/appspecific/com.chrome.devtools.json', (req, res) => {
    res.status(404).json({});
});
app.listen(PORT, () => {
    console.log(`Secure backend server running on http://localhost:${PORT}`);
});