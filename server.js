const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || process.env.WEBSITES_PORT || 8080;

// Security middleware - Configured for Azure App Service
const isProduction = process.env.NODE_ENV === 'production';
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
    crossOriginOpenerPolicy: !isProduction ? false : { policy: "same-origin" },
    crossOriginResourcePolicy: !isProduction ? false : { policy: "same-origin" },
    crossOriginEmbedderPolicy: false,
    originAgentCluster: false,
    hsts: isProduction,
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// Stricter rate limiting for admin login
const adminLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 login attempts per windowMs
    message: 'Too many login attempts, please try again later.',
    skipSuccessfulRequests: true
});

// Body parser middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-secret-change-immediately',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // Set to true if using HTTPS
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 2 // 2 hours
    }
}));

// Serve static files
app.use(express.static('public'));

// Request logging for debugging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url} from ${req.ip}`);
    next();
});

// Handle favicon requests to prevent 404 errors
app.get('/favicon.ico', (req, res) => {
    res.status(204).end(); // No content response
});

// Database setup - Azure App Service compatible
const fs = require('fs');
const dbDir = process.env.DB_PATH ? path.dirname(process.env.DB_PATH) : './data';
const dbPath = process.env.DB_PATH || './data/tickets.db';

// Ensure database directory exists (Azure App Service)
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Database connection error:', err);
    } else {
        console.log('✅ Connected to SQLite database at:', dbPath);
    }
});

// Initialize database tables with enhanced schema
db.serialize(() => {
    // Create tickets table
    db.run(`CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        department TEXT NOT NULL,
        priority TEXT NOT NULL,
        issue_type TEXT NOT NULL,
        description TEXT NOT NULL,
        status TEXT DEFAULT 'Open',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Create enhanced admin users table
    db.run(`CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL DEFAULT 'Admin User',
        email TEXT NOT NULL DEFAULT 'admin@company.com',
        permission_level TEXT NOT NULL DEFAULT 'Ticket Staff',
        last_login DATETIME,
        is_owner INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    console.log('📊 Database tables initialized');
    console.log('💡 Run upgrade-db.js to set up enhanced user management');
});

// Authentication middleware
function requireAuth(req, res, next) {
    if (req.session && req.session.authenticated) {
        return next();
    } else {
        return res.redirect('/admin/login');
    }
}

// Admin permission middleware
function requireAdmin(req, res, next) {
    if (req.session && req.session.authenticated && req.session.permission_level === 'Admin') {
        return next();
    } else {
        return res.status(403).json({ error: 'Admin permission required' });
    }
}

// Check if user is owner
function isOwner(req, res, next) {
    if (req.session && req.session.authenticated && req.session.is_owner) {
        return next();
    } else {
        return res.status(403).json({ error: 'Owner permission required' });
    }
}

// Routes

// Home page - ticket submission form
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

// Submit ticket
app.post('/submit-ticket', (req, res) => {
    const { name, email, department, priority, issue_type, description } = req.body;
    
    // Basic validation
    if (!name || !email || !department || !priority || !issue_type || !description) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    const query = `INSERT INTO tickets (name, email, department, priority, issue_type, description) 
                   VALUES (?, ?, ?, ?, ?, ?)`;
    
    db.run(query, [name, email, department, priority, issue_type, description], function(err) {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to submit ticket' });
        }
        
        res.json({ 
            success: true, 
            message: 'Ticket submitted successfully!', 
            ticketId: this.lastID 
        });
    });
});

// Admin login page
app.get('/admin/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

// Admin login handler
app.post('/admin/login', adminLoginLimiter, (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    db.get(`SELECT * FROM admin_users WHERE username = ?`, [username], (err, user) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        bcrypt.compare(password, user.password_hash, (err, result) => {
            if (err) {
                console.error('bcrypt error:', err);
                return res.status(500).json({ error: 'Internal server error' });
            }

            if (result) {
                // Update last login
                db.run(`UPDATE admin_users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, [user.id]);
                
                // Store user info in session
                req.session.authenticated = true;
                req.session.user_id = user.id;
                req.session.username = user.username;
                req.session.full_name = user.full_name;
                req.session.email = user.email;
                req.session.permission_level = user.permission_level;
                req.session.is_owner = user.is_owner;
                
                res.json({ 
                    success: true, 
                    message: 'Login successful',
                    user: {
                        username: user.username,
                        full_name: user.full_name,
                        permission_level: user.permission_level,
                        is_owner: user.is_owner
                    }
                });
            } else {
                res.status(401).json({ error: 'Invalid credentials' });
            }
        });
    });
});

// Admin dashboard - view tickets
app.get('/admin/dashboard', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

// Get tickets API (protected)
app.get('/api/tickets', requireAuth, (req, res) => {
    const query = `SELECT * FROM tickets ORDER BY created_at DESC`;
    
    db.all(query, [], (err, rows) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to fetch tickets' });
        }
        
        res.json(rows);
    });
});

// Update ticket status (protected)
app.post('/api/tickets/:id/status', requireAuth, (req, res) => {
    const { id } = req.params;
    const { status } = req.body;
    
    const validStatuses = ['Open', 'In Progress', 'Resolved', 'Closed'];
    if (!validStatuses.includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }

    const query = `UPDATE tickets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;
    
    db.run(query, [status, id], function(err) {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to update ticket' });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Ticket not found' });
        }
        
        res.json({ success: true, message: 'Ticket status updated' });
    });
});

// Admin logout
app.post('/admin/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Session destroy error:', err);
            return res.status(500).json({ error: 'Failed to logout' });
        }
        res.json({ success: true, message: 'Logged out successfully' });
    });
});

// User Management Routes

// User management page
app.get('/admin/users', requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'users.html'));
});

// Get all users (Admin only)
app.get('/api/users', requireAdmin, (req, res) => {
    const query = `SELECT id, username, full_name, email, permission_level, last_login, is_owner, created_at 
                   FROM admin_users ORDER BY created_at DESC`;
    
    db.all(query, [], (err, rows) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to fetch users' });
        }
        
        res.json(rows);
    });
});

// Create new user (Admin only)
app.post('/api/users', requireAdmin, (req, res) => {
    const { username, password, full_name, email, permission_level } = req.body;
    
    // Validation
    if (!username || !password || !full_name || !email || !permission_level) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (!['Admin', 'Ticket Staff'].includes(permission_level)) {
        return res.status(400).json({ error: 'Invalid permission level' });
    }
    
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    // Hash password
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            console.error('bcrypt error:', err);
            return res.status(500).json({ error: 'Failed to create user' });
        }
        
        const query = `INSERT INTO admin_users (username, password_hash, full_name, email, permission_level) 
                       VALUES (?, ?, ?, ?, ?)`;
        
        db.run(query, [username, hash, full_name, email, permission_level], function(err) {
            if (err) {
                if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
                    return res.status(400).json({ error: 'Username already exists' });
                }
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Failed to create user' });
            }
            
            res.json({ 
                success: true, 
                message: 'User created successfully', 
                userId: this.lastID 
            });
        });
    });
});

// Update user (Admin only, or user updating themselves)
app.put('/api/users/:id', requireAuth, (req, res) => {
    const userId = parseInt(req.params.id);
    const { full_name, email, permission_level } = req.body;
    
    // Check permissions
    const isUpdatingSelf = req.session.user_id === userId;
    const isAdmin = req.session.permission_level === 'Admin';
    
    if (!isUpdatingSelf && !isAdmin) {
        return res.status(403).json({ error: 'Permission denied' });
    }
    
    // Get current user data
    db.get(`SELECT * FROM admin_users WHERE id = ?`, [userId], (err, user) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Prevent non-owners from modifying owner account
        if (user.is_owner && !req.session.is_owner) {
            return res.status(403).json({ error: 'Cannot modify owner account' });
        }
        
        // Only admins can change permission levels
        if (permission_level && !isAdmin) {
            return res.status(403).json({ error: 'Only admins can change permission levels' });
        }
        
        // Prevent changing owner permission level
        if (user.is_owner && permission_level && permission_level !== 'Admin') {
            return res.status(400).json({ error: 'Owner must maintain Admin permissions' });
        }
        
        // Build update query
        const updates = [];
        const values = [];
        
        if (full_name) {
            updates.push('full_name = ?');
            values.push(full_name);
        }
        
        if (email) {
            updates.push('email = ?');
            values.push(email);
        }
        
        if (permission_level && isAdmin && ['Admin', 'Ticket Staff'].includes(permission_level)) {
            updates.push('permission_level = ?');
            values.push(permission_level);
        }
        
        if (updates.length === 0) {
            return res.status(400).json({ error: 'No valid fields to update' });
        }
        
        updates.push('updated_at = CURRENT_TIMESTAMP');
        values.push(userId);
        
        const query = `UPDATE admin_users SET ${updates.join(', ')} WHERE id = ?`;
        
        db.run(query, values, function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Failed to update user' });
            }
            
            res.json({ success: true, message: 'User updated successfully' });
        });
    });
});

// Change password
app.post('/api/users/:id/password', requireAuth, (req, res) => {
    const userId = parseInt(req.params.id);
    const { current_password, new_password } = req.body;
    
    // Check permissions
    const isUpdatingSelf = req.session.user_id === userId;
    const isAdmin = req.session.permission_level === 'Admin';
    
    if (!isUpdatingSelf && !isAdmin) {
        return res.status(403).json({ error: 'Permission denied' });
    }
    
    if (!new_password || new_password.length < 6) {
        return res.status(400).json({ error: 'New password must be at least 6 characters' });
    }
    
    // Get user data
    db.get(`SELECT * FROM admin_users WHERE id = ?`, [userId], (err, user) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // If updating own password, verify current password
        if (isUpdatingSelf && !current_password) {
            return res.status(400).json({ error: 'Current password required' });
        }
        
        const updatePassword = (hash) => {
            db.run(`UPDATE admin_users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, 
                [hash, userId], function(err) {
                    if (err) {
                        console.error('Database error:', err);
                        return res.status(500).json({ error: 'Failed to update password' });
                    }
                    
                    res.json({ success: true, message: 'Password updated successfully' });
                }
            );
        };
        
        if (isUpdatingSelf) {
            // Verify current password
            bcrypt.compare(current_password, user.password_hash, (err, result) => {
                if (err) {
                    console.error('bcrypt error:', err);
                    return res.status(500).json({ error: 'Internal server error' });
                }
                
                if (!result) {
                    return res.status(401).json({ error: 'Current password is incorrect' });
                }
                
                // Hash new password
                bcrypt.hash(new_password, 10, (err, hash) => {
                    if (err) {
                        console.error('bcrypt error:', err);
                        return res.status(500).json({ error: 'Failed to update password' });
                    }
                    
                    updatePassword(hash);
                });
            });
        } else {
            // Admin resetting password - no current password verification needed
            bcrypt.hash(new_password, 10, (err, hash) => {
                if (err) {
                    console.error('bcrypt error:', err);
                    return res.status(500).json({ error: 'Failed to update password' });
                }
                
                updatePassword(hash);
            });
        }
    });
});

// Delete user (Admin only, cannot delete owner)
app.delete('/api/users/:id', requireAdmin, (req, res) => {
    const userId = parseInt(req.params.id);
    
    // Get user data
    db.get(`SELECT * FROM admin_users WHERE id = ?`, [userId], (err, user) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Cannot delete owner
        if (user.is_owner) {
            return res.status(403).json({ error: 'Cannot delete owner account' });
        }
        
        // Cannot delete yourself
        if (userId === req.session.user_id) {
            return res.status(400).json({ error: 'Cannot delete your own account' });
        }
        
        db.run(`DELETE FROM admin_users WHERE id = ?`, [userId], function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Failed to delete user' });
            }
            
            res.json({ success: true, message: 'User deleted successfully' });
        });
    });
});

// Get current user info
app.get('/api/user/me', requireAuth, (req, res) => {
    const query = `SELECT id, username, full_name, email, permission_level, last_login, is_owner, created_at 
                   FROM admin_users WHERE id = ?`;
    
    db.get(query, [req.session.user_id], (err, user) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json(user);
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Page not found' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    const os = require('os');
    const networkInterfaces = os.networkInterfaces();
    let localIPs = [];
    
    // Find all local network IPs
    for (const interfaceName in networkInterfaces) {
        const interfaces = networkInterfaces[interfaceName];
        for (const iface of interfaces) {
            if (iface.family === 'IPv4' && !iface.internal) {
                if (iface.address.startsWith('192.168.') || 
                    iface.address.startsWith('10.') || 
                    (iface.address.startsWith('172.') && 
                     parseInt(iface.address.split('.')[1]) >= 16 && 
                     parseInt(iface.address.split('.')[1]) <= 31)) {
                    localIPs.push(iface.address);
                }
            }
        }
    }
    
    // Sort IPs to prioritize 192.168.1.x range (typical home networks)
    localIPs.sort((a, b) => {
        if (a.startsWith('192.168.1.') && !b.startsWith('192.168.1.')) return -1;
        if (!a.startsWith('192.168.1.') && b.startsWith('192.168.1.')) return 1;
        return a.localeCompare(b);
    });
    
    const primaryIP = localIPs.length > 0 ? localIPs[0] : 'Unknown';
    
    console.log(`🎫 IT Ticketing System is now running!`);
    console.log(`\n📍 Access URLs:`);
    console.log(`   Local:    http://localhost:${PORT}`);
    console.log(`   Network:  http://${primaryIP}:${PORT}`);
    console.log(`\n📊 Admin Dashboard:`);
    console.log(`   Local:    http://localhost:${PORT}/admin/dashboard`);
    console.log(`   Network:  http://${primaryIP}:${PORT}/admin/dashboard`);
    
    // Show all available network IPs if there are multiple
    if (localIPs.length > 1) {
        console.log(`\n🌐 All network interfaces:`);
        localIPs.forEach(ip => {
            console.log(`   http://${ip}:${PORT}`);
        });
    }
    
    console.log(`\n🔒 Default admin credentials: admin / admin123 (CHANGE IMMEDIATELY!)`);
    console.log(`\n💡 Other devices on your network can now access the system!`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down server...');
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err);
        } else {
            console.log('✅ Database connection closed.');
        }
        process.exit(0);
    });
});