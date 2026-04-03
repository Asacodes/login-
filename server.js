const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = 4444;

// File to store passwords
const PASSWORDS_FILE = './passwords.json';

// Default passwords (will be created on first run)
const DEFAULT_PASSWORDS = {
    admin: 'admin123', // Change this immediately!
    users: ['user-password-1'] // Array of user passwords
};

let passwords = { ...DEFAULT_PASSWORDS };

// Load passwords from file
async function loadPasswords() {
    try {
        const data = await fs.readFile(PASSWORDS_FILE, 'utf8');
        passwords = JSON.parse(data);
        console.log('Passwords loaded from file');
    } catch (e) {
        console.log('Creating default passwords file');
        await savePasswords();
    }
}

// Save passwords to file
async function savePasswords() {
    await fs.writeFile(PASSWORDS_FILE, JSON.stringify(passwords, null, 2));
}

// Track active sessions
const activeSessions = new Map();

app.use(express.json());
app.use(express.static('public'));

app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,
        httpOnly: true,
        maxAge: 5 * 60 * 1000 // 5 minutes
    },
    name: 'sessionId'
}));


// ==================== HTML ROUTES (Clean URLs) ====================

// Route: /login serves /public/login.html
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Route: /admin serves /public/admin.html
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Route: /dashboard serves /public/dashboard.html
app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Optional: Redirect root to login
app.get('/', (req, res) => {
    res.redirect('/login');
});

// ==================== API ROUTES ====================

// Check if running (API health check)
app.get('/api/status', (req, res) => {
    res.json({ status: 'running', timestamp: new Date().toISOString() });
});

// USER LOGIN
app.post('/api/login', async (req, res) => {
    const { password } = req.body;
    const clientIp = req.ip || req.connection.remoteAddress;
    
    if (!password) {
        return res.status(400).json({ error: 'Password required' });
    }
    
    // Check if it's admin password
    const isAdmin = password === passwords.admin;
    // Check if it's a user password
    const isUser = passwords.users.includes(password);
    
    if (!isAdmin && !isUser) {
        return res.status(401).json({ error: 'Invalid password' });
    }
    
    // Generate unique session ID
    const sessionId = crypto.randomBytes(16).toString('hex');
    
    // Dual login prevention: Remove old session from same IP
    for (const [existingId, data] of activeSessions.entries()) {
        if (data.ip === clientIp) {
            activeSessions.delete(existingId);
            console.log(`Dual login prevented for IP: ${clientIp}`);
        }
    }
    
    // Store new session
    activeSessions.set(sessionId, {
        lastActivity: Date.now(),
        ip: clientIp,
        isAdmin: isAdmin
    });
    
    req.session.isAuthenticated = true;
    req.session.sessionId = sessionId;
    req.session.isAdmin = isAdmin;
    req.session.loginTime = Date.now();
    
    res.json({ 
        success: true, 
        isAdmin: isAdmin,
        message: isAdmin ? 'Logged in as admin' : 'Logged in as user'
    });
});

// CHECK AUTH STATUS
app.get('/api/check-auth', (req, res) => {
    if (!req.session.isAuthenticated || !req.session.sessionId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const activeSession = activeSessions.get(req.session.sessionId);
    
    if (!activeSession) {
        req.session.destroy();
        return res.status(401).json({ error: 'Session expired or invalid' });
    }
    
    // Update activity
    activeSession.lastActivity = Date.now();
    
    res.json({ 
        authenticated: true,
        isAdmin: req.session.isAdmin,
        timeRemaining: 5 * 60 * 1000 - (Date.now() - activeSession.lastActivity)
    });
});

// LOGOUT
app.post('/api/logout', (req, res) => {
    if (req.session.sessionId) {
        activeSessions.delete(req.session.sessionId);
    }
    req.session.destroy();
    res.json({ success: true, message: 'Logged out' });
});

// ==================== ADMIN API (Protected) ====================

// Middleware for admin-only routes
const requireAdmin = (req, res, next) => {
    if (!req.session.isAuthenticated || !req.session.isAdmin) {
        return res.status(403).json({ error: 'Admin access required' });
    }
    
    const activeSession = activeSessions.get(req.session.sessionId);
    if (activeSession) {
        activeSession.lastActivity = Date.now();
    }
    
    next();
};

// Get all passwords (admin only)
app.get('/api/admin/passwords', requireAdmin, (req, res) => {
    // Don't send actual admin password, just indicate it exists
    res.json({
        adminSet: true,
        userCount: passwords.users.length,
        users: passwords.users.map((pass, index) => ({
            id: index,
            preview: pass.substring(0, 3) + '****'
        }))
    });
});

// Add new user password (admin only)
app.post('/api/admin/passwords', requireAdmin, async (req, res) => {
    const { password } = req.body;
    
    if (!password || password.length < 4) {
        return res.status(400).json({ error: 'Password must be at least 4 characters' });
    }
    
    if (passwords.users.includes(password)) {
        return res.status(400).json({ error: 'Password already exists' });
    }
    
    passwords.users.push(password);
    await savePasswords();
    
    res.json({ success: true, message: 'Password added' });
});

// Delete user password (admin only)
app.delete('/api/admin/passwords/:id', requireAdmin, async (req, res) => {
    const id = parseInt(req.params.id);
    
    if (id < 0 || id >= passwords.users.length) {
        return res.status(404).json({ error: 'Password not found' });
    }
    
    passwords.users.splice(id, 1);
    await savePasswords();
    
    res.json({ success: true, message: 'Password deleted' });
});

// Change admin password (admin only)
app.put('/api/admin/password', requireAdmin, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    
    if (currentPassword !== passwords.admin) {
        return res.status(401).json({ error: 'Current password incorrect' });
    }
    
    if (!newPassword || newPassword.length < 6) {
        return res.status(400).json({ error: 'New password must be at least 6 characters' });
    }
    
    passwords.admin = newPassword;
    await savePasswords();
    
    res.json({ success: true, message: 'Admin password updated' });
});

// Get active sessions (admin only)
app.get('/api/admin/sessions', requireAdmin, (req, res) => {
    const sessions = [];
    for (const [id, data] of activeSessions.entries()) {
        sessions.push({
            id: id.substring(0, 8) + '...',
            ip: data.ip,
            isAdmin: data.isAdmin,
            lastActivity: new Date(data.lastActivity).toISOString(),
            timeRemaining: Math.max(0, 5 * 60 * 1000 - (Date.now() - data.lastActivity))
        });
    }
    res.json({ sessions });
});

// Force logout session (admin only)
app.delete('/api/admin/sessions/:sessionId', requireAdmin, (req, res) => {
    const fullSessionId = Array.from(activeSessions.keys()).find(
        id => id.startsWith(req.params.sessionId.replace('...', ''))
    );
    
    if (fullSessionId) {
        activeSessions.delete(fullSessionId);
        res.json({ success: true, message: 'Session terminated' });
    } else {
        res.status(404).json({ error: 'Session not found' });
    }
});

// ==================== CLEANUP ====================

// Cleanup expired sessions every minute
setInterval(() => {
    const now = Date.now();
    const timeout = 5 * 60 * 1000;
    
    for (const [sessionId, data] of activeSessions.entries()) {
        if (now - data.lastActivity > timeout) {
            activeSessions.delete(sessionId);
            console.log(`Session ${sessionId.substring(0, 8)}... expired`);
        }
    }
}, 60000);

// Initialize and start
loadPasswords().then(() => {
    app.listen(PORT, () => {
        console.log(`✅ Server running on http://localhost:${PORT}`);
        console.log(`📁 API endpoints:`);
        console.log(`   POST /api/login          - Login`);
        console.log(`   GET  /api/check-auth     - Check session`);
        console.log(`   POST /api/logout         - Logout`);
        console.log(`   GET  /api/admin/passwords  - List passwords (admin)`);
        console.log(`   POST /api/admin/passwords  - Add password (admin)`);
    });
});