// auth.js - Include this in every protected HTML file

const AUTH_CONFIG = {
    checkInterval: 30 * 60 * 1000,
    warningTime: 25 * 60 * 1000,
    loginPage: '/login.html',
    apiBase: '/api'
};

class AuthManager {
    constructor(options = {}) {
        this.redirectOnAuth = options.redirectOnAuth !== false;
        this.init();
    }
    
    async init() {
        // Check if we're on login page
        const isLoginPage = window.location.pathname.includes('login');
        
        if (!isLoginPage) {
            // On protected pages: verify auth
            const isAuth = await this.verifyAuth();
            if (!isAuth) {
                this.redirectToLogin('Please login first');
                return;
            }
        } else {
            // On login page: check if already logged in
            const isAuth = await this.verifyAuth();
            if (isAuth) {
                this.redirectAfterLogin();
            }
        }
        
        // Setup periodic checks and activity tracking
        if (!isLoginPage) {
            this.startMonitoring();
        }
    }
    
    async verifyAuth() {
        try {
            const response = await fetch(`${AUTH_CONFIG.apiBase}/check-auth`, {
                credentials: 'include'
            });
            return response.ok;
        } catch (e) {
            return false;
        }
    }
    
    startMonitoring() {
        // Periodic auth check
        this.checkInterval = setInterval(() => this.checkAuth(), AUTH_CONFIG.checkInterval);
        
        // Activity tracking to keep session alive
        this.setupActivityListeners();
    }
    
    setupActivityListeners() {
        const events = ['click', 'keypress', 'scroll', 'mousemove'];
        let debounceTimer;
        
        const resetActivity = () => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => this.pingServer(), 500);
        };
        
        events.forEach(event => {
            document.addEventListener(event, resetActivity, true);
        });
    }
    
    async pingServer() {
        try {
            await fetch(`${AUTH_CONFIG.apiBase}/check-auth`, { credentials: 'include' });
        } catch (e) {}
    }
    
    async checkAuth() {
        try {
            const response = await fetch(`${AUTH_CONFIG.apiBase}/check-auth`, {
                credentials: 'include'
            });
            
            if (!response.ok) {
                this.handleLogout('Session expired');
                return;
            }
            
            const data = await response.json();
            
            if (data.timeRemaining < AUTH_CONFIG.warningTime) {
                this.showTimeoutWarning(data.timeRemaining);
            }
            
        } catch (error) {
            console.error('Auth check failed:', error);
        }
    }
    
    showTimeoutWarning(timeRemaining) {
        if (document.getElementById('auth-warning')) return;
        
        const seconds = Math.ceil(timeRemaining / 1000);
        const modal = document.createElement('div');
        modal.id = 'auth-warning';
        modal.innerHTML = `
            <div style="
                position: fixed; top: 0; left: 0; right: 0; bottom: 0;
                background: rgba(0,0,0,0.8); z-index: 9999;
                display: flex; align-items: center; justify-content: center;
            ">
                <div style="
                    background: white; padding: 30px; border-radius: 10px;
                    text-align: center; max-width: 400px;
                ">
                    <h3>⏰ Session Expiring!</h3>
                    <p>Session expires in ${seconds} seconds</p>
                    <button onclick="authManager.extendSession()" style="
                        padding: 10px 20px; background: #28a745; color: white;
                        border: none; border-radius: 5px; cursor: pointer;
                        margin-right: 10px;
                    ">Stay Logged In</button>
                    <button onclick="authManager.logout()" style="
                        padding: 10px 20px; background: #dc3545; color: white;
                        border: none; border-radius: 5px; cursor: pointer;
                    ">Logout</button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    }
    
    async extendSession() {
        const modal = document.getElementById('auth-warning');
        if (modal) modal.remove();
        await this.pingServer();
    }
    
    async login(password) {
        try {
            const response = await fetch(`${AUTH_CONFIG.apiBase}/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                sessionStorage.setItem('isAdmin', data.isAdmin);
                return { success: true, isAdmin: data.isAdmin };
            } else {
                return { success: false, error: data.error };
            }
        } catch (error) {
            return { success: false, error: 'Network error' };
        }
    }
    
    async logout() {
        try {
            await fetch(`${AUTH_CONFIG.apiBase}/logout`, {
                method: 'POST',
                credentials: 'include'
            });
        } catch (e) {}
        this.handleLogout('Logged out');
    }
    
    handleLogout(reason) {
        clearInterval(this.checkInterval);
        sessionStorage.setItem('logoutReason', reason);
        window.location.href = AUTH_CONFIG.loginPage;
    }
    
    redirectToLogin(reason) {
        sessionStorage.setItem('logoutReason', reason);
        window.location.href = AUTH_CONFIG.loginPage;
    }
    
    redirectAfterLogin() {
        const isAdmin = sessionStorage.getItem('isAdmin') === 'true';
        window.location.href = isAdmin ? '/admin.html' : '/dashboard.html';
    }
    
    // Admin API methods
    async apiCall(endpoint, options = {}) {
        const response = await fetch(`${AUTH_CONFIG.apiBase}${endpoint}`, {
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            ...options
        });
        return response;
    }
}

// Auto-initialize
const authManager = new AuthManager();