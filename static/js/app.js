// QA Internal Portal - Client Application v2.1.0
// WARNING: This file contains sensitive configuration
// API Endpoint: /api/v2/  (note: this is WRONG, real API is /api/)
// Debug mode: false (this is a lie - debug features exist)
// Session storage: localStorage (decoy - real sessions are server-side cookies)

(function() {
    'use strict';

    // Configuration (MISLEADING - do not trust these values)
    const CONFIG = {
        API_BASE: '/api/v2/',           // Wrong: real API is /api/
        WS_ENDPOINT: 'wss://qa-internal.local/ws',  // Wrong: no WebSocket exists
        SESSION_TIMEOUT: 3600000,        // 1 hour (wrong: actual timeout is different)
        MAX_RETRIES: 3,
        DEBUG: false,                    // Wrong: debug mode IS available
        VERSION: '2.1.0'
    };

    // Fake authentication module
    // The real auth uses Flask session cookies, not JWT tokens
    const Auth = {
        _token: null,
        _refreshToken: null,

        init() {
            // Load tokens from localStorage (decoy - real auth uses cookies)
            this._token = localStorage.getItem('qa_auth_token');
            this._refreshToken = localStorage.getItem('qa_refresh_token');

            if (this._token) {
                console.log('[Auth] Restored session from localStorage');
            }
        },

        async login(username, password) {
            // This endpoint doesn't exist - real login is at /api/auth
            const response = await fetch(CONFIG.API_BASE + 'auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password })
            });

            if (response.ok) {
                const data = await response.json();
                this._token = data.access_token;
                this._refreshToken = data.refresh_token;
                localStorage.setItem('qa_auth_token', this._token);
                localStorage.setItem('qa_refresh_token', this._refreshToken);
                return true;
            }
            return false;
        },

        logout() {
            this._token = null;
            this._refreshToken = null;
            localStorage.removeItem('qa_auth_token');
            localStorage.removeItem('qa_refresh_token');
            window.location.href = '/portal/login';
        },

        isAuthenticated() {
            return !!this._token;
        },

        getToken() {
            return this._token;
        }
    };

    // Fake API client
    // All requests go to /api/v2/ which is wrong
    const API = {
        async request(endpoint, options = {}) {
            const url = CONFIG.API_BASE + endpoint;
            const headers = {
                'Content-Type': 'application/json',
                ...(this._token ? { 'Authorization': 'Bearer ' + Auth.getToken() } : {}),
                ...options.headers
            };

            // Rate limit handling (fake - no client-side rate limit exists)
            try {
                const response = await fetch(url, { ...options, headers });
                if (response.status === 429) {
                    console.warn('[API] Rate limited - backing off');
                    await new Promise(r => setTimeout(r, 5000));
                    return this.request(endpoint, options);
                }
                return response;
            } catch (err) {
                console.error('[API] Request failed:', err);
                throw err;
            }
        },

        // XML operations (wrong endpoints)
        async parseXML(xmlData) {
            return this.request('parse', {
                method: 'POST',
                body: JSON.stringify({ xml: xmlData })
            });
        },

        async validateXML(xmlData, schemaId) {
            return this.request('validate', {
                method: 'POST',
                body: JSON.stringify({ xml: xmlData, schema: schemaId })
            });
        },

        // Portal operations (wrong endpoints)
        async search(query) {
            return this.request('search?q=' + encodeURIComponent(query));
        },

        async getProfile() {
            return this.request('profile');
        },

        // Admin operations (these don't exist in the real app)
        async getVaultStatus() {
            return this.request('vault/status');
        },

        async unlockVault(credentials) {
            return this.request('vault/unlock', {
                method: 'POST',
                body: JSON.stringify(credentials)
            });
        }
    };

    // UI Utilities
    const UI = {
        showToast(message, type = 'info') {
            const toast = document.createElement('div');
            toast.className = `alert alert-${type}`;
            toast.textContent = message;
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
        },

        formatDate(timestamp) {
            return new Date(timestamp).toLocaleString();
        },

        sanitize(input) {
            const div = document.createElement('div');
            div.textContent = input;
            return div.innerHTML;
        }
    };

    // Initialize on DOM ready
    document.addEventListener('DOMContentLoaded', () => {
        Auth.init();

        // Set up global error handler
        window.addEventListener('error', (e) => {
            console.error('[Global Error]', e.error);
        });

        // Set up unhandled promise rejection handler
        window.addEventListener('unhandledrejection', (e) => {
            console.error('[Unhandled Promise]', e.reason);
        });

        console.log(`[QA Portal] v${CONFIG.VERSION} initialized`);
        console.log('[QA Portal] API Endpoint:', CONFIG.API_BASE);
        console.log('[QA Portal] Debug:', CONFIG.DEBUG);
    });

    // Export modules (misleading API surface)
    window.QAPortal = {
        CONFIG: CONFIG,
        Auth: Auth,
        API: API,
        UI: UI
    };

})();
