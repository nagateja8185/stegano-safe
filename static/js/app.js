/**
 * SteganoSafe — Core JavaScript Utility Module
 * =============================================
 * Shared utilities for:
 * - API calls with authentication
 * - Session management & timer
 * - Toast notifications
 * - UI helpers (sidebar, modals, etc.)
 * - Route protection
 */

// ─── API Helper ──────────────────────────────────────────────────

const API = {
    /**
     * Make an authenticated API request.
     * @param {string} url - API endpoint
     * @param {object} options - fetch options
     * @returns {Promise<object>} Response data
     */
    async request(url, options = {}) {
        const defaults = {
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'same-origin',
        };

        const config = { ...defaults, ...options };
        if (options.headers) {
            config.headers = { ...defaults.headers, ...options.headers };
        }

        // Don't set Content-Type for FormData (let browser set boundary)
        if (options.body instanceof FormData) {
            delete config.headers['Content-Type'];
        }

        try {
            const response = await fetch(url, config);

            // Handle authentication errors
            if (response.status === 401) {
                const data = await response.json().catch(() => ({}));
                throw new Error(data.error || 'Authentication required');
            }

            // Handle file download
            if (response.headers.get('Content-Type')?.includes('text/csv') ||
                response.headers.get('Content-Disposition')?.includes('attachment')) {
                return response;
            }

            // If the Content-Type is not JSON this is a file download
            const contentType = response.headers.get('Content-Type') || '';
            if (!contentType.includes('application/json')) {
                return response;
            }

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || `Request failed (${response.status})`);
            }

            return data;
        } catch (error) {
            if (error.message === 'Failed to fetch') {
                throw new Error('Cannot connect to server. Is it running?');
            }
            throw error;
        }
    },

    get(url) {
        return this.request(url, { method: 'GET' });
    },

    post(url, data) {
        if (data instanceof FormData) {
            return this.request(url, { method: 'POST', body: data });
        }
        return this.request(url, { method: 'POST', body: JSON.stringify(data) });
    },

    put(url, data) {
        return this.request(url, { method: 'PUT', body: JSON.stringify(data) });
    },

    delete(url) {
        return this.request(url, { method: 'DELETE' });
    }
};


// ─── Auth & Session ──────────────────────────────────────────────

const Auth = {
    currentUser: null,
    sessionTimer: null,
    sessionRemaining: 1800,
    _redirecting: false,

    /**
     * Check current authentication status.
     * Redirects to login if not authenticated.
     * @param {string} requiredRole - Optional role requirement
     */
    async check(requiredRole = null) {
        try {
            const data = await API.get('/api/auth/check');
            if (!data || !data.authenticated) {
                if (!Auth._redirecting) {
                    Auth._redirecting = true;
                    window.location.href = '/login';
                }
                return null;
            }

            this.currentUser = data.user;
            this.sessionRemaining = data.session_remaining || 1800;

            // Check role
            if (requiredRole && this.currentUser.role !== requiredRole) {
                if (!Auth._redirecting) {
                    Auth._redirecting = true;
                    window.location.href = this.currentUser.role === 'admin'
                        ? '/admin/dashboard' : '/dashboard';
                }
                return null;
            }

            this.updateUI();
            this.startSessionTimer();
            return this.currentUser;
        } catch (e) {
            if (!Auth._redirecting) {
                Auth._redirecting = true;
                window.location.href = '/login';
            }
            return null;
        }
    },

    /** Update UI elements with user info */
    updateUI() {
        if (!this.currentUser) return;

        // Update username displays
        document.querySelectorAll('.user-name-display').forEach(el => {
            el.textContent = this.currentUser.username;
        });

        // Update role displays
        document.querySelectorAll('.user-role-display').forEach(el => {
            el.textContent = this.currentUser.role.toUpperCase();
        });

        // Update avatar
        document.querySelectorAll('.user-avatar-letter').forEach(el => {
            el.textContent = this.currentUser.username.charAt(0).toUpperCase();
        });

        // Show/hide admin elements
        const isAdmin = this.currentUser.role === 'admin';
        document.querySelectorAll('.admin-only').forEach(el => {
            el.style.display = isAdmin ? '' : 'none';
        });
        document.querySelectorAll('.user-only').forEach(el => {
            el.style.display = isAdmin ? 'none' : '';
        });

        // ── Fix Dashboard nav link based on role ──
        // On shared pages (vault, decrypt, security), the Dashboard link
        // is hardcoded to /dashboard. Fix it for admin users.
        const dashboardHref = isAdmin ? '/admin/dashboard' : '/dashboard';
        document.querySelectorAll('.nav-item').forEach(item => {
            const href = item.getAttribute('href');
            if (href === '/dashboard' || href === '/admin/dashboard') {
                item.setAttribute('href', dashboardHref);
            }
        });

        // Update access badge
        document.querySelectorAll('.access-badge').forEach(badge => {
            badge.className = `access-badge ${this.currentUser.role}`;
            const accessText = badge.querySelector('.access-text');
            if (accessText) {
                accessText.textContent =
                    `${this.currentUser.role.toUpperCase()} Access`;
            }
        });

        // ── Wire up header buttons ──
        this._setupHeaderButtons();
    },

    /** Set up notification and settings header buttons */
    _setupHeaderButtons() {
        const headerBtns = document.querySelectorAll('.header-icon-btn');
        headerBtns.forEach(btn => {
            const svg = btn.querySelector('svg');
            if (!svg) return;
            const paths = svg.innerHTML;

            // Settings gear button → navigate to security page
            if (paths.includes('circle cx="12" cy="12" r="3"') || paths.includes('19.4 15')) {
                btn.title = 'Security Settings';
                btn.onclick = () => {
                    window.location.href = '/security';
                };
            }

            // Notification bell button → show recent activity toast
            if (paths.includes('M18 8A6 6 0') || paths.includes('M13.73 21')) {
                btn.title = 'Notifications';
                btn.onclick = async () => {
                    try {
                        const { activity } = await API.get('/api/activity');
                        const count = (activity && activity.length) || 0;
                        const badge = btn.querySelector('.badge');
                        if (badge) badge.textContent = count;

                        if (count > 0) {
                            const latest = activity[0];
                            Toast.show(
                                `Latest: ${latest.action} — ${latest.details || latest.username}`,
                                'info'
                            );
                        } else {
                            Toast.show('No new notifications', 'info');
                        }
                    } catch (e) {
                        Toast.show('Could not load notifications', 'error');
                    }
                };

                // Auto-load notification count on page load
                (async () => {
                    try {
                        const { activity } = await API.get('/api/activity');
                        const badge = btn.querySelector('.badge');
                        if (badge && activity) {
                            badge.textContent = activity.length;
                        }
                    } catch (e) { /* ignore */ }
                })();
            }
        });
    },

    /** Start the session countdown timer */
    startSessionTimer() {
        if (this.sessionTimer) clearInterval(this.sessionTimer);

        this.sessionTimer = setInterval(() => {
            this.sessionRemaining--;
            const minutes = Math.floor(this.sessionRemaining / 60);
            const seconds = this.sessionRemaining % 60;
            const timerEl = document.getElementById('session-time');
            if (timerEl) {
                timerEl.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
            }

            if (this.sessionRemaining <= 0) {
                clearInterval(this.sessionTimer);
                Toast.show('Session expired. Redirecting to login...', 'error');
                if (!Auth._redirecting) {
                    Auth._redirecting = true;
                    setTimeout(() => window.location.href = '/login', 2000);
                }
            }
        }, 1000);
    },

    /** Logout */
    async logout() {
        try {
            await API.post('/api/auth/logout');
        } catch (e) { /* ignore */ }
        window.location.href = '/login';
    }
};


// ─── Toast Notifications ─────────────────────────────────────────

const Toast = {
    container: null,

    init() {
        if (!this.container) {
            this.container = document.createElement('div');
            this.container.className = 'toast-container';
            document.body.appendChild(this.container);
        }
    },

    /**
     * Show a toast notification.
     * @param {string} message - Message to display
     * @param {string} type - 'success', 'error', or 'info'
     * @param {number} duration - Auto-dismiss in ms
     */
    show(message, type = 'info', duration = 4000) {
        this.init();

        const icons = {
            success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
            error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
            info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
        };

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `${icons[type] || icons.info}<span>${message}</span>`;
        toast.addEventListener('click', () => {
            toast.style.animation = 'slideInRight 0.3s ease reverse';
            setTimeout(() => toast.remove(), 300);
        });

        this.container.appendChild(toast);

        if (duration > 0) {
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.style.animation = 'slideInRight 0.3s ease reverse';
                    setTimeout(() => toast.remove(), 300);
                }
            }, duration);
        }
    }
};


// ─── Sidebar ─────────────────────────────────────────────────────

const Sidebar = {
    init() {
        const sidebar = document.querySelector('.sidebar');
        let toggle = document.querySelector('.sidebar-toggle');

        if (toggle && sidebar) {
            // Clone the toggle to remove any inline onclick handlers
            const newToggle = toggle.cloneNode(true);
            toggle.parentNode.replaceChild(newToggle, toggle);
            toggle = newToggle;

            // Remove the inline onclick attribute (set in HTML)
            toggle.removeAttribute('onclick');

            toggle.addEventListener('click', (e) => {
                e.stopPropagation();
                sidebar.classList.toggle('collapsed');
                localStorage.setItem('sidebar-collapsed', sidebar.classList.contains('collapsed'));
            });

            // Restore state
            if (localStorage.getItem('sidebar-collapsed') === 'true') {
                sidebar.classList.add('collapsed');
            }
        }

        // Set active nav item
        const currentPath = window.location.pathname;
        document.querySelectorAll('.nav-item').forEach(item => {
            const href = item.getAttribute('href') || item.dataset.href;
            if (href === currentPath) {
                item.classList.add('active');
            }
        });

        // Logout button
        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', (e) => {
                e.preventDefault();
                Auth.logout();
            });
        }
    }
};


// ─── Modal ───────────────────────────────────────────────────────

const Modal = {
    show(id) {
        const overlay = document.getElementById(id);
        if (overlay) {
            overlay.classList.add('active');
        }
    },

    hide(id) {
        const overlay = document.getElementById(id);
        if (overlay) {
            overlay.classList.remove('active');
        }
    },

    init() {
        // Close modal on overlay click
        document.querySelectorAll('.modal-overlay').forEach(overlay => {
            overlay.addEventListener('click', (e) => {
                if (e.target === overlay) {
                    overlay.classList.remove('active');
                }
            });
        });

        // Close buttons
        document.querySelectorAll('.modal-close').forEach(btn => {
            btn.addEventListener('click', () => {
                btn.closest('.modal-overlay').classList.remove('active');
            });
        });
    }
};


// ─── Helpers ─────────────────────────────────────────────────────

/**
 * Format file size in human readable form.
 * @param {number} bytes - Size in bytes
 * @returns {string} Formatted size
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

/**
 * Format ISO date string to friendly format.
 * @param {string} isoString - ISO date string
 * @returns {string} Formatted date
 */
function formatDate(isoString) {
    if (!isoString) return '';
    try {
        const d = new Date(isoString);
        return d.toLocaleDateString('en-US', {
            month: 'numeric',
            day: 'numeric',
            year: 'numeric'
        });
    } catch {
        return isoString;
    }
}

/**
 * Format timestamp for activity display.
 * @param {string} timestamp - Timestamp string 
 * @returns {string} Formatted time
 */
function formatTime(timestamp) {
    if (!timestamp) return '';
    return timestamp;
}

/**
 * Get badge class for an action type.
 * @param {string} action - Action type
 * @returns {string} CSS class
 */
function getActionBadgeClass(action) {
    const map = {
        'LOGIN': 'badge-login',
        'LOGOUT': 'badge-logout',
        'LOGIN_FAILED': 'badge-error',
        'FILE_UPLOADED': 'badge-upload',
        'FILE_DOWNLOADED': 'badge-download',
        'FILE_DELETED': 'badge-delete',
        'FILE_DECRYPTED': 'badge-download',
        'USER_CREATED': 'badge-created',
        'USER_DELETED': 'badge-delete',
        'USER_UPDATED': 'badge-login',
        'PASSWORD_CHANGED': 'badge-password',
        'PROFILE_UPDATED': 'badge-login',
        'UNAUTHORIZED_ACCESS': 'badge-error',
        'RATE_LIMITED': 'badge-error',
        'DECRYPT_FAILED': 'badge-error',
    };
    return map[action] || 'badge-default';
}

/**
 * Password visibility toggle.
 * @param {string} inputId - Input element ID
 * @param {HTMLElement} btn - Toggle button
 */
function togglePassword(inputId, btn) {
    const input = document.getElementById(inputId);
    if (!input) return;

    const eyeOpen = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
    const eyeClosed = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';

    if (input.type === 'password') {
        input.type = 'text';
        btn.innerHTML = eyeClosed;
    } else {
        input.type = 'password';
        btn.innerHTML = eyeOpen;
    }
}


// ─── SVG Icons ───────────────────────────────────────────────────

const Icons = {
    shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
    file: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
    upload: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>',
    download: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
    search: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
    users: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
    settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
    activity: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
    key: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>',
};

// Initialize common elements when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    Sidebar.init();
    Modal.init();
    Toast.init();
});
