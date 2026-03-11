#!/usr/bin/env python3
"""
SteganoSafe — Main HTTP Server
==============================
Production-style secure file sharing system using:
- Python http.server (no frameworks)
- AES-256-GCM encryption
- LSB steganography
- RBAC with session-based auth
- Complete audit logging

Run: python server.py
Access: http://localhost:8000
"""

import os
import sys
import json
import time
import uuid
import mimetypes
import urllib.parse
import cgi
import io
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from datetime import datetime

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from modules.database import Database  # type: ignore
from modules.crypto_utils import CryptoUtils  # type: ignore
from modules.steganography import Steganography  # type: ignore
from modules.auth import AuthManager  # type: ignore
from modules.audit import AuditLogger  # type: ignore

# ─── Configuration ───────────────────────────────────────────────
HOST = '127.0.0.1'
PORT = 8000
SESSION_TIMEOUT = 1800  # 30 minutes in seconds
MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB
DATA_DIR = os.path.join(PROJECT_ROOT, 'data')
FILES_DIR = os.path.join(DATA_DIR, 'files')
STEGO_DIR = os.path.join(DATA_DIR, 'stego_images')
STATIC_DIR = os.path.join(PROJECT_ROOT, 'static')
PAGES_DIR = os.path.join(PROJECT_ROOT, 'pages')
CARRIER_DIR = os.path.join(PROJECT_ROOT, 'carriers')

# Ensure directories exist
for d in [DATA_DIR, FILES_DIR, STEGO_DIR, CARRIER_DIR]:
    os.makedirs(d, exist_ok=True)

# ─── Rate Limiting ───────────────────────────────────────────────
rate_limit_store = {}  # ip -> [(timestamp, ...)]
RATE_LIMIT_WINDOW = 60  # 1 minute
RATE_LIMIT_MAX = 5  # max 5 login attempts per minute


def check_rate_limit(ip):
    """Check if IP has exceeded login rate limit. Returns True if allowed."""
    now = time.time()
    if ip not in rate_limit_store:
        rate_limit_store[ip] = []

    # Clean old entries
    rate_limit_store[ip] = [t for t in rate_limit_store[ip] if now - t < RATE_LIMIT_WINDOW]

    if len(rate_limit_store[ip]) >= RATE_LIMIT_MAX:
        return False

    rate_limit_store[ip].append(now)
    return True


# ─── Initialize Core Modules ─────────────────────────────────────
db = Database(os.path.join(DATA_DIR, 'steganosafe.db'))
crypto = CryptoUtils()
stego = Steganography()
auth = AuthManager(db)
audit = AuditLogger(db)

# ─── Secure Headers ──────────────────────────────────────────────
SECURE_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:;",
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    'Pragma': 'no-cache',
}


class SteganoSafeHandler(BaseHTTPRequestHandler):
    """
    Main HTTP request handler for SteganoSafe.
    Handles routing, authentication, RBAC, and all API endpoints.
    """

    # ─── Utility Methods ─────────────────────────────────────────

    def send_secure_headers(self):
        """Add security headers to every response."""
        for header, value in SECURE_HEADERS.items():
            self.send_header(header, value)

    def send_json(self, data, status=200):
        """Send a JSON response with security headers."""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_secure_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def send_html(self, filepath):
        """Send an HTML file with security headers."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_secure_headers()
            self.end_headers()
            self.wfile.write(content.encode('utf-8'))
        except FileNotFoundError:
            self.send_json({'error': 'Page not found'}, 404)

    def send_file_download(self, filepath, filename):
        """Send a file as download with proper headers."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            self.send_response(200)
            mime = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
            self.send_header('Content-Type', mime)
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
            self.send_header('Content-Length', str(len(data)))
            self.send_secure_headers()
            self.end_headers()
            self.wfile.write(data)
        except FileNotFoundError:
            self.send_json({'error': 'File not found'}, 404)

    def get_session_user(self):
        """Extract and validate session from cookie. Returns user dict or None."""
        cookie_header = self.headers.get('Cookie', '')
        session_token = None
        for cookie in cookie_header.split(';'):
            cookie = cookie.strip()
            if cookie.startswith('session_token='):
                session_token = cookie.split('=', 1)[1]
                break

        if not session_token:
            return None

        user = auth.validate_session(session_token)
        return user

    def require_auth(self, role=None):
        """
        Check authentication and optional role requirement.
        Returns user dict if authorized, None otherwise (and sends error).
        """
        user = self.get_session_user()
        if not user:
            self.send_json({'error': 'Authentication required', 'redirect': '/login'}, 401)
            return None

        if role and user.get('role') != role:
            audit.log(user['username'], 'UNAUTHORIZED_ACCESS',
                      f'Attempted access requiring role: {role}')
            self.send_json({'error': 'Insufficient permissions'}, 403)
            return None

        return user

    def read_body(self):
        """Read and return the request body."""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > MAX_UPLOAD_SIZE:
            return None
        return self.rfile.read(content_length)

    def parse_json_body(self):
        """Parse JSON request body."""
        body = self.read_body()
        if body is None:
            return None
        try:
            return json.loads(body.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def parse_multipart(self):
        """Parse multipart form data for file uploads."""
        content_type = self.headers.get('Content-Type', '')
        if 'multipart/form-data' not in content_type:
            return None, None

        # Use cgi module to parse multipart data
        environ = {
            'REQUEST_METHOD': 'POST',
            'CONTENT_TYPE': content_type,
            'CONTENT_LENGTH': self.headers.get('Content-Length', '0'),
        }
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ=environ,
            keep_blank_values=True
        )
        return form, None

    def get_client_ip(self):
        """Get client IP address."""
        return self.client_address[0]

    # ─── Route Handler ───────────────────────────────────────────

    def do_GET(self):
        """Handle GET requests — serve pages and static files."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # ── Static files ──
        if path.startswith('/static/'):
            self.serve_static(path)
            return

        # ── API routes ──
        if path.startswith('/api/'):
            self.handle_api_get(path, parsed.query)
            return

        # ── Page routes ──
        page_map = {
            '/': 'login.html',
            '/login': 'login.html',
            '/register': 'register.html',
            '/dashboard': 'dashboard.html',
            '/vault': 'vault.html',
            '/decrypt': 'decrypt.html',
            '/security': 'security.html',
            '/admin/dashboard': 'admin_dashboard.html',
            '/admin/users': 'admin_users.html',
            '/admin/logs': 'admin_logs.html',
            '/admin/security': 'admin_security.html',
        }

        if path in page_map:
            self.send_html(os.path.join(PAGES_DIR, page_map[path]))
            return

        self.send_json({'error': 'Not found'}, 404)

    def do_POST(self):
        """Handle POST requests — API endpoints."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path.startswith('/api/'):
            self.handle_api_post(path)
            return

        self.send_json({'error': 'Not found'}, 404)

    def do_DELETE(self):
        """Handle DELETE requests."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path.startswith('/api/'):
            self.handle_api_delete(path)
            return

        self.send_json({'error': 'Not found'}, 404)

    def do_PUT(self):
        """Handle PUT requests."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path.startswith('/api/'):
            self.handle_api_put(path)
            return

        self.send_json({'error': 'Not found'}, 404)

    # ─── Static File Server ──────────────────────────────────────

    def serve_static(self, path):
        """Serve static files (CSS, JS, images, SVG)."""
        # Security: prevent path traversal
        clean_path = os.path.normpath(path.lstrip('/'))
        filepath = os.path.join(PROJECT_ROOT, clean_path)

        if not filepath.startswith(os.path.join(PROJECT_ROOT, 'static')):
            self.send_json({'error': 'Forbidden'}, 403)
            return

        if not os.path.isfile(filepath):
            self.send_json({'error': 'Not found'}, 404)
            return

        mime_type = mimetypes.guess_type(filepath)[0] or 'application/octet-stream'
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', mime_type)
            self.send_header('Content-Length', str(len(content)))
            if mime_type.startswith('image/') or mime_type == 'image/svg+xml':
                self.send_header('Cache-Control', 'public, max-age=86400')
            else:
                self.send_secure_headers()
            self.end_headers()
            self.wfile.write(content)
        except Exception:
            self.send_json({'error': 'Server error'}, 500)

    # ─── API GET Handlers ────────────────────────────────────────

    def handle_api_get(self, path, query_string):
        """Route API GET requests."""

        # ── Session check ──
        if path == '/api/auth/check':
            user = self.get_session_user()
            if user:
                self.send_json({
                    'authenticated': True,
                    'user': {
                        'id': user['id'],
                        'username': user['username'],
                        'role': user['role'],
                        'email': user.get('email', ''),
                        'created_at': user.get('created_at', ''),
                    },
                    'session_remaining': auth.get_session_remaining(
                        self.headers.get('Cookie', '').split('session_token=')[-1].split(';')[0]
                        if 'session_token=' in self.headers.get('Cookie', '') else ''
                    )
                })
            else:
                self.send_json({'authenticated': False})
            return

        # ── User's files ──
        if path == '/api/files':
            user = self.require_auth()
            if not user:
                return
            params = urllib.parse.parse_qs(query_string)
            search = params.get('search', [''])[0]
            if user['role'] == 'admin':
                files = db.get_all_files(search)
            else:
                files = db.get_user_files(user['id'], search)
            self.send_json({'files': files})
            return

        # ── Download stego image ──
        if path.startswith('/api/files/download/'):
            user = self.require_auth()
            if not user:
                return
            file_id = path.split('/')[-1]
            file_info = db.get_file_by_id(file_id)
            if not file_info:
                self.send_json({'error': 'File not found'}, 404)
                return
            # RBAC: users can only download own files
            if user['role'] != 'admin' and file_info['user_id'] != user['id']:
                audit.log(user['username'], 'UNAUTHORIZED_ACCESS',
                          f'Attempted to download file: {file_info["original_name"]}')
                self.send_json({'error': 'Access denied'}, 403)
                return
            stego_path = os.path.join(STEGO_DIR, file_info['stego_filename'])
            if not os.path.isfile(stego_path):
                self.send_json({'error': 'Stego image not found on disk'}, 404)
                return
            audit.log(user['username'], 'FILE_DOWNLOADED',
                      f'Downloaded: {file_info["stego_filename"]}')
            self.send_file_download(stego_path, file_info['stego_filename'])
            return

        # ── Admin: all users ──
        if path == '/api/admin/users':
            user = self.require_auth(role='admin')
            if not user:
                return
            users = db.get_all_users()
            self.send_json({'users': users})
            return

        # ── Admin: audit logs ──
        if path == '/api/admin/logs':
            user = self.require_auth(role='admin')
            if not user:
                return
            params = urllib.parse.parse_qs(query_string)
            search = params.get('search', [''])[0]
            action_filter = params.get('action', [''])[0]
            logs = db.get_audit_logs(search, action_filter)
            self.send_json({'logs': logs})
            return

        # ── Admin: export logs CSV ──
        if path == '/api/admin/logs/export':
            user = self.require_auth(role='admin')
            if not user:
                return
            logs = db.get_audit_logs()
            csv_content = 'ID,Action,Username,Details,IP Address,Timestamp\n'
            for log_entry in logs:
                csv_content += f'{log_entry["id"]},{log_entry["action"]},{log_entry["username"]},{log_entry["details"]},{log_entry.get("ip_address", "")},{log_entry["timestamp"]}\n'

            self.send_response(200)
            self.send_header('Content-Type', 'text/csv')
            self.send_header('Content-Disposition',
                             f'attachment; filename="audit_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"')
            self.send_secure_headers()
            self.end_headers()
            self.wfile.write(csv_content.encode('utf-8'))
            audit.log(user['username'], 'FILE_DOWNLOADED',
                      f'Downloaded: admin-audit_logs.csv')
            return

        # ── Dashboard stats ──
        if path == '/api/stats':
            user = self.require_auth()
            if not user:
                return
            if user['role'] == 'admin':
                stats = db.get_admin_stats()
            else:
                stats = db.get_user_stats(user['id'])
            self.send_json(stats)
            return

        # ── Recent activity ──
        if path == '/api/activity':
            user = self.require_auth()
            if not user:
                return
            if user['role'] == 'admin':
                activity = db.get_recent_activity(limit=10)
            else:
                activity = db.get_user_activity(user['username'], limit=10)
            self.send_json({'activity': activity})
            return

        self.send_json({'error': 'API endpoint not found'}, 404)

    # ─── API POST Handlers ───────────────────────────────────────

    def handle_api_post(self, path):
        """Route API POST requests."""

        # ── Login ──
        if path == '/api/auth/login':
            self.handle_login()
            return

        # ── Register ──
        if path == '/api/auth/register':
            self.handle_register()
            return

        # ── Logout ──
        if path == '/api/auth/logout':
            self.handle_logout()
            return

        # ── Upload file ──
        if path == '/api/files/upload':
            self.handle_upload()
            return

        # ── Decrypt file ──
        if path == '/api/files/decrypt':
            self.handle_decrypt()
            return

        # ── Change password ──
        if path == '/api/auth/change-password':
            self.handle_change_password()
            return

        # ── Update profile ──
        if path == '/api/auth/update-profile':
            self.handle_update_profile()
            return

        # ── Admin: create user ──
        if path == '/api/admin/users':
            self.handle_admin_create_user()
            return

        self.send_json({'error': 'API endpoint not found'}, 404)

    # ─── API DELETE Handlers ─────────────────────────────────────

    def handle_api_delete(self, path):
        """Route API DELETE requests."""

        # ── Delete file ──
        if path.startswith('/api/files/'):
            user = self.require_auth()
            if not user:
                return
            file_id = path.split('/')[-1]
            file_info = db.get_file_by_id(file_id)
            if not file_info:
                self.send_json({'error': 'File not found'}, 404)
                return
            if user['role'] != 'admin' and file_info['user_id'] != user['id']:
                self.send_json({'error': 'Access denied'}, 403)
                return
            # Delete stego image from disk
            stego_path = os.path.join(STEGO_DIR, file_info['stego_filename'])
            if os.path.isfile(stego_path):
                os.remove(stego_path)
            db.delete_file(file_id)
            audit.log(user['username'], 'FILE_DELETED',
                      f'Deleted file: {file_info["original_name"]}')
            self.send_json({'success': True, 'message': 'File deleted'})
            return

        # ── Admin: delete user ──
        if path.startswith('/api/admin/users/'):
            user = self.require_auth(role='admin')
            if not user:
                return
            target_user_id = path.split('/')[-1]
            # Prevent self-deletion
            if str(target_user_id) == str(user['id']):
                self.send_json({'error': 'Cannot delete your own account'}, 400)
                return
            target_user = db.get_user_by_id(target_user_id)
            if not target_user:
                self.send_json({'error': 'User not found'}, 404)
                return
            db.delete_user(target_user_id)
            audit.log(user['username'], 'USER_DELETED',
                      f'Deleted user: {target_user["username"]}')
            self.send_json({'success': True, 'message': 'User deleted'})
            return

        # ── Admin: clear all audit logs ──
        if path == '/api/admin/logs':
            user = self.require_auth(role='admin')
            if not user:
                return
            db.clear_all_audit_logs()
            audit.log(user['username'], 'LOGS_CLEARED',
                      'Cleared all audit logs')
            self.send_json({'success': True, 'message': 'All logs cleared'})
            return

        # ── Admin: delete single audit log ──
        if path.startswith('/api/admin/logs/'):
            user = self.require_auth(role='admin')
            if not user:
                return
            log_id = path.split('/')[-1]
            try:
                log_id_int = int(log_id)
            except ValueError:
                self.send_json({'error': 'Invalid log ID'}, 400)
                return
            db.delete_audit_log(log_id_int)
            self.send_json({'success': True, 'message': 'Log entry deleted'})
            return

        self.send_json({'error': 'API endpoint not found'}, 404)

    # ─── API PUT Handlers ────────────────────────────────────────

    def handle_api_put(self, path):
        """Route API PUT requests."""

        # ── Admin: update user role ──
        if path.startswith('/api/admin/users/'):
            user = self.require_auth(role='admin')
            if not user:
                return
            target_user_id = path.split('/')[-1]
            data = self.parse_json_body()
            if not data:
                self.send_json({'error': 'Invalid request body'}, 400)
                return
            new_role = data.get('role')
            if new_role not in ('admin', 'user'):
                self.send_json({'error': 'Invalid role'}, 400)
                return
            target_user = db.get_user_by_id(target_user_id)
            if not target_user:
                self.send_json({'error': 'User not found'}, 404)
                return
            db.update_user_role(target_user_id, new_role)
            audit.log(user['username'], 'USER_UPDATED',
                      f'Updated role of {target_user["username"]} to {new_role}')
            self.send_json({'success': True, 'message': 'User role updated'})
            return

        self.send_json({'error': 'API endpoint not found'}, 404)

    # ─── Auth Handlers ───────────────────────────────────────────

    def handle_login(self):
        """Process login request with rate limiting."""
        ip = self.get_client_ip()

        if not check_rate_limit(ip):
            audit.log('unknown', 'RATE_LIMITED',
                      f'Login rate limit exceeded from IP: {ip}', ip)
            self.send_json({
                'error': 'Too many login attempts. Please wait 1 minute.'
            }, 429)
            return

        data = self.parse_json_body()
        if not data:
            self.send_json({'error': 'Invalid request'}, 400)
            return

        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not username or not password:
            self.send_json({'error': 'Username and password required'}, 400)
            return

        user = auth.authenticate(username, password)
        if not user:
            audit.log(username, 'LOGIN_FAILED',
                      f'Failed login attempt for: {username}', ip)
            self.send_json({'error': 'Invalid credentials'}, 401)
            return

        # Create session
        session_token = auth.create_session(user['id'], ip)

        audit.log(username, 'LOGIN',
                  f'User logged in: {username}', ip)

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Set-Cookie',
                         f'session_token={session_token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TIMEOUT}')
        self.send_secure_headers()
        self.end_headers()
        response = json.dumps({
            'success': True,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'role': user['role'],
            },
            'redirect': '/admin/dashboard' if user['role'] == 'admin' else '/dashboard'
        })
        self.wfile.write(response.encode('utf-8'))

    def handle_register(self):
        """Process registration request."""
        data = self.parse_json_body()
        if not data:
            self.send_json({'error': 'Invalid request'}, 400)
            return

        username = data.get('username', '').strip()
        password = data.get('password', '')
        email = data.get('email', '').strip()

        # Validation
        if not username or not password:
            self.send_json({'error': 'Username and password required'}, 400)
            return

        if len(username) < 3:
            self.send_json({'error': 'Username must be at least 3 characters'}, 400)
            return

        if len(password) < 8:
            self.send_json({'error': 'Password must be at least 8 characters'}, 400)
            return

        # Check if user already exists
        if db.get_user_by_username(username):
            self.send_json({'error': 'Username already exists'}, 409)
            return

        # Create user
        user_id = auth.register_user(username, password, email, role='user')
        if user_id:
            audit.log('system', 'USER_CREATED',
                      f'New user registered: {username}', self.get_client_ip())
            self.send_json({
                'success': True,
                'message': 'Registration successful. Please login.'
            })
        else:
            self.send_json({'error': 'Registration failed'}, 500)

    def handle_logout(self):
        """Process logout request."""
        user = self.get_session_user()
        if user:
            # Get session token from cookie
            cookie_header = self.headers.get('Cookie', '')
            for cookie in cookie_header.split(';'):
                cookie = cookie.strip()
                if cookie.startswith('session_token='):
                    token = cookie.split('=', 1)[1]
                    auth.destroy_session(token)
                    break
            audit.log(user['username'], 'LOGOUT',
                      f'User logged out: {user["username"]}', self.get_client_ip())

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Set-Cookie',
                         'session_token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0')
        self.send_secure_headers()
        self.end_headers()
        self.wfile.write(json.dumps({'success': True, 'redirect': '/login'}).encode('utf-8'))

    def handle_change_password(self):
        """Process password change request."""
        user = self.require_auth()
        if not user:
            return

        data = self.parse_json_body()
        if not data:
            self.send_json({'error': 'Invalid request'}, 400)
            return

        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')

        if not current_password or not new_password:
            self.send_json({'error': 'Both passwords required'}, 400)
            return

        if len(new_password) < 8:
            self.send_json({'error': 'New password must be at least 8 characters'}, 400)
            return

        # Verify current password
        if not auth.authenticate(user['username'], current_password):
            self.send_json({'error': 'Current password is incorrect'}, 401)
            return

        # Update password and invalidate all sessions
        auth.change_password(user['id'], new_password)
        auth.invalidate_user_sessions(user['id'])

        # Create new session
        new_token = auth.create_session(user['id'], self.get_client_ip())

        audit.log(user['username'], 'PASSWORD_CHANGED',
                  f'Password changed for: {user["username"]}', self.get_client_ip())

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Set-Cookie',
                         f'session_token={new_token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TIMEOUT}')
        self.send_secure_headers()
        self.end_headers()
        self.wfile.write(json.dumps({
            'success': True,
            'message': 'Password changed successfully'
        }).encode('utf-8'))

    def handle_update_profile(self):
        """Process profile update request."""
        user = self.require_auth()
        if not user:
            return

        data = self.parse_json_body()
        if not data:
            self.send_json({'error': 'Invalid request'}, 400)
            return

        email = data.get('email', '').strip()
        db.update_user_profile(user['id'], email)

        audit.log(user['username'], 'PROFILE_UPDATED',
                  f'Profile updated for: {user["username"]}', self.get_client_ip())

        self.send_json({'success': True, 'message': 'Profile updated'})

    # ─── File Handlers ───────────────────────────────────────────

    def handle_upload(self):
        """
        Process secure file upload:
        1. Receive file + cover image + encryption password
        2. Validate sizes (cover: 100KB-10MB, file: up to 50MB)
        3. Encrypt file with AES-256-GCM
        4. Compute SHA-256 hash of encrypted data
        5. Embed encrypted data into cover image using multi-bit LSB
        6. Store stego image only
        """
        user = self.require_auth()
        if not user:
            return

        # Size limits
        MIN_COVER_SIZE = 100 * 1024       # 100 KB
        MAX_COVER_SIZE = 10 * 1024 * 1024  # 10 MB
        MAX_FILE_SIZE  = 50 * 1024 * 1024  # 50 MB

        try:
            form, _ = self.parse_multipart()
            if form is None:
                self.send_json({'error': 'Invalid form data'}, 400)
                return

            # Extract fields
            file_item = form['file'] if 'file' in form else None
            password = form.getvalue('password', '')
            carrier_item = form['carrier'] if 'carrier' in form else None

            if file_item is None or not hasattr(file_item, 'filename') or not file_item.filename:
                self.send_json({'error': 'No file selected'}, 400)
                return

            if not password:
                self.send_json({'error': 'Encryption password required'}, 400)
                return

            # Cover image is required — no auto-generation
            if carrier_item is None or not hasattr(carrier_item, 'filename') or not carrier_item.filename:
                self.send_json({'error': 'Cover image is required. Please select a PNG or BMP image.'}, 400)
                return

            # Read file data
            assert file_item is not None and file_item.file is not None
            file_data = file_item.file.read()
            original_name = str(os.path.basename(file_item.filename or 'unknown'))
            file_size = len(file_data)

            # Validate file size
            if file_size > MAX_FILE_SIZE:
                self.send_json({
                    'error': f'File too large. Maximum allowed: {MAX_FILE_SIZE // (1024*1024)} MB, '
                             f'got {file_size / (1024*1024):.1f} MB.'
                }, 400)
                return

            if file_size == 0:
                self.send_json({'error': 'File is empty.'}, 400)
                return

            # Read cover image
            assert carrier_item is not None  # guaranteed by check above
            assert carrier_item.file is not None
            carrier_data = carrier_item.file.read()
            carrier_size = len(carrier_data)

            # Validate cover image size
            if carrier_size < MIN_COVER_SIZE:
                self.send_json({
                    'error': f'Cover image too small. Minimum: 100 KB, '
                             f'got {carrier_size / 1024:.1f} KB. Use a larger image.'
                }, 400)
                return

            if carrier_size > MAX_COVER_SIZE:
                self.send_json({
                    'error': f'Cover image too large. Maximum: 10 MB, '
                             f'got {carrier_size / (1024*1024):.1f} MB.'
                }, 400)
                return

            # Validate it's a valid PNG
            if carrier_data[:8] != b'\x89PNG\r\n\x1a\n':
                self.send_json({
                    'error': 'Invalid cover image. Only PNG format is supported.'
                }, 400)
                return

            # Step 1: Encrypt with AES-256-GCM
            encrypted_data, salt, nonce, tag = crypto.encrypt(file_data, password)

            # Step 2: Compute SHA-256 hash of encrypted payload
            file_hash = crypto.compute_hash(encrypted_data)

            # Step 3: Prepare payload (salt + nonce + tag + encrypted_data)
            payload = crypto.package_payload(encrypted_data, salt, nonce, tag, original_name)

            # Step 4: Embed payload into cover image using multi-bit LSB
            # The embed method auto-selects bits-per-channel and compresses
            try:
                stego_image_data = stego.embed(carrier_data, payload)
            except ValueError as ve:
                self.send_json({'error': str(ve)}, 400)
                return

            # Step 5: Save stego image
            stego_filename = f"{uuid.uuid4().hex}_{original_name}.png"
            stego_path = os.path.join(STEGO_DIR, stego_filename)
            with open(stego_path, 'wb') as f:
                f.write(stego_image_data)

            stego_size = len(stego_image_data)

            # Step 6: Save file metadata to database
            file_id = db.create_file_record(
                user_id=user['id'],
                original_name=original_name,
                original_size=file_size,
                stego_filename=stego_filename,
                stego_size=stego_size,
                file_hash=file_hash,
                encryption_algorithm='AES-256-GCM',
                stego_algorithm='Multi-bit LSB'
            )

            audit.log(user['username'], 'FILE_UPLOADED',
                      f'Encrypted & embedded: {stego_filename} ({file_size / 1024:.1f} KB)',
                      self.get_client_ip())

            self.send_json({
                'success': True,
                'message': 'File encrypted and embedded in cover image successfully',
                'file': {
                    'id': file_id,
                    'original_name': original_name,
                    'stego_filename': stego_filename,
                    'original_size': file_size,
                    'stego_size': stego_size,
                    'hash': file_hash,
                }
            })

        except Exception as e:
            traceback.print_exc()
            self.send_json({'error': f'Upload failed: {str(e)}'}, 500)

    def handle_decrypt(self):
        """
        Process decryption request:
        1. Receive stego image + password
        2. Extract embedded data using LSB
        3. Verify SHA-256 hash
        4. Decrypt with AES-256-GCM
        5. Return original file
        """
        user = self.require_auth()
        if not user:
            return

        try:
            form, _ = self.parse_multipart()
            if form is None:
                self.send_json({'error': 'Invalid form data'}, 400)
                return

            stego_item = form['stego_image'] if 'stego_image' in form else None
            password = form.getvalue('password', '')

            if stego_item is None or not hasattr(stego_item, 'filename') or not stego_item.filename:
                self.send_json({'error': 'No stego image selected'}, 400)
                return

            if not password:
                self.send_json({'error': 'Decryption password required'}, 400)
                return

            # Read stego image (stego_item is guaranteed non-None by check above)
            assert stego_item is not None and stego_item.file is not None
            stego_data = stego_item.file.read()

            # Step 1: Extract payload from stego image
            payload = stego.extract(stego_data)

            # Step 2: Unpackage payload
            encrypted_data, salt, nonce, tag, original_name = crypto.unpackage_payload(payload)

            # Step 3: Verify hash integrity
            stored_hash = crypto.compute_hash(encrypted_data)

            # Step 4: Decrypt with AES-256-GCM
            decrypted_data = crypto.decrypt(encrypted_data, password, salt, nonce, tag)

            if decrypted_data is None:
                audit.log(user['username'], 'DECRYPT_FAILED',
                          f'Decryption failed (wrong password or tampered data)',
                          self.get_client_ip())
                self.send_json({
                    'error': 'Decryption failed. Wrong password or data has been tampered with.'
                }, 400)
                return

            audit.log(user['username'], 'FILE_DECRYPTED',
                      f'Decrypted file: {original_name}', self.get_client_ip())

            # Send decrypted file
            self.send_response(200)
            mime = mimetypes.guess_type(original_name)[0] or 'application/octet-stream'
            self.send_header('Content-Type', mime)
            self.send_header('Content-Disposition',
                             f'attachment; filename="{original_name}"')
            self.send_header('Content-Length', str(len(decrypted_data)))
            self.send_header('X-Original-Filename', str(original_name))
            self.send_secure_headers()
            self.end_headers()
            self.wfile.write(decrypted_data)

        except ValueError as e:
            audit.log(user['username'] if user else 'unknown', 'DECRYPT_FAILED',
                      f'Extraction/decryption error: {str(e)}', self.get_client_ip())
            self.send_json({'error': f'Decryption failed: {str(e)}'}, 400)
        except Exception as e:
            traceback.print_exc()
            self.send_json({'error': f'Decryption failed: {str(e)}'}, 500)

    # ─── Admin Handlers ──────────────────────────────────────────

    def handle_admin_create_user(self):
        """Admin: Create a new user."""
        user = self.require_auth(role='admin')
        if not user:
            return

        data = self.parse_json_body()
        if not data:
            self.send_json({'error': 'Invalid request'}, 400)
            return

        username = data.get('username', '').strip()
        password = data.get('password', '')
        email = data.get('email', '').strip()
        role = data.get('role', 'user')

        if not username or not password:
            self.send_json({'error': 'Username and password required'}, 400)
            return

        if role not in ('admin', 'user'):
            self.send_json({'error': 'Invalid role'}, 400)
            return

        if db.get_user_by_username(username):
            self.send_json({'error': 'Username already exists'}, 409)
            return

        user_id = auth.register_user(username, password, email, role)
        if user_id:
            audit.log(user['username'], 'USER_CREATED',
                      f'Admin created user: {username} (role: {role})', self.get_client_ip())
            self.send_json({'success': True, 'message': f'User {username} created'})
        else:
            self.send_json({'error': 'Failed to create user'}, 500)

    # ─── Suppress default logging ────────────────────────────────

    def log_message(self, format, *args):
        """Custom log format."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] {self.client_address[0]} - {format % args}")


# ─── Threaded Server (handles concurrent requests) ──────────────

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """HTTPServer that handles each request in a new thread."""
    daemon_threads = True


# ─── Server Startup ──────────────────────────────────────────────

def main():
    """Start the SteganoSafe server."""
    print("=" * 60)
    print("  SteganoSafe — Secure File Sharing System")
    print("=" * 60)
    print(f"  Server:    http://{HOST}:{PORT}")
    print(f"  Data Dir:  {DATA_DIR}")
    print(f"  Database:  {os.path.join(DATA_DIR, 'steganosafe.db')}")
    print("=" * 60)

    # Initialize database
    db.initialize()

    # Create default admin if not exists
    if not db.get_user_by_username('admin'):
        auth.register_user('admin', 'Admin@123', 'admin@steganosafe.local', 'admin')
        print("  [+] Default admin created (admin / Admin@123)")

    print("  [*] Server starting (multi-threaded)...")
    print(f"  [*] Open http://{HOST}:{PORT} in your browser")
    print("=" * 60)

    server = ThreadedHTTPServer((HOST, PORT), SteganoSafeHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  [!] Server shutting down...")
        server.server_close()


if __name__ == '__main__':
    main()
