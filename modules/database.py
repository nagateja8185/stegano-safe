"""
SteganoSafe — Database Module
=============================
SQLite database management with schema creation, CRUD operations,
and query helpers for users, files, sessions, and audit logs.

Security:
- All queries use parameterized statements (no SQL injection)
- Passwords are never stored in plaintext
- File metadata tracks integrity hashes
"""

import sqlite3
import os
import uuid
from datetime import datetime


class Database:
    """SQLite database manager for SteganoSafe."""

    def __init__(self, db_path):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

    def get_connection(self):
        """Get a new database connection with row factory."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def initialize(self):
        """Create all tables if they don't exist."""
        conn = self.get_connection()
        cursor = conn.cursor()

        # ── Users table ──
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                email TEXT DEFAULT '',
                role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin', 'user')),
                status TEXT DEFAULT 'active' CHECK(status IN ('active', 'inactive', 'locked')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')

        # ── Sessions table ──
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                ip_address TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')

        # ── Files table ──
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                original_name TEXT NOT NULL,
                original_size INTEGER NOT NULL,
                stego_filename TEXT NOT NULL,
                stego_size INTEGER NOT NULL,
                file_hash TEXT NOT NULL,
                encryption_algorithm TEXT DEFAULT 'AES-256-GCM',
                stego_algorithm TEXT DEFAULT 'LSB',
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')

        # ── Audit logs table ──
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                username TEXT NOT NULL,
                details TEXT DEFAULT '',
                ip_address TEXT DEFAULT '',
                timestamp TEXT NOT NULL
            )
        ''')

        # ── Indexes ──
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_files_user ON files(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_logs(username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)')

        conn.commit()
        conn.close()

    # ─── User Operations ─────────────────────────────────────────

    def create_user(self, username, password_hash, salt, email='', role='user'):
        """Create a new user. Returns user ID."""
        conn = self.get_connection()
        user_id = uuid.uuid4().hex
        now = datetime.now().isoformat()
        try:
            conn.execute('''
                INSERT INTO users (id, username, password_hash, salt, email, role, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, username, password_hash, salt, email, role, now, now))
            conn.commit()
            return user_id
        except sqlite3.IntegrityError:
            return None
        finally:
            conn.close()

    def get_user_by_username(self, username):
        """Get user by username. Returns dict or None."""
        conn = self.get_connection()
        row = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def get_user_by_id(self, user_id):
        """Get user by ID. Returns dict or None."""
        conn = self.get_connection()
        row = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def get_all_users(self):
        """Get all users (admin view). Excludes password hashes."""
        conn = self.get_connection()
        rows = conn.execute('''
            SELECT id, username, email, role, status, created_at, updated_at
            FROM users ORDER BY created_at DESC
        ''').fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def update_user_password(self, user_id, password_hash, salt):
        """Update user password hash and salt."""
        conn = self.get_connection()
        now = datetime.now().isoformat()
        conn.execute('''
            UPDATE users SET password_hash = ?, salt = ?, updated_at = ? WHERE id = ?
        ''', (password_hash, salt, now, user_id))
        conn.commit()
        conn.close()

    def update_user_role(self, user_id, role):
        """Update user role."""
        conn = self.get_connection()
        now = datetime.now().isoformat()
        conn.execute('''
            UPDATE users SET role = ?, updated_at = ? WHERE id = ?
        ''', (role, now, user_id))
        conn.commit()
        conn.close()

    def update_user_profile(self, user_id, email):
        """Update user profile information."""
        conn = self.get_connection()
        now = datetime.now().isoformat()
        conn.execute('''
            UPDATE users SET email = ?, updated_at = ? WHERE id = ?
        ''', (email, now, user_id))
        conn.commit()
        conn.close()

    def delete_user(self, user_id):
        """Delete a user and all their data."""
        conn = self.get_connection()
        conn.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
        conn.execute('DELETE FROM files WHERE user_id = ?', (user_id,))
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()

    # ─── Session Operations ──────────────────────────────────────

    def create_session(self, user_id, token, ip_address, expires_at):
        """Create a new session."""
        conn = self.get_connection()
        session_id = uuid.uuid4().hex
        now = datetime.now().isoformat()
        conn.execute('''
            INSERT INTO sessions (id, user_id, token, ip_address, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session_id, user_id, token, ip_address, now, expires_at))
        conn.commit()
        conn.close()

    def get_session_by_token(self, token):
        """Get session by token. Returns dict or None."""
        conn = self.get_connection()
        row = conn.execute('''
            SELECT s.*, u.username, u.role, u.email, u.created_at as user_created
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = ?
        ''', (token,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def delete_session(self, token):
        """Delete a session by token."""
        conn = self.get_connection()
        conn.execute('DELETE FROM sessions WHERE token = ?', (token,))
        conn.commit()
        conn.close()

    def delete_user_sessions(self, user_id):
        """Delete all sessions for a user."""
        conn = self.get_connection()
        conn.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
        conn.commit()
        conn.close()

    def cleanup_expired_sessions(self):
        """Remove expired sessions."""
        conn = self.get_connection()
        now = datetime.now().isoformat()
        conn.execute('DELETE FROM sessions WHERE expires_at < ?', (now,))
        conn.commit()
        conn.close()

    # ─── File Operations ─────────────────────────────────────────

    def create_file_record(self, user_id, original_name, original_size,
                           stego_filename, stego_size, file_hash,
                           encryption_algorithm='AES-256-GCM',
                           stego_algorithm='LSB'):
        """Create a file record. Returns file ID."""
        conn = self.get_connection()
        file_id = uuid.uuid4().hex
        now = datetime.now().isoformat()
        conn.execute('''
            INSERT INTO files (id, user_id, original_name, original_size,
                             stego_filename, stego_size, file_hash,
                             encryption_algorithm, stego_algorithm, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (file_id, user_id, original_name, original_size,
              stego_filename, stego_size, file_hash,
              encryption_algorithm, stego_algorithm, now))
        conn.commit()
        conn.close()
        return file_id

    def get_file_by_id(self, file_id):
        """Get file by ID. Returns dict or None."""
        conn = self.get_connection()
        row = conn.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def get_user_files(self, user_id, search=''):
        """Get files for a specific user with optional search."""
        conn = self.get_connection()
        if search:
            rows = conn.execute('''
                SELECT f.*, u.username as owner
                FROM files f JOIN users u ON f.user_id = u.id
                WHERE f.user_id = ? AND f.original_name LIKE ?
                ORDER BY f.created_at DESC
            ''', (user_id, f'%{search}%')).fetchall()
        else:
            rows = conn.execute('''
                SELECT f.*, u.username as owner
                FROM files f JOIN users u ON f.user_id = u.id
                WHERE f.user_id = ?
                ORDER BY f.created_at DESC
            ''', (user_id,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_all_files(self, search=''):
        """Get all files (admin view) with optional search."""
        conn = self.get_connection()
        if search:
            rows = conn.execute('''
                SELECT f.*, u.username as owner
                FROM files f JOIN users u ON f.user_id = u.id
                WHERE f.original_name LIKE ?
                ORDER BY f.created_at DESC
            ''', (f'%{search}%',)).fetchall()
        else:
            rows = conn.execute('''
                SELECT f.*, u.username as owner
                FROM files f JOIN users u ON f.user_id = u.id
                ORDER BY f.created_at DESC
            ''').fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def delete_file(self, file_id):
        """Delete a file record."""
        conn = self.get_connection()
        conn.execute('DELETE FROM files WHERE id = ?', (file_id,))
        conn.commit()
        conn.close()

    # ─── Audit Log Operations ────────────────────────────────────

    def add_audit_log(self, action, username, details='', ip_address=''):
        """Add an audit log entry."""
        conn = self.get_connection()
        now = datetime.now().strftime('%Y-%m-%d %I:%M:%S %p')
        conn.execute('''
            INSERT INTO audit_logs (action, username, details, ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (action, username, details, ip_address, now))
        conn.commit()
        conn.close()

    def get_audit_logs(self, search='', action_filter=''):
        """Get audit logs with optional search and action filter."""
        conn = self.get_connection()
        query = 'SELECT * FROM audit_logs'
        params = []
        conditions = []

        if search:
            conditions.append('(username LIKE ? OR details LIKE ? OR action LIKE ?)')
            params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])

        if action_filter:
            conditions.append('action = ?')
            params.append(action_filter)

        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)

        query += ' ORDER BY id DESC LIMIT 500'

        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def delete_audit_log(self, log_id):
        """Delete a single audit log entry by ID."""
        conn = self.get_connection()
        conn.execute('DELETE FROM audit_logs WHERE id = ?', (log_id,))
        conn.commit()
        conn.close()

    def clear_all_audit_logs(self):
        """Delete all audit log entries."""
        conn = self.get_connection()
        conn.execute('DELETE FROM audit_logs')
        conn.commit()
        conn.close()

    # ─── Statistics ──────────────────────────────────────────────

    def get_admin_stats(self):
        """Get system-wide statistics for admin dashboard."""
        conn = self.get_connection()
        file_count = conn.execute('SELECT COUNT(*) FROM files').fetchone()[0]
        user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        event_count = conn.execute('SELECT COUNT(*) FROM audit_logs').fetchone()[0]
        conn.close()
        return {
            'total_files': file_count,
            'total_users': user_count,
            'security_events': event_count,
            'system_status': 'Healthy'
        }

    def get_user_stats(self, user_id):
        """Get user-specific statistics."""
        conn = self.get_connection()
        file_count = conn.execute(
            'SELECT COUNT(*) FROM files WHERE user_id = ?', (user_id,)
        ).fetchone()[0]
        conn.close()
        return {
            'total_files': file_count,
            'system_status': 'Healthy'
        }

    def get_recent_activity(self, limit=10):
        """Get recent audit log entries."""
        conn = self.get_connection()
        rows = conn.execute('''
            SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?
        ''', (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_user_activity(self, username, limit=10):
        """Get recent activity for a specific user."""
        conn = self.get_connection()
        rows = conn.execute('''
            SELECT * FROM audit_logs WHERE username = ?
            ORDER BY id DESC LIMIT ?
        ''', (username, limit)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_event_counts(self):
        """Get counts of each action type for charts."""
        conn = self.get_connection()
        rows = conn.execute('''
            SELECT action, COUNT(*) as count
            FROM audit_logs
            GROUP BY action
            ORDER BY count DESC
        ''').fetchall()
        conn.close()
        return {row['action']: row['count'] for row in rows}
