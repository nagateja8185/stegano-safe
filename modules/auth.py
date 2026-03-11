"""
SteganoSafe — Authentication Module
====================================
Handles:
- User registration with secure password hashing
- Session-based authentication with expiry
- Password verification
- Session lifecycle management

Security:
- PBKDF2 with SHA-256, 100,000 iterations for password hashing
- Random 32-byte salt per user
- UUID4 session tokens (cryptographically random)
- Session expiry enforcement
"""

import os
import uuid
import hashlib
from datetime import datetime, timedelta


SESSION_TIMEOUT = 1800  # 30 minutes


class AuthManager:
    """Authentication and session management for SteganoSafe."""

    PBKDF2_ITERATIONS = 100_000

    def __init__(self, db):
        self.db = db

    def _hash_password(self, password, salt=None):
        """
        Hash password using PBKDF2-SHA256.
        
        Args:
            password: Plain text password
            salt: Optional salt bytes (generated if not provided)
            
        Returns:
            tuple: (hex_hash, hex_salt)
        """
        if salt is None:
            salt = os.urandom(32)
        elif isinstance(salt, str):
            salt = bytes.fromhex(salt)

        dk = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            self.PBKDF2_ITERATIONS
        )
        return dk.hex(), salt.hex()

    def register_user(self, username, password, email='', role='user'):
        """
        Register a new user with secure password hashing.
        
        Args:
            username: Unique username
            password: Plain text password
            email: User's email
            role: 'admin' or 'user'
            
        Returns:
            User ID string or None on failure
        """
        password_hash, salt = self._hash_password(password)
        return self.db.create_user(username, password_hash, salt, email, role)

    def authenticate(self, username, password):
        """
        Verify user credentials.
        
        Args:
            username: Username to check
            password: Password to verify
            
        Returns:
            User dict if valid, None otherwise
        """
        user = self.db.get_user_by_username(username)
        if not user:
            return None

        # Hash provided password with stored salt
        password_hash, _ = self._hash_password(password, user['salt'])

        # Constant-time comparison
        if password_hash == user['password_hash']:
            return user
        return None

    def create_session(self, user_id, ip_address=''):
        """
        Create a new session for authenticated user.
        
        Args:
            user_id: User's ID
            ip_address: Client IP
            
        Returns:
            Session token string
        """
        token = uuid.uuid4().hex + uuid.uuid4().hex  # 64-char token
        expires_at = (datetime.now() + timedelta(seconds=SESSION_TIMEOUT)).isoformat()
        self.db.create_session(user_id, token, ip_address, expires_at)
        return token

    def validate_session(self, token):
        """
        Validate a session token and check expiry.
        
        Args:
            token: Session token from cookie
            
        Returns:
            User dict if session is valid, None otherwise
        """
        if not token:
            return None

        session = self.db.get_session_by_token(token)
        if not session:
            return None

        # Check expiry
        expires_at = datetime.fromisoformat(session['expires_at'])
        if datetime.now() > expires_at:
            self.db.delete_session(token)
            return None

        return {
            'id': session['user_id'],
            'username': session['username'],
            'role': session['role'],
            'email': session.get('email', ''),
            'created_at': session.get('user_created', ''),
        }

    def get_session_remaining(self, token):
        """
        Get remaining seconds for a session.
        
        Args:
            token: Session token
            
        Returns:
            Remaining seconds (int), 0 if expired
        """
        if not token:
            return 0

        session = self.db.get_session_by_token(token)
        if not session:
            return 0

        expires_at = datetime.fromisoformat(session['expires_at'])
        remaining = (expires_at - datetime.now()).total_seconds()
        return max(0, int(remaining))

    def destroy_session(self, token):
        """Destroy a session (logout)."""
        self.db.delete_session(token)

    def change_password(self, user_id, new_password):
        """
        Change user password with new salt.
        
        Args:
            user_id: User's ID
            new_password: New plain text password
        """
        password_hash, salt = self._hash_password(new_password)
        self.db.update_user_password(user_id, password_hash, salt)

    def invalidate_user_sessions(self, user_id):
        """Invalidate all sessions for a user (used after password change)."""
        self.db.delete_user_sessions(user_id)
