"""
SteganoSafe — Audit Logger Module
==================================
Provides centralized audit logging for all security-sensitive actions.

Logged events:
- LOGIN / LOGOUT / LOGIN_FAILED
- FILE_UPLOADED / FILE_DOWNLOADED / FILE_DELETED / FILE_DECRYPTED
- PASSWORD_CHANGED / PROFILE_UPDATED
- USER_CREATED / USER_DELETED / USER_UPDATED
- UNAUTHORIZED_ACCESS / RATE_LIMITED
- DECRYPT_FAILED

All logs are:
- Stored permanently in SQLite
- Timestamped
- Associated with username and IP
- Exportable to CSV (admin only)
"""


class AuditLogger:
    """Centralized audit logging for SteganoSafe."""

    # Valid action types
    ACTIONS = [
        'LOGIN', 'LOGOUT', 'LOGIN_FAILED',
        'FILE_UPLOADED', 'FILE_DOWNLOADED', 'FILE_DELETED', 'FILE_DECRYPTED',
        'PASSWORD_CHANGED', 'PROFILE_UPDATED',
        'USER_CREATED', 'USER_DELETED', 'USER_UPDATED',
        'UNAUTHORIZED_ACCESS', 'RATE_LIMITED',
        'DECRYPT_FAILED',
    ]

    def __init__(self, db):
        self.db = db

    def log(self, username, action, details='', ip_address=''):
        """
        Record an audit log entry.
        
        Args:
            username: The user performing the action
            action: Action type (from ACTIONS list)
            details: Human-readable description
            ip_address: Client IP address
        """
        self.db.add_audit_log(
            action=action,
            username=username,
            details=details,
            ip_address=ip_address
        )
