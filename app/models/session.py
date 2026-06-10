"""
Session Model
=============
Active user sessions for secure session management.
"""
from datetime import datetime, timedelta
from ..extensions import db


class Session(db.Model):
    """User session tracking for security and concurrent session management."""
    __tablename__ = 'sessions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_token = db.Column(db.String(255), nullable=False, unique=True, index=True)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent_hash = db.Column(db.String(64), nullable=False)
    device_info = db.Column(db.String(255), nullable=True)
    browser_info = db.Column(db.String(255), nullable=True)
    location_info = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    last_activity = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User', back_populates='sessions')

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.expires_at is None:
            self.expires_at = datetime.utcnow() + timedelta(hours=24)

    def is_expired(self) -> bool:
        """Check if session has expired."""
        return datetime.utcnow() > self.expires_at

    def touch(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = datetime.utcnow()

    def deactivate(self) -> None:
        """Mark session as inactive (logout)."""
        self.is_active = False

    def __repr__(self) -> str:
        return f'<Session user={self.user_id} active={self.is_active}>'
