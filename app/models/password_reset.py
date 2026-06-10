"""
Password Reset Model
====================
Secure password reset token storage.
"""
from datetime import datetime, timedelta
from ..extensions import db


class PasswordReset(db.Model):
    """Password reset token for forgot-password flow."""
    __tablename__ = 'password_resets'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token_hash = db.Column(db.String(128), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User', back_populates='password_resets')

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.expires_at is None:
            self.expires_at = datetime.utcnow() + timedelta(hours=24)

    def is_valid(self) -> bool:
        """Check if token is still valid (not expired, not used)."""
        return not self.is_used and datetime.utcnow() < self.expires_at

    def mark_used(self) -> None:
        """Mark token as consumed."""
        self.is_used = True

    def __repr__(self) -> str:
        return f'<PasswordReset user={self.user_id} valid={self.is_valid()}>'
