"""
User Model
==========
Core user account with authentication, MFA, and role-based access.
"""
import hashlib
import secrets
from datetime import datetime, timedelta
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from ..extensions import db


class User(UserMixin, db.Model):
    """User account model with security features."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    email_verified = db.Column(db.Boolean, nullable=False, default=False)
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    password_changed_at = db.Column(db.DateTime, nullable=True)
    password_strength = db.Column(db.Integer, nullable=False, default=15)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    sessions = db.relationship('Session', back_populates='user',
                               lazy='dynamic', cascade='all, delete-orphan')
    trusted_devices = db.relationship('TrustedDevice', back_populates='user',
                                      lazy='dynamic', cascade='all, delete-orphan')
    risk_events = db.relationship('RiskEvent', back_populates='user',
                                  lazy='dynamic', cascade='all, delete-orphan')
    privacy_scores = db.relationship('PrivacyScore', back_populates='user',
                                     lazy='dynamic', cascade='all, delete-orphan')
    frustration_metrics = db.relationship('FrustrationMetric', back_populates='user',
                                          lazy='dynamic', cascade='all, delete-orphan')
    policy_reports = db.relationship('PolicyReport', back_populates='user',
                                     lazy='dynamic', cascade='all, delete-orphan')
    recommendations = db.relationship('Recommendation', back_populates='user',
                                      lazy='dynamic', cascade='all, delete-orphan')
    survey_responses = db.relationship('SurveyResponse', back_populates='user',
                                       lazy='dynamic', cascade='all, delete-orphan')
    sus_responses = db.relationship('SUSResponse', back_populates='user',
                                    lazy='dynamic', cascade='all, delete-orphan')
    ml_predictions = db.relationship('MLPrediction', back_populates='user',
                                     lazy='dynamic', cascade='all, delete-orphan')
    notifications = db.relationship('Notification', back_populates='user',
                                    lazy='dynamic', cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', back_populates='user',
                                 lazy='dynamic', cascade='all, delete-orphan')
    password_resets = db.relationship('PasswordReset', back_populates='user',
                                      lazy='dynamic', cascade='all, delete-orphan')
    email_verifications = db.relationship('EmailVerification', back_populates='user',
                                          lazy='dynamic', cascade='all, delete-orphan')
    website_permissions = db.relationship('WebsitePermission', back_populates='user',
                                          lazy='dynamic', cascade='all, delete-orphan')

    def set_password(self, password: str) -> None:
        """Hash and store password using Werkzeug."""
        self.password_hash = generate_password_hash(password)
        self.password_changed_at = datetime.utcnow()
        # Calculate password strength and store it
        from ..services.auth_service import get_password_strength
        strength_info = get_password_strength(password)
        self.password_strength = int(strength_info['score'] / 6 * 25)

    def check_password(self, password: str) -> bool:
        """Verify password against stored hash."""
        return check_password_hash(self.password_hash, password)

    def is_account_locked(self) -> bool:
        """Check if account is temporarily locked due to failed logins."""
        if self.failed_login_count < 5:
            return False
        if self.last_failed_login is None:
            return False
        lockout_until = self.last_failed_login + timedelta(minutes=15)
        return datetime.utcnow() < lockout_until

    def record_failed_login(self) -> None:
        """Increment failed login counter."""
        self.failed_login_count += 1
        self.last_failed_login = datetime.utcnow()

    def reset_failed_logins(self) -> None:
        """Clear failed login counter on successful login."""
        self.failed_login_count = 0
        self.last_failed_login = None

    def get_id(self) -> str:
        """Return user ID for Flask-Login."""
        return str(self.id)

    @property
    def is_admin(self) -> bool:
        """Check if user has admin role."""
        return self.role == 'admin'

    def generate_email_token(self) -> str:
        """Generate a raw email verification token."""
        return secrets.token_urlsafe(32)

    def hash_token(self, token: str) -> str:
        """Hash a token for secure storage."""
        return hashlib.sha256(token.encode()).hexdigest()

    def gravatar_url(self, size: int = 80) -> str:
        """Generate Gravatar URL from email hash."""
        email_hash = hashlib.md5(self.email.lower().strip().encode()).hexdigest()
        return f'https://www.gravatar.com/avatar/{email_hash}?s={size}&d=identicon'

    def __repr__(self) -> str:
        return f'<User {self.email} role={self.role}>'
