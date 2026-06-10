"""
Risk Event Model
================
Logs individual risk-scoring events during authentication.
"""
from datetime import datetime
from ..extensions import db


class RiskEvent(db.Model):
    """A single risk event recorded during login or other security actions."""
    __tablename__ = 'risk_events'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    event_type = db.Column(db.String(50), nullable=False)
    risk_points = db.Column(db.Integer, nullable=False)
    total_score = db.Column(db.Integer, nullable=False)
    risk_category = db.Column(db.String(20), nullable=False)
    device_info = db.Column(db.String(255), nullable=True)
    browser_info = db.Column(db.String(100), nullable=True)
    location_info = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    result = db.Column(db.String(50), nullable=False)  # allowed, mfa_required, blocked
    explanation = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User', back_populates='risk_events')

    @property
    def result_label(self) -> str:
        """Human-friendly result label."""
        labels = {
            'allowed': 'Login Allowed',
            'mfa_required': 'MFA Required',
            'blocked': 'Login Blocked'
        }
        return labels.get(self.result, self.result)

    @property
    def result_color(self) -> str:
        """Bootstrap color class for result."""
        colors = {
            'allowed': 'success',
            'mfa_required': 'warning',
            'blocked': 'danger'
        }
        return colors.get(self.result, 'secondary')

    def __repr__(self) -> str:
        return f'<RiskEvent {self.event_type} +{self.risk_points}pts {self.result}>'
