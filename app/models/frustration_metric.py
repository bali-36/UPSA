"""
Frustration Metric Model
========================
Tracks user experience friction to adapt security UX.
"""
from datetime import datetime
from ..extensions import db


class FrustrationMetric(db.Model):
    """User frustration metrics for adaptive UX."""
    __tablename__ = 'frustration_metrics'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    login_failures_7d = db.Column(db.Integer, nullable=False, default=0)
    password_reset_count_7d = db.Column(db.Integer, nullable=False, default=0)
    mfa_abandonment_count = db.Column(db.Integer, nullable=False, default=0)
    avg_login_completion_sec = db.Column(db.Integer, nullable=True)
    help_page_visit_count = db.Column(db.Integer, nullable=False, default=0)
    frustration_level = db.Column(db.String(20), nullable=False, default='low')
    recorded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User', back_populates='frustration_metrics')

    @property
    def level_label(self) -> str:
        """Human-friendly frustration level."""
        labels = {
            'low': 'Smooth Experience',
            'medium': 'Some Friction',
            'high': 'High Frustration'
        }
        return labels.get(self.frustration_level, self.frustration_level)

    @property
    def level_color(self) -> str:
        """Bootstrap color — low frustration is good (green)."""
        colors = {'low': 'success', 'medium': 'warning', 'high': 'danger'}
        return colors.get(self.frustration_level, 'secondary')

    def calculate_level(self) -> str:
        """Recalculate frustration level from metrics."""
        score = 0
        score += min(self.login_failures_7d * 5, 25)
        score += min(self.password_reset_count_7d * 10, 20)
        score += min(self.mfa_abandonment_count * 8, 24)
        score += min(self.help_page_visit_count * 3, 15)
        if score <= 20:
            return 'low'
        elif score <= 45:
            return 'medium'
        return 'high'

    def __repr__(self) -> str:
        return f'<FrustrationMetric user={self.user_id} level={self.frustration_level}>'
