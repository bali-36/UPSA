"""
Privacy Score Model
===================
Stores calculated privacy health scores with full component breakdown.
"""
from datetime import datetime
from ..extensions import db


class PrivacyScore(db.Model):
    """A privacy health score snapshot for a user."""
    __tablename__ = 'privacy_scores'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    overall_score = db.Column(db.Integer, nullable=False)
    mfa_score = db.Column(db.Integer, nullable=False, default=0)
    password_strength_score = db.Column(db.Integer, nullable=False, default=0)
    password_age_score = db.Column(db.Integer, nullable=False, default=0)
    browser_perm_score = db.Column(db.Integer, nullable=False, default=0)
    location_perm_score = db.Column(db.Integer, nullable=False, default=0)
    cam_mic_score = db.Column(db.Integer, nullable=False, default=0)
    notification_score = db.Column(db.Integer, nullable=False, default=0)
    survey_score = db.Column(db.Integer, nullable=False, default=0)
    risk_category = db.Column(db.String(20), nullable=False)
    recorded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User', back_populates='privacy_scores')

    @property
    def category_label(self) -> str:
        """Human-friendly risk category label."""
        labels = {
            'low': 'Good',
            'medium': 'Fair',
            'high': 'Needs Work'
        }
        return labels.get(self.risk_category, self.risk_category)

    @property
    def category_color(self) -> str:
        """Bootstrap color for category badge."""
        colors = {'low': 'success', 'medium': 'warning', 'high': 'danger'}
        return colors.get(self.risk_category, 'secondary')

    @property
    def score_color_hex(self) -> str:
        """Hex color based on score value."""
        if self.overall_score >= 71:
            return '#059669'
        elif self.overall_score >= 41:
            return '#D97706'
        return '#DC2626'

    def to_dict(self) -> dict:
        """Serialize score to dictionary."""
        return {
            'id': self.id,
            'overall_score': self.overall_score,
            'mfa_score': self.mfa_score,
            'password_strength_score': self.password_strength_score,
            'password_age_score': self.password_age_score,
            'browser_perm_score': self.browser_perm_score,
            'location_perm_score': self.location_perm_score,
            'cam_mic_score': self.cam_mic_score,
            'notification_score': self.notification_score,
            'survey_score': self.survey_score,
            'risk_category': self.risk_category,
            'recorded_at': self.recorded_at.isoformat() if self.recorded_at else None
        }

    def __repr__(self) -> str:
        return f'<PrivacyScore user={self.user_id} score={self.overall_score}>'
