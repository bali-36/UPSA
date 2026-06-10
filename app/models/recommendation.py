"""
Recommendation Model
====================
Personalized security recommendations for the user.
"""
from datetime import datetime
from ..extensions import db


class Recommendation(db.Model):
    """A personalized security recommendation."""
    __tablename__ = 'recommendations'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    category = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    plain_explanation = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(20), nullable=False)
    impact_estimate = db.Column(db.Integer, nullable=True)
    is_completed = db.Column(db.Boolean, nullable=False, default=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User', back_populates='recommendations')

    @property
    def priority_label(self) -> str:
        """Human-friendly priority label."""
        labels = {
            'high': 'High Priority',
            'medium': 'Medium Priority',
            'low': 'Low Priority'
        }
        return labels.get(self.priority, self.priority)

    @property
    def priority_color(self) -> str:
        """Bootstrap color for priority badge."""
        colors = {'high': 'danger', 'medium': 'warning', 'low': 'info'}
        return colors.get(self.priority, 'secondary')

    @property
    def category_label(self) -> str:
        """Human-friendly category name."""
        labels = {
            'mfa': 'Multi-Factor Authentication',
            'password': 'Password Security',
            'privacy': 'Privacy Settings',
            'device': 'Device Security',
            'phishing': 'Phishing Awareness',
            'permissions': 'App Permissions',
            'updates': 'Software Updates',
            'backup': 'Data Backups',
            'general': 'General Security'
        }
        return labels.get(self.category, self.category.title())

    @property
    def category_icon(self) -> str:
        """Font Awesome icon class for category."""
        icons = {
            'mfa': 'fa-solid fa-shield-halved',
            'password': 'fa-solid fa-lock',
            'privacy': 'fa-solid fa-user-shield',
            'device': 'fa-solid fa-laptop',
            'phishing': 'fa-solid fa-fish',
            'permissions': 'fa-solid fa-check-double',
            'updates': 'fa-solid fa-rotate',
            'backup': 'fa-solid fa-cloud-arrow-up',
            'general': 'fa-solid fa-circle-info'
        }
        return icons.get(self.category, 'fa-solid fa-circle-info')

    def mark_completed(self) -> None:
        """Mark recommendation as completed."""
        self.is_completed = True
        self.completed_at = datetime.utcnow()

    def __repr__(self) -> str:
        return f'<Recommendation {self.title[:30]} priority={self.priority}>'
