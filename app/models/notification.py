"""
Notification Model
==================
In-app notifications for users.
"""
from datetime import datetime
from ..extensions import db


class Notification(db.Model):
    """User notification for score changes, recommendations, alerts."""
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), nullable=False, default='info')
    related_entity_type = db.Column(db.String(50), nullable=True)
    related_entity_id = db.Column(db.Integer, nullable=True)
    is_read = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User', back_populates='notifications')

    @property
    def type_color(self) -> str:
        """Bootstrap alert color for notification type."""
        colors = {
            'info': 'info',
            'success': 'success',
            'warning': 'warning',
            'danger': 'danger'
        }
        return colors.get(self.type, 'info')

    @property
    def type_icon(self) -> str:
        """Font Awesome icon for notification type."""
        icons = {
            'info': 'fa-solid fa-circle-info',
            'success': 'fa-solid fa-circle-check',
            'warning': 'fa-solid fa-triangle-exclamation',
            'danger': 'fa-solid fa-circle-xmark'
        }
        return icons.get(self.type, 'fa-solid fa-circle-info')

    @property
    def time_ago(self) -> str:
        """Human-readable time since creation."""
        from ..utils.time_helpers import time_ago as ta
        return ta(self.created_at)

    def mark_read(self) -> None:
        """Mark notification as read."""
        self.is_read = True

    def __repr__(self) -> str:
        return f'<Notification user={self.user_id} type={self.type}>'
