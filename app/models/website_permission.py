"""
Website Permission Model
========================
Stores permissions granted by users to various websites (Location, Camera, Mic, Notification).
Allows context-based classification (e.g., Maps with Location is Legitimate; Gaming with Location is Risky).
"""
from datetime import datetime
from ..extensions import db


class WebsitePermission(db.Model):
    """A browser permission granted to a website."""
    __tablename__ = 'website_permissions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    website = db.Column(db.String(255), nullable=False)
    permission_type = db.Column(db.String(50), nullable=False)  # 'location', 'camera', 'microphone', 'notification'
    category = db.Column(db.String(50), nullable=False)  # 'navigation', 'communication', 'gaming', 'shopping', 'ads', 'weather', 'social'
    description = db.Column(db.String(255), nullable=True)
    is_allowed = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User', back_populates='website_permissions')

    @property
    def is_contextually_appropriate(self) -> bool:
        """Check if the permission is contextually appropriate for the website's category."""
        if self.permission_type == 'location':
            return self.category in ('navigation', 'weather')
        elif self.permission_type in ('camera', 'microphone'):
            return self.category in ('communication', 'creative')
        elif self.permission_type == 'notification':
            return self.category in ('communication', 'news', 'productivity')
        return True

    @property
    def permission_icon(self) -> str:
        """Font Awesome icon for the permission type."""
        icons = {
            'location': 'fa-solid fa-location-dot',
            'camera': 'fa-solid fa-video',
            'microphone': 'fa-solid fa-microphone',
            'notification': 'fa-solid fa-bell'
        }
        return icons.get(self.permission_type, 'fa-solid fa-circle-info')

    @property
    def category_label(self) -> str:
        """Friendly label for the website category."""
        labels = {
            'navigation': 'Navigation / Maps',
            'communication': 'Communication / Meetings',
            'gaming': 'Gaming',
            'shopping': 'Shopping / E-commerce',
            'ads': 'Advertising Networks',
            'weather': 'Weather Services',
            'social': 'Social Media'
        }
        return labels.get(self.category, self.category.title())

    def __repr__(self) -> str:
        return f'<WebsitePermission {self.website} type={self.permission_type} allowed={self.is_allowed}>'
