"""
Trusted Device Model
====================
Devices that the user has explicitly marked as trusted for risk scoring.
"""
from datetime import datetime
from ..extensions import db


class TrustedDevice(db.Model):
    """A device/browser combination trusted by the user."""
    __tablename__ = 'trusted_devices'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    device_name = db.Column(db.String(255), nullable=False)
    browser = db.Column(db.String(100), nullable=False)
    operating_system = db.Column(db.String(100), nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    location = db.Column(db.String(255), nullable=True)
    user_agent_hash = db.Column(db.String(64), nullable=False)
    is_trusted = db.Column(db.Boolean, nullable=False, default=True)
    trusted_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_used_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User', back_populates='trusted_devices')

    __table_args__ = (
        db.UniqueConstraint('user_id', 'user_agent_hash',
                            name='uq_trusted_device_user_ua'),
    )

    def __repr__(self) -> str:
        return f'<TrustedDevice {self.device_name} trusted={self.is_trusted}>'
