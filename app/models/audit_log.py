"""
Audit Log Model
===============
Comprehensive audit trail for all security-relevant actions.
"""
from datetime import datetime
from ..extensions import db


class AuditLog(db.Model):
    """Audit log entry for security-relevant system actions."""
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    action = db.Column(db.String(100), nullable=False)
    entity_type = db.Column(db.String(50), nullable=True)
    entity_id = db.Column(db.Integer, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    result = db.Column(db.String(20), nullable=False)
    details_json = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow, index=True)

    user = db.relationship('User', back_populates='audit_logs')

    @property
    def result_color(self) -> str:
        """Bootstrap color for result badge."""
        colors = {'success': 'success', 'failure': 'danger',
                  'blocked': 'warning', 'info': 'info'}
        return colors.get(self.result, 'secondary')

    @property
    def action_label(self) -> str:
        """Human-friendly action label."""
        labels = {
            'user_login': 'Login',
            'user_logout': 'Logout',
            'user_register': 'Registration',
            'password_change': 'Password Change',
            'password_reset_request': 'Password Reset Request',
            'password_reset_complete': 'Password Reset Complete',
            'mfa_enable': 'MFA Enabled',
            'mfa_disable': 'MFA Disabled',
            'mfa_verify': 'MFA Verification',
            'email_verify': 'Email Verification',
            'device_trust': 'Device Trust Changed',
            'privacy_score_update': 'Privacy Score Updated',
            'survey_submit': 'Survey Submitted',
            'sus_submit': 'SUS Evaluation Submitted',
            'policy_upload': 'Policy Uploaded',
            'recommendation_complete': 'Recommendation Completed',
            'settings_update': 'Settings Updated',
            'role_change': 'Role Changed',
            'account_lockout': 'Account Lockout',
            'login_blocked': 'Login Blocked',
            'risk_rule_update': 'Risk Rule Updated'
        }
        return labels.get(self.action, self.action.replace('_', ' ').title())

    def __repr__(self) -> str:
        return f'<AuditLog {self.action} result={self.result}>'
