"""
Policy Report Model
===================
Stores results from uploaded privacy policy document analysis.
"""
from datetime import datetime, timezone
from ..extensions import db


class PolicyReport(db.Model):
    """Analyzed privacy policy report."""
    __tablename__ = 'policy_reports'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(10), nullable=False)
    overall_risk = db.Column(db.String(20), nullable=False)
    data_collection_score = db.Column(db.Integer, nullable=False)
    data_sharing_score = db.Column(db.Integer, nullable=False)
    third_party_score = db.Column(db.Integer, nullable=False)
    retention_score = db.Column(db.Integer, nullable=False)
    user_rights_score = db.Column(db.Integer, nullable=False)
    overall_policy_score = db.Column(db.Integer, nullable=False)
    summary_text = db.Column(db.Text, nullable=False)
    key_findings_json = db.Column(db.Text, nullable=False, default='[]')
    extracted_text_sample = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', back_populates='policy_reports')

    @property
    def risk_label(self) -> str:
        """Human-friendly risk label."""
        labels = {
            'low': 'Low Risk',
            'medium': 'Medium Risk',
            'high': 'High Risk'
        }
        return labels.get(self.overall_risk, self.overall_risk)

    @property
    def risk_color(self) -> str:
        """Bootstrap color for risk badge."""
        colors = {'low': 'success', 'medium': 'warning', 'high': 'danger'}
        return colors.get(self.overall_risk, 'secondary')

    @property
    def risk_color_hex(self) -> str:
        """Hex color for charts."""
        colors = {'low': '#059669', 'medium': '#D97706', 'high': '#DC2626'}
        return colors.get(self.overall_risk, '#6B7B8F')

    def to_dict(self) -> dict:
        """Serialize report to dictionary."""
        import json
        return {
            'id': self.id,
            'original_filename': self.original_filename,
            'file_type': self.file_type,
            'overall_risk': self.overall_risk,
            'overall_policy_score': self.overall_policy_score,
            'breakdown': {
                'data_collection': {
                    'score': self.data_collection_score,
                    'label': self._score_label(self.data_collection_score)
                },
                'data_sharing': {
                    'score': self.data_sharing_score,
                    'label': self._score_label(self.data_sharing_score)
                },
                'third_party_tracking': {
                    'score': self.third_party_score,
                    'label': self._score_label(self.third_party_score)
                },
                'retention': {
                    'score': self.retention_score,
                    'label': self._score_label(self.retention_score)
                },
                'user_rights': {
                    'score': self.user_rights_score,
                    'label': self._score_label(self.user_rights_score)
                }
            },
            'summary': self.summary_text,
            'key_findings': json.loads(self.key_findings_json),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    @staticmethod
    def _score_label(score: int) -> str:
        if score >= 71:
            return 'High Concern'
        elif score >= 41:
            return 'Moderate'
        return 'Low Concern'

    def __repr__(self) -> str:
        return f'<PolicyReport {self.original_filename} risk={self.overall_risk}>'
