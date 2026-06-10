"""
Survey Response Model
=====================
Stores security awareness survey submissions.
"""
from datetime import datetime
from ..extensions import db


class SurveyResponse(db.Model):
    """Security awareness survey response."""
    __tablename__ = 'survey_responses'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    q1_reuse_password = db.Column(db.Integer, nullable=False)
    q2_mfa_usage = db.Column(db.Integer, nullable=False)
    q3_email_verify = db.Column(db.Integer, nullable=False)
    q4_location_perm = db.Column(db.Integer, nullable=False)
    q5_privacy_review = db.Column(db.Integer, nullable=False)
    q6_public_wifi = db.Column(db.Integer, nullable=False)
    q7_software_updates = db.Column(db.Integer, nullable=False)
    q8_backup_habits = db.Column(db.Integer, nullable=False)
    q9_phishing_recognition = db.Column(db.Integer, nullable=False)
    q10_password_manager = db.Column(db.Integer, nullable=False)
    awareness_score = db.Column(db.Integer, nullable=False)
    score_category = db.Column(db.String(20), nullable=False)
    completed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User', back_populates='survey_responses')

    @property
    def category_label(self) -> str:
        """Human-friendly score category."""
        labels = {'low': 'Needs Improvement', 'medium': 'Moderate', 'high': 'Strong'}
        return labels.get(self.score_category, self.score_category)

    @property
    def category_color(self) -> str:
        """Bootstrap color for category badge."""
        colors = {'low': 'danger', 'medium': 'warning', 'high': 'success'}
        return colors.get(self.score_category, 'secondary')

    @staticmethod
    def calculate_score(answers: list) -> tuple:
        """Calculate awareness score from raw answers (1-4 each)."""
        raw_total = sum(answers)
        min_raw = len(answers) * 1
        max_raw = len(answers) * 4
        score = int(round(((raw_total - min_raw) / (max_raw - min_raw)) * 100))
        score = max(0, min(100, score))
        if score <= 40:
            category = 'low'
        elif score <= 70:
            category = 'medium'
        else:
            category = 'high'
        return score, category

    @property
    def breakdown(self) -> dict:
        """Score breakdown by category."""
        categories = {
            'password_habits': [self.q1_reuse_password, self.q10_password_manager],
            'mfa_awareness': [self.q2_mfa_usage],
            'privacy_awareness': [self.q4_location_perm, self.q5_privacy_review],
            'phishing_awareness': [self.q3_email_verify, self.q9_phishing_recognition],
            'general_security': [self.q6_public_wifi, self.q7_software_updates, self.q8_backup_habits]
        }
        result = {}
        for name, answers in categories.items():
            raw = sum(answers)
            mn = len(answers) * 1
            mx = len(answers) * 4
            result[name] = int(round(((raw - mn) / (mx - mn)) * 100))
        return result

    def __repr__(self) -> str:
        return f'<SurveyResponse user={self.user_id} score={self.awareness_score}>'
