"""
SUS Response Model
==================
System Usability Scale evaluation responses.
"""
from datetime import datetime
from ..extensions import db


class SUSResponse(db.Model):
    """System Usability Scale (SUS) response."""
    __tablename__ = 'sus_responses'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    q1 = db.Column(db.Integer, nullable=False)
    q2 = db.Column(db.Integer, nullable=False)
    q3 = db.Column(db.Integer, nullable=False)
    q4 = db.Column(db.Integer, nullable=False)
    q5 = db.Column(db.Integer, nullable=False)
    q6 = db.Column(db.Integer, nullable=False)
    q7 = db.Column(db.Integer, nullable=False)
    q8 = db.Column(db.Integer, nullable=False)
    q9 = db.Column(db.Integer, nullable=False)
    q10 = db.Column(db.Integer, nullable=False)
    sus_score = db.Column(db.Float, nullable=False)
    interpretation = db.Column(db.String(20), nullable=False)
    completed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User', back_populates='sus_responses')

    @staticmethod
    def calculate_score(answers: list) -> tuple:
        """
        Calculate SUS score using standard formula:
        Odd questions: (response - 1)
        Even questions: (5 - response)
        Sum * 2.5 = score (0-100)
        """
        if len(answers) != 10:
            raise ValueError("SUS requires exactly 10 answers")
        total = 0
        for i, ans in enumerate(answers):
            if (i + 1) % 2 == 1:  # Odd
                total += (ans - 1)
            else:  # Even
                total += (5 - ans)
        score = round(total * 2.5, 1)
        score = max(0, min(100, score))

        if score >= 81:
            interp = 'excellent'
        elif score >= 69:
            interp = 'good'
        elif score >= 51:
            interp = 'average'
        else:
            interp = 'poor'
        return score, interp

    @property
    def interpretation_label(self) -> str:
        """Human-friendly interpretation label."""
        labels = {
            'excellent': 'Excellent',
            'good': 'Good',
            'average': 'Average',
            'poor': 'Poor'
        }
        return labels.get(self.interpretation, self.interpretation)

    @property
    def interpretation_color(self) -> str:
        """Bootstrap color for interpretation badge."""
        colors = {
            'excellent': 'success',
            'good': 'info',
            'average': 'warning',
            'poor': 'danger'
        }
        return colors.get(self.interpretation, 'secondary')

    def __repr__(self) -> str:
        return f'<SUSResponse user={self.user_id} score={self.sus_score}>'
