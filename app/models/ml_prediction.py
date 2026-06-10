"""
ML Prediction Model
===================
Stores machine learning prediction outputs.
"""
from datetime import datetime
from ..extensions import db


class MLPrediction(db.Model):
    """Machine learning prediction result."""
    __tablename__ = 'ml_predictions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    phishing_susceptibility = db.Column(db.String(20), nullable=False)
    phishing_probability = db.Column(db.Float, nullable=False)
    account_risk_probability = db.Column(db.Float, nullable=False)
    model_version = db.Column(db.String(20), nullable=False)
    features_json = db.Column(db.Text, nullable=False)
    predicted_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User', back_populates='ml_predictions')

    @property
    def phishing_color(self) -> str:
        """Bootstrap color for phishing susceptibility."""
        colors = {'low': 'success', 'medium': 'warning', 'high': 'danger'}
        return colors.get(self.phishing_susceptibility, 'secondary')

    @property
    def account_risk_level(self) -> str:
        """Risk level from account risk probability."""
        if self.account_risk_probability >= 0.7:
            return 'high'
        elif self.account_risk_probability >= 0.3:
            return 'medium'
        return 'low'

    @property
    def account_risk_color(self) -> str:
        """Bootstrap color for account risk."""
        colors = {'low': 'success', 'medium': 'warning', 'high': 'danger'}
        return colors.get(self.account_risk_level, 'secondary')

    def __repr__(self) -> str:
        return f'<MLPrediction user={self.user_id} phishing={self.phishing_susceptibility}>'
