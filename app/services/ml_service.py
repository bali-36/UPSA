"""
ML Service
==========
Machine learning predictions for phishing susceptibility and account risk.
"""
import os
import json
from datetime import datetime, timedelta
from flask import current_app
from ..extensions import db
from ..models.ml_prediction import MLPrediction
from ..models.survey_response import SurveyResponse
from ..models.privacy_score import PrivacyScore
from ..models.risk_event import RiskEvent


def _get_model_path(filename: str) -> str:
    """Get full path to a persisted model file."""
    return os.path.join(current_app.config['ML_MODEL_PATH'], filename)


def _model_exists(filename: str) -> bool:
    """Check if a model file exists."""
    return os.path.exists(_get_model_path(filename))


def train_models() -> dict:
    """
    Train ML models for phishing susceptibility and account risk prediction.
    Uses synthetic training data when real data is insufficient.
    Persists models with joblib.
    """
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.tree import DecisionTreeClassifier
        import joblib
        import numpy as np

        # Generate synthetic training data
        np.random.seed(42)
        n_samples = 500

        # Features: survey_q1..q10, mfa_enabled, password_age_days, login_failures, privacy_score
        X = np.random.rand(n_samples, 14)

        # Phishing susceptibility labels (0=low, 1=medium, 2=high)
        # Lower survey scores, no MFA, older passwords = higher susceptibility
        y_phishing = np.zeros(n_samples, dtype=int)
        for i in range(n_samples):
            risk_score = (1 - X[i, :10].mean()) * 60  # invert survey scores
            risk_score += (1 - X[i, 10]) * 20  # no MFA
            risk_score += X[i, 11] * 10  # old password
            risk_score += X[i, 12] * 10  # login failures
            if risk_score > 55:
                y_phishing[i] = 2  # high
            elif risk_score > 30:
                y_phishing[i] = 1  # medium
            else:
                y_phishing[i] = 0  # low

        # Account risk labels (binary: 0=low risk, 1=high risk)
        y_account = np.zeros(n_samples, dtype=int)
        for i in range(n_samples):
            risk_score = (1 - X[i, :10].mean()) * 40
            risk_score += (1 - X[i, 10]) * 25
            risk_score += X[i, 11] * 15
            risk_score += X[i, 12] * 20
            y_account[i] = 1 if risk_score > 50 else 0

        # Train models
        models = {
            'phishing_rf': RandomForestClassifier(n_estimators=100, random_state=42),
            'phishing_lr': LogisticRegression(max_iter=1000, random_state=42),
            'phishing_dt': DecisionTreeClassifier(random_state=42),
            'account_rf': RandomForestClassifier(n_estimators=100, random_state=42)
        }

        models['phishing_rf'].fit(X, y_phishing)
        models['phishing_lr'].fit(X, y_phishing)
        models['phishing_dt'].fit(X, y_phishing)
        models['account_rf'].fit(X, y_account)

        # Persist
        for name, model in models.items():
            joblib.dump(model, _get_model_path(f'{name}.joblib'))

        # Save training metadata
        meta = {
            'trained_at': datetime.utcnow().isoformat(),
            'version': '1.0.0',
            'samples': n_samples,
            'features': [
                'q1_reuse_password', 'q2_mfa_usage', 'q3_email_verify',
                'q4_location_perm', 'q5_privacy_review', 'q6_public_wifi',
                'q7_software_updates', 'q8_backup_habits', 'q9_phishing_recognition',
                'q10_password_manager', 'mfa_enabled', 'password_age_days',
                'login_failures_7d', 'privacy_score'
            ]
        }
        with open(_get_model_path('metadata.json'), 'w') as f:
            json.dump(meta, f, indent=2)

        return {
            'success': True,
            'message': f'Models trained on {n_samples} samples',
            'models': list(models.keys())
        }

    except Exception as e:
        current_app.logger.error(f'ML training error: {e}')
        return {'success': False, 'message': str(e)}


def predict(user_id: int) -> dict:
    """
    Generate ML predictions for a user.
    Returns prediction dict with explanations.
    """
    import joblib
    import numpy as np

    # Check if models exist, train if not
    if not _model_exists('phishing_rf.joblib'):
        train_models()

    # Gather features
    features = _extract_features(user_id)
    if not features:
        return _fallback_prediction(user_id)

    X = np.array([features['vector']])

    try:
        # Load models
        phishing_rf = joblib.load(_get_model_path('phishing_rf.joblib'))
        phishing_lr = joblib.load(_get_model_path('phishing_lr.joblib'))
        account_rf = joblib.load(_get_model_path('account_rf.joblib'))

        # Phishing prediction (ensemble of RF and LR)
        pred_rf = int(phishing_rf.predict(X)[0])
        pred_lr = int(phishing_lr.predict(X)[0])
        proba_rf = phishing_rf.predict_proba(X)[0]
        proba_lr = phishing_lr.predict_proba(X)[0]

        # Average probabilities
        avg_proba = (proba_rf + proba_lr) / 2
        phishing_class = int(np.argmax(avg_proba))
        phishing_prob = float(avg_proba[phishing_class])

        # Account risk
        account_proba = float(account_rf.predict_proba(X)[0][1])

        susceptibility_map = {0: 'low', 1: 'medium', 2: 'high'}
        phishing_label = susceptibility_map.get(phishing_class, 'medium')

        # Generate explanation
        explanation = _generate_phishing_explanation(features, phishing_label)
        account_explanation = _generate_account_explanation(features, account_proba)

        # Store prediction
        prediction = MLPrediction(
            user_id=user_id,
            phishing_susceptibility=phishing_label,
            phishing_probability=phishing_prob,
            account_risk_probability=account_proba,
            model_version='1.0.0',
            features_json=json.dumps(features['raw'])
        )
        db.session.add(prediction)
        db.session.commit()

        return {
            'phishing': {
                'susceptibility': phishing_label,
                'probability': round(phishing_prob, 2),
                'explanation': explanation
            },
            'account_risk': {
                'probability': round(account_proba, 2),
                'risk_level': 'high' if account_proba >= 0.7 else 'medium' if account_proba >= 0.3 else 'low',
                'explanation': account_explanation
            },
            'model_version': '1.0.0',
            'predicted_at': datetime.utcnow().isoformat()
        }

    except Exception as e:
        current_app.logger.error(f'ML prediction error: {e}')
        return _fallback_prediction(user_id)


def _extract_features(user_id: int) -> dict:
    """Extract feature vector for ML prediction."""
    from ..models.user import User

    user = User.query.get(user_id)
    if not user:
        return None

    # Survey responses
    survey = SurveyResponse.query.filter_by(user_id=user_id).order_by(
        SurveyResponse.completed_at.desc()
    ).first()

    survey_answers = []
    if survey:
        survey_answers = [
            survey.q1_reuse_password / 4.0,
            survey.q2_mfa_usage / 4.0,
            survey.q3_email_verify / 4.0,
            survey.q4_location_perm / 4.0,
            survey.q5_privacy_review / 4.0,
            survey.q6_public_wifi / 4.0,
            survey.q7_software_updates / 4.0,
            survey.q8_backup_habits / 4.0,
            survey.q9_phishing_recognition / 4.0,
            survey.q10_password_manager / 4.0
        ]
    else:
        survey_answers = [0.5] * 10  # Default neutral

    # MFA
    mfa = 1.0 if user.mfa_enabled else 0.0

    # Password age (normalized, older = higher)
    pwd_age_days = 180
    if user.password_changed_at:
        pwd_age_days = (datetime.utcnow() - user.password_changed_at).days
    pwd_age_norm = min(pwd_age_days / 365.0, 1.0)

    # Login failures
    failures = user.failed_login_count if user.failed_login_count else 0
    failures_norm = min(failures / 10.0, 1.0)

    # Privacy score
    latest_score = PrivacyScore.query.filter_by(user_id=user_id).order_by(
        PrivacyScore.recorded_at.desc()
    ).first()
    privacy_norm = (latest_score.overall_score / 100.0) if latest_score else 0.5

    vector = survey_answers + [mfa, pwd_age_norm, failures_norm, privacy_norm]

    return {
        'vector': vector,
        'raw': {
            'survey_answers': survey_answers,
            'mfa_enabled': bool(mfa),
            'password_age_days': pwd_age_days,
            'login_failures': failures,
            'privacy_score': int(privacy_norm * 100)
        }
    }


def _generate_phishing_explanation(features: dict, label: str) -> str:
    """Generate a plain-language phishing susceptibility explanation."""
    raw = features['raw']
    parts = []

    if label == 'low':
        parts.append('Your security awareness habits suggest you are well-protected against phishing.')
    elif label == 'medium':
        parts.append('Based on your survey responses, you show moderate awareness of phishing techniques.')
    else:
        parts.append('Your responses indicate you may be more vulnerable to phishing attempts.')

    # Specific advice
    survey = raw.get('survey_answers', [0.5] * 10)
    if survey[2] < 0.5:  # q3 email verification
        parts.append('Improving how you verify email senders could significantly reduce your risk.')
    if survey[8] < 0.5:  # q9 phishing recognition
        parts.append('Learning to recognize common phishing signs would help protect you.')
    if not raw.get('mfa_enabled'):
        parts.append('Enabling MFA would add a strong layer of protection against account takeover via phishing.')

    return ' '.join(parts) if parts else 'Complete the security survey for a personalized assessment.'


def _generate_account_explanation(features: dict, probability: float) -> str:
    """Generate a plain-language account risk explanation."""
    raw = features['raw']

    if probability < 0.3:
        return ('Your current security practices — including password hygiene and awareness — '
                'suggest a low probability of account compromise in the next 90 days.')
    elif probability < 0.7:
        return ('Your account has a moderate risk of compromise. '
                'Consider enabling MFA and updating your password to reduce this risk.')
    else:
        return ('Your account shows a higher risk of compromise based on current patterns. '
                'We strongly recommend enabling MFA immediately, updating your password, '
                'and reviewing your security settings.')


def _fallback_prediction(user_id: int) -> dict:
    """Return a reasonable fallback prediction when ML is unavailable."""
    from ..models.user import User
    user = User.query.get(user_id)

    if not user:
        return {
            'phishing': {'susceptibility': 'medium', 'probability': 0.5,
                        'explanation': 'Complete the security survey for a personalized assessment.'},
            'account_risk': {'probability': 0.5, 'risk_level': 'medium',
                           'explanation': 'Complete the security survey for a personalized assessment.'},
            'model_version': 'fallback',
            'predicted_at': datetime.utcnow().isoformat()
        }

    # Simple heuristic-based fallback
    phishing = 'low' if user.mfa_enabled else 'medium'
    account_prob = 0.2 if user.mfa_enabled else 0.5

    return {
        'phishing': {
            'susceptibility': phishing,
            'probability': 0.4,
            'explanation': 'This is a preliminary estimate. Complete the security survey for a more accurate assessment.'
        },
        'account_risk': {
            'probability': account_prob,
            'risk_level': 'low' if account_prob < 0.3 else 'medium',
            'explanation': 'This is a preliminary estimate based on your current settings.'
        },
        'model_version': 'fallback',
        'predicted_at': datetime.utcnow().isoformat()
    }


def get_latest_prediction(user_id: int) -> MLPrediction:
    """Get the most recent ML prediction for a user."""
    return MLPrediction.query.filter_by(user_id=user_id).order_by(
        MLPrediction.predicted_at.desc()
    ).first()
