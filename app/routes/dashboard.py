"""
Dashboard Routes
================
Main user dashboard with overview of scores, activity, and recommendations.
"""
from flask import Blueprint, render_template
from flask_login import login_required, current_user
from ..services.privacy_service import get_latest_privacy_score, calculate_security_score, get_recommendations
from ..services.notification_service import get_unread_count
from ..services.risk_engine import get_current_risk_status
from ..services.frustration_service import get_frustration_status
from ..services.ml_service import get_latest_prediction
from ..models.audit_log import AuditLog

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/dashboard')
@login_required
def index():
    """Main dashboard page."""
    user_id = current_user.id

    # Get latest scores
    privacy_score = get_latest_privacy_score(user_id)
    if not privacy_score:
        from ..services.privacy_service import calculate_privacy_score
        privacy_score = calculate_privacy_score(user_id, current_user)

    security_score = calculate_security_score(user_id, current_user)

    # Risk status
    risk_status = get_current_risk_status(user_id)

    # Frustration
    frustration = get_frustration_status(user_id)

    # ML predictions
    ml_pred = get_latest_prediction(user_id)

    # Recent activity
    recent_activity = AuditLog.query.filter_by(user_id=user_id).order_by(
        AuditLog.created_at.desc()
    ).limit(10).all()

    # Top recommendations
    recommendations = get_recommendations(user_id, status='pending')[:3]

    # Potential improvement
    potential = _calculate_potential_improvement(privacy_score, security_score)

    # Unread notifications
    unread_notifs = get_unread_count(user_id)

    return render_template('dashboard.html',
                         privacy_score=privacy_score,
                         security_score=security_score,
                         risk_status=risk_status,
                         frustration=frustration,
                         ml_pred=ml_pred,
                         recent_activity=recent_activity,
                         recommendations=recommendations,
                         potential=potential,
                         unread_notifs=unread_notifs)


def _calculate_potential_improvement(privacy, security):
    """Calculate potential score improvement if all recommendations completed."""
    recs = get_recommendations(current_user.id, status='pending')
    total_impact = sum(r.impact_estimate for r in recs if r.impact_estimate)

    priv_potential = min(100, privacy.overall_score + total_impact)
    sec_potential = min(100, security['total_score'] + total_impact)

    return {
        'privacy': {'current': privacy.overall_score, 'potential': priv_potential},
        'security': {'current': security['total_score'], 'potential': sec_potential}
    }
