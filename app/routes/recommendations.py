"""
Recommendations Routes
======================
Personalized security recommendations.
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from ..services.privacy_service import get_recommendations, complete_recommendation

recommendations_bp = Blueprint('recommendations', __name__)


@recommendations_bp.route('/recommendations')
@login_required
def index():
    """Recommendations page."""
    status = request.args.get('status', 'all')
    recommendations = get_recommendations(current_user.id, status=status)

    # Calculate potential improvement
    from ..services.privacy_service import get_latest_privacy_score, calculate_security_score
    privacy = get_latest_privacy_score(current_user.id)
    security = calculate_security_score(current_user.id)
    total_impact = sum(r.impact_estimate for r in recommendations if r.impact_estimate and not r.is_completed)

    potential = {
        'privacy': {'current': privacy.overall_score if privacy else 0,
                   'potential': min(100, (privacy.overall_score if privacy else 0) + total_impact)},
        'security': {'current': security['total_score'],
                    'potential': min(100, security['total_score'] + total_impact)}
    }

    return render_template('recommendations.html',
                         recommendations=recommendations,
                         status=status,
                         potential=potential)


@recommendations_bp.route('/recommendations/<int:rec_id>/complete', methods=['POST'])
@login_required
def complete(rec_id):
    """Mark a recommendation as completed."""
    success, message = complete_recommendation(rec_id, current_user.id)
    flash(message, 'success' if success else 'warning')
    return redirect(url_for('recommendations.index'))
