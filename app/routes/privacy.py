"""
Privacy Center Routes
=====================
Privacy health score detail, history, and recommendations.
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from ..services.privacy_service import (
    get_latest_privacy_score, calculate_privacy_score,
    get_privacy_score_history, get_recommendations, complete_recommendation
)

privacy_bp = Blueprint('privacy', __name__)


@privacy_bp.route('/privacy-center')
@login_required
def index():
    """Privacy center page."""
    user_id = current_user.id

    privacy_score = get_latest_privacy_score(user_id)
    if not privacy_score:
        privacy_score = calculate_privacy_score(user_id, current_user)

    # Score history
    days = request.args.get('days', 30, type=int)
    history = get_privacy_score_history(user_id, days)

    # Recommendations
    recommendations = get_recommendations(user_id, status='pending')

    # Website permissions
    from ..models.website_permission import WebsitePermission
    permissions = WebsitePermission.query.filter_by(user_id=user_id).all()

    return render_template('privacy_center.html',
                         privacy_score=privacy_score,
                         history=history,
                         recommendations=recommendations,
                         permissions=permissions,
                         days=days)


@privacy_bp.route('/privacy-center/recalculate', methods=['GET', 'POST'])
@login_required
def recalculate():
    """Trigger privacy score recalculation."""
    calculate_privacy_score(current_user.id, current_user)
    flash('Your privacy score has been recalculated!', 'success')
    return index()


@privacy_bp.route('/recommendations/<int:rec_id>/complete', methods=['POST'])
@login_required
def complete_rec(rec_id):
    """Mark a recommendation as completed."""
    success, message = complete_recommendation(rec_id, current_user.id)
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
        if not success:
            return jsonify({'success': False, 'message': message}), 400
        
        # Get updated score info
        score = get_latest_privacy_score(current_user.id)
        recs = get_recommendations(current_user.id, status='pending')
        recs_data = [{
            'id': r.id,
            'title': r.title,
            'plain_explanation': r.plain_explanation[:120] + '...' if len(r.plain_explanation) > 120 else r.plain_explanation,
            'priority': r.priority,
            'priority_label': r.priority_label,
            'priority_color': r.priority_color,
            'complete_url': url_for('privacy.complete_rec', rec_id=r.id)
        } for r in recs[:5]]

        return jsonify({
            'success': True,
            'message': message,
            'overall_score': score.overall_score,
            'category_label': score.category_label,
            'category_color': score.category_color,
            'score_color_hex': score.score_color_hex,
            'breakdown': {
                'mfa_score': score.mfa_score,
                'password_strength_score': score.password_strength_score,
                'password_age_score': score.password_age_score,
                'browser_perm_score': score.browser_perm_score,
                'location_perm_score': score.location_perm_score,
                'cam_mic_score': score.cam_mic_score,
                'notification_score': score.notification_score,
                'survey_score': score.survey_score
            },
            'recommendations': recs_data
        })

    flash(message, 'success' if success else 'warning')
    return redirect(request.referrer or url_for('privacy.index'))


@privacy_bp.route('/privacy-center/permissions/<int:perm_id>/revoke', methods=['POST'])
@login_required
def revoke_permission(perm_id):
    """Revoke a website permission."""
    from ..models.website_permission import WebsitePermission
    from ..extensions import db
    
    perm = WebsitePermission.query.filter_by(id=perm_id, user_id=current_user.id).first()
    if not perm:
        return jsonify({'success': False, 'message': 'Permission not found.'}), 404
        
    perm.is_allowed = False
    db.session.commit()
    
    # Recalculate privacy score
    score = calculate_privacy_score(current_user.id)
    recs = get_recommendations(current_user.id, status='pending')
    recs_data = [{
        'id': r.id,
        'title': r.title,
        'plain_explanation': r.plain_explanation[:120] + '...' if len(r.plain_explanation) > 120 else r.plain_explanation,
        'priority': r.priority,
        'priority_label': r.priority_label,
        'priority_color': r.priority_color,
        'complete_url': url_for('privacy.complete_rec', rec_id=r.id)
    } for r in recs[:5]]
    
    return jsonify({
        'success': True,
        'message': f"Permission revoked for {perm.website}.",
        'overall_score': score.overall_score,
        'category_label': score.category_label,
        'category_color': score.category_color,
        'score_color_hex': score.score_color_hex,
        'breakdown': {
            'mfa_score': score.mfa_score,
            'password_strength_score': score.password_strength_score,
            'password_age_score': score.password_age_score,
            'browser_perm_score': score.browser_perm_score,
            'location_perm_score': score.location_perm_score,
            'cam_mic_score': score.cam_mic_score,
            'notification_score': score.notification_score,
            'survey_score': score.survey_score
        },
        'recommendations': recs_data
    })
