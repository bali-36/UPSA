"""
Settings Routes
===============
User profile, notification preferences, session management.
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from ..extensions import db
from ..models.session import Session
from ..services.notification_service import (
    get_notifications, mark_read, mark_all_read, get_unread_count
)

settings_bp = Blueprint('settings', __name__)


@settings_bp.route('/settings')
@login_required
def index():
    """Settings page."""
    # Active sessions
    sessions = Session.query.filter_by(
        user_id=current_user.id, is_active=True
    ).order_by(Session.created_at.desc()).all()

    # Notification preferences (stored in session for simplicity)
    notif_prefs = {
        'score_changes': request.cookies.get('notif_score_changes', 'true') == 'true',
        'new_recommendations': request.cookies.get('notif_new_recommendations', 'true') == 'true',
        'unusual_login': request.cookies.get('notif_unusual_login', 'true') == 'true',
        'weekly_summary': request.cookies.get('notif_weekly_summary', 'false') == 'true'
    }

    # Notifications
    notifs, _, _ = get_notifications(current_user.id, per_page=20)
    unread_count = get_unread_count(current_user.id)

    return render_template('settings.html',
                         sessions=sessions,
                         notif_prefs=notif_prefs,
                         notifications=notifs,
                         unread_count=unread_count)


@settings_bp.route('/settings/profile', methods=['POST'])
@login_required
def update_profile():
    """Update user profile."""
    full_name = request.form.get('full_name', '').strip()
    if full_name and len(full_name) >= 2:
        current_user.full_name = full_name
        db.session.commit()
        flash('Profile updated successfully.', 'success')
    else:
        flash('Full name must be at least 2 characters.', 'danger')
    return redirect(url_for('settings.index'))


@settings_bp.route('/settings/sessions/<int:session_id>/revoke', methods=['POST'])
@login_required
def revoke_session(session_id):
    """Revoke a specific session."""
    sess = Session.query.filter_by(id=session_id, user_id=current_user.id).first()
    if sess:
        sess.deactivate()
        db.session.commit()
        flash('Session revoked.', 'success')
    else:
        flash('Session not found.', 'danger')
    return redirect(url_for('settings.index'))


@settings_bp.route('/settings/sessions/revoke-all', methods=['POST'])
@login_required
def revoke_all_sessions():
    """Revoke all sessions except current."""
    current_token = request.session.get('session_token') if hasattr(request, 'session') else None
    query = Session.query.filter_by(user_id=current_user.id, is_active=True)
    if current_token:
        query = query.filter(Session.session_token != current_token)
    query.update({'is_active': False})
    db.session.commit()
    flash('All other sessions have been revoked.', 'success')
    return redirect(url_for('settings.index'))


@settings_bp.route('/settings/notifications/read-all', methods=['POST'])
@login_required
def read_all_notifications():
    """Mark all notifications as read."""
    count = mark_all_read(current_user.id)
    flash(f'{count} notification(s) marked as read.', 'success')
    return redirect(url_for('settings.index'))
