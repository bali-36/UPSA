"""
Admin Routes
============
Admin dashboard, user management, analytics, audit logs, risk rules.
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, current_app
from flask_login import login_required, current_user
from functools import wraps
from ..extensions import db
from ..models.user import User
from ..models.privacy_score import PrivacyScore
from ..models.risk_event import RiskEvent
from ..models.audit_log import AuditLog
from ..models.session import Session
from ..services.audit_service import get_logs_paginated

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


def admin_required(f):
    """Decorator to require admin role."""
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    return decorated


@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    """Admin dashboard."""
    # Stats
    total_users = User.query.count()
    active_sessions = Session.query.filter_by(is_active=True).filter(
        Session.expires_at > db.func.now()
    ).count()

    # Average scores
    avg_privacy = db.session.query(db.func.avg(PrivacyScore.overall_score)).scalar() or 0
    avg_privacy = round(avg_privacy, 1)

    # Blocked logins today
    from datetime import datetime, timedelta
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    blocked_today = RiskEvent.query.filter(
        RiskEvent.result == 'blocked',
        RiskEvent.created_at >= today_start
    ).count()

    # Score distribution
    score_dist = {
        '0-20': 0, '21-40': 0, '41-60': 0, '61-80': 0, '81-100': 0
    }
    scores = db.session.query(PrivacyScore.overall_score).all()
    for s in scores:
        v = s[0]
        if v <= 20:
            score_dist['0-20'] += 1
        elif v <= 40:
            score_dist['21-40'] += 1
        elif v <= 60:
            score_dist['41-60'] += 1
        elif v <= 80:
            score_dist['61-80'] += 1
        else:
            score_dist['81-100'] += 1

    # Risk distribution
    risk_dist = {'low': 0, 'medium': 0, 'high': 0}
    latest_scores = db.session.query(
        PrivacyScore.user_id,
        db.func.max(PrivacyScore.recorded_at).label('max_date')
    ).group_by(PrivacyScore.user_id).subquery()

    recent_scores = PrivacyScore.query.join(
        latest_scores,
        db.and_(
            PrivacyScore.user_id == latest_scores.c.user_id,
            PrivacyScore.recorded_at == latest_scores.c.max_date
        )
    ).all()
    for s in recent_scores:
        risk_dist[s.risk_category] = risk_dist.get(s.risk_category, 0) + 1

    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         active_sessions=active_sessions,
                         avg_privacy=avg_privacy,
                         blocked_today=blocked_today,
                         score_dist=score_dist,
                         risk_dist=risk_dist)


@admin_bp.route('/users')
@admin_required
def users():
    """User management page."""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')

    query = User.query
    if search:
        query = query.filter(
            db.or_(
                User.full_name.ilike(f'%{search}%'),
                User.email.ilike(f'%{search}%')
            )
        )

    pagination = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )

    # Attach latest privacy scores
    user_ids = [u.id for u in pagination.items]
    latest_scores = {}
    for uid in user_ids:
        score = PrivacyScore.query.filter_by(user_id=uid).order_by(
            PrivacyScore.recorded_at.desc()
        ).first()
        latest_scores[uid] = score

    return render_template('admin/users.html',
                         users=pagination.items,
                         scores=latest_scores,
                         pagination=pagination,
                         search=search)


@admin_bp.route('/users/<int:user_id>/toggle-role', methods=['POST'])
@admin_required
def toggle_role(user_id):
    """Toggle user role between user and admin."""
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot change your own role.', 'danger')
        return redirect(url_for('admin.users'))

    user.role = 'admin' if user.role == 'user' else 'user'
    db.session.commit()
    flash(f"{user.full_name}'s role updated to {user.role}.", 'success')
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<int:user_id>/toggle-active', methods=['POST'])
@admin_required
def toggle_active(user_id):
    """Toggle user active status."""
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot deactivate your own account.', 'danger')
        return redirect(url_for('admin.users'))

    user.is_active = not user.is_active
    db.session.commit()
    status = 'activated' if user.is_active else 'deactivated'
    flash(f"{user.full_name}'s account has been {status}.", 'success')
    return redirect(url_for('admin.users'))


@admin_bp.route('/audit-logs')
@admin_required
def audit_logs():
    """Audit logs page."""
    page = request.args.get('page', 1, type=int)
    action_filter = request.args.get('action', '')
    result_filter = request.args.get('result', '')

    action = action_filter if action_filter else None
    result = result_filter if result_filter else None

    logs, total, pages = get_logs_paginated(
        page=page, per_page=50, action=action, result=result
    )

    # Unique actions for filter dropdown
    actions = db.session.query(AuditLog.action).distinct().order_by(AuditLog.action).all()
    actions = [a[0] for a in actions]

    return render_template('admin/audit_logs.html',
                         logs=logs,
                         total=total,
                         pages=pages,
                         current_page=page,
                         actions=actions,
                         action_filter=action_filter,
                         result_filter=result_filter)


@admin_bp.route('/risk-rules')
@admin_required
def risk_rules():
    """Risk rules management page."""
    rules = current_app.config.get('RISK_RULES', {})
    thresholds = current_app.config.get('RISK_THRESHOLDS', {})
    return render_template('admin/risk_rules.html',
                         rules=rules,
                         thresholds=thresholds)


@admin_bp.route('/risk-rules/update', methods=['POST'])
@admin_required
def update_risk_rules():
    """Update risk scoring rules."""
    try:
        new_rules = {
            'new_device': int(request.form.get('new_device', 25)),
            'new_browser': int(request.form.get('new_browser', 20)),
            'new_location': int(request.form.get('new_location', 30)),
            'unusual_time': int(request.form.get('unusual_time', 15)),
            'failed_attempts': int(request.form.get('failed_attempts', 25)),
            'impossible_travel': int(request.form.get('impossible_travel', 40))
        }
        new_thresholds = {
            'low': int(request.form.get('low_threshold', 30)),
            'medium': int(request.form.get('medium_threshold', 60))
        }
        current_app.config['RISK_RULES'] = new_rules
        current_app.config['RISK_THRESHOLDS'] = new_thresholds
        flash('Risk rules updated successfully.', 'success')
    except ValueError:
        flash('Invalid values. Please use integers.', 'danger')

    return redirect(url_for('admin.risk_rules'))
