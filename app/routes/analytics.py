"""
Analytics Routes
================
Behavioral analytics dashboard with charts.
"""
from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user
from ..services.privacy_service import get_privacy_score_history
from ..services.risk_engine import get_risk_events
from ..services.frustration_service import get_frustration_history
from ..models.risk_event import RiskEvent
from ..models.audit_log import AuditLog
from ..models.privacy_score import PrivacyScore
from ..models.frustration_metric import FrustrationMetric
from ..extensions import db
from datetime import datetime, timedelta

analytics_bp = Blueprint('analytics', __name__)


@analytics_bp.route('/analytics')
@login_required
def index():
    """Analytics dashboard page."""
    from ..services.privacy_service import seed_analytics_history
    seed_analytics_history(current_user.id)
    return render_template('analytics.html')


@analytics_bp.route('/api/analytics/privacy-trend')
@login_required
def privacy_trend():
    """Get privacy score trend data for Chart.js."""
    view = request.args.get('view', 'daily')
    
    if view == 'monthly':
        days = 180
    elif view == 'weekly':
        days = 90
    else: # daily
        days = 30
        
    since = datetime.utcnow() - timedelta(days=days)
    scores = PrivacyScore.query.filter(
        PrivacyScore.user_id == current_user.id,
        PrivacyScore.recorded_at >= since
    ).order_by(PrivacyScore.recorded_at).all()
    
    data = []
    if view == 'monthly':
        from collections import defaultdict
        by_month = defaultdict(list)
        for s in scores:
            month_key = s.recorded_at.strftime('%Y-%m')
            by_month[month_key].append(s.overall_score)
        for m_key in sorted(by_month.keys()):
            dt = datetime.strptime(m_key, '%Y-%m')
            label = dt.strftime('%b %Y')
            avg_score = int(sum(by_month[m_key]) / len(by_month[m_key]))
            data.append({'date': label, 'score': avg_score})
            
    elif view == 'weekly':
        from collections import defaultdict
        by_week = defaultdict(list)
        for s in scores:
            start_of_week = s.recorded_at - timedelta(days=s.recorded_at.weekday())
            week_key = start_of_week.strftime('%Y-%m-%d')
            by_week[week_key].append(s.overall_score)
        for w_key in sorted(by_week.keys()):
            dt = datetime.strptime(w_key, '%Y-%m-%d')
            label = f"W/C {dt.strftime('%b %d')}"
            avg_score = int(sum(by_week[w_key]) / len(by_week[w_key]))
            data.append({'date': label, 'score': avg_score})
            
    else: # daily
        by_date = {}
        for s in scores:
            date_key = s.recorded_at.strftime('%Y-%m-%d')
            by_date[date_key] = s
        for d_key in sorted(by_date.keys()):
            dt = datetime.strptime(d_key, '%Y-%m-%d')
            label = dt.strftime('%b %d')
            data.append({'date': label, 'score': by_date[d_key].overall_score})
            
    return jsonify({'data': data})


@analytics_bp.route('/api/analytics/risk-trend')
@login_required
def risk_trend():
    """Get risk level trend data."""
    view = request.args.get('view', 'daily')
    
    if view == 'monthly':
        days = 180
    elif view == 'weekly':
        days = 90
    else: # daily
        days = 30
        
    since = datetime.utcnow() - timedelta(days=days)
    events = RiskEvent.query.filter(
        RiskEvent.user_id == current_user.id,
        RiskEvent.created_at >= since
    ).order_by(RiskEvent.created_at).all()

    level_map = {'low': 15, 'medium': 45, 'high': 80}
    data = []
    
    if view == 'monthly':
        from collections import defaultdict
        by_month = defaultdict(list)
        for e in events:
            month_key = e.created_at.strftime('%Y-%m')
            by_month[month_key].append(level_map.get(e.risk_category, 15))
        for m_key in sorted(by_month.keys()):
            dt = datetime.strptime(m_key, '%Y-%m')
            label = dt.strftime('%b %Y')
            avg_score = int(sum(by_month[m_key]) / len(by_month[m_key]))
            data.append({'date': label, 'risk_score': avg_score})
            
    elif view == 'weekly':
        from collections import defaultdict
        by_week = defaultdict(list)
        for e in events:
            start_of_week = e.created_at - timedelta(days=e.created_at.weekday())
            week_key = start_of_week.strftime('%Y-%m-%d')
            by_week[week_key].append(level_map.get(e.risk_category, 15))
        for w_key in sorted(by_week.keys()):
            dt = datetime.strptime(w_key, '%Y-%m-%d')
            label = f"W/C {dt.strftime('%b %d')}"
            avg_score = int(sum(by_week[w_key]) / len(by_week[w_key]))
            data.append({'date': label, 'risk_score': avg_score})
            
    else: # daily
        from collections import defaultdict
        by_date = defaultdict(list)
        for e in events:
            date_key = e.created_at.strftime('%Y-%m-%d')
            by_date[date_key].append(level_map.get(e.risk_category, 15))
        for d_key in sorted(by_date.keys()):
            dt = datetime.strptime(d_key, '%Y-%m-%d')
            label = dt.strftime('%b %d')
            avg_score = int(sum(by_date[d_key]) / len(by_date[d_key]))
            data.append({'date': label, 'risk_score': avg_score})
            
    return jsonify({'data': data})


@analytics_bp.route('/api/analytics/login-activity')
@login_required
def login_activity():
    """Get login activity data (success vs failure)."""
    view = request.args.get('view', 'daily')
    
    if view == 'monthly':
        days = 180
    elif view == 'weekly':
        days = 90
    else: # daily
        days = 30
        
    since = datetime.utcnow() - timedelta(days=days)
    logs = AuditLog.query.filter(
        AuditLog.user_id == current_user.id,
        AuditLog.created_at >= since,
        AuditLog.action.in_(['user_login', 'login_risk_assessed'])
    ).order_by(AuditLog.created_at).all()

    from collections import defaultdict
    data = []
    
    if view == 'monthly':
        by_month = defaultdict(lambda: {'successful': 0, 'failed': 0})
        for log in logs:
            month_key = log.created_at.strftime('%Y-%m')
            if log.result == 'success':
                by_month[month_key]['successful'] += 1
            elif log.result == 'failure':
                by_month[month_key]['failed'] += 1
        for m_key in sorted(by_month.keys()):
            dt = datetime.strptime(m_key, '%Y-%m')
            label = dt.strftime('%b %Y')
            data.append({'date': label, **by_month[m_key]})
            
    elif view == 'weekly':
        by_week = defaultdict(lambda: {'successful': 0, 'failed': 0})
        for log in logs:
            start_of_week = log.created_at - timedelta(days=log.created_at.weekday())
            week_key = start_of_week.strftime('%Y-%m-%d')
            if log.result == 'success':
                by_week[week_key]['successful'] += 1
            elif log.result == 'failure':
                by_week[week_key]['failed'] += 1
        for w_key in sorted(by_week.keys()):
            dt = datetime.strptime(w_key, '%Y-%m-%d')
            label = f"W/C {dt.strftime('%b %d')}"
            data.append({'date': label, **by_week[w_key]})
            
    else: # daily
        by_date = defaultdict(lambda: {'successful': 0, 'failed': 0})
        for log in logs:
            date_key = log.created_at.strftime('%Y-%m-%d')
            if log.result == 'success':
                by_date[date_key]['successful'] += 1
            elif log.result == 'failure':
                by_date[date_key]['failed'] += 1
        for d_key in sorted(by_date.keys()):
            dt = datetime.strptime(d_key, '%Y-%m-%d')
            label = dt.strftime('%b %d')
            data.append({'date': label, **by_date[d_key]})
            
    return jsonify({'data': data})


@analytics_bp.route('/api/analytics/frustration-trend')
@login_required
def frustration_trend():
    """Get frustration trend data."""
    view = request.args.get('view', 'daily')
    
    if view == 'monthly':
        days = 180
    elif view == 'weekly':
        days = 90
    else: # daily
        days = 30
        
    since = datetime.utcnow() - timedelta(days=days)
    metrics = FrustrationMetric.query.filter(
        FrustrationMetric.user_id == current_user.id,
        FrustrationMetric.recorded_at >= since
    ).order_by(FrustrationMetric.recorded_at).all()

    level_map = {'low': 1, 'medium': 2, 'high': 3}
    data = []
    
    if view == 'monthly':
        from collections import defaultdict
        by_month = defaultdict(list)
        for m in metrics:
            month_key = m.recorded_at.strftime('%Y-%m')
            by_month[month_key].append(level_map.get(m.frustration_level, 1))
        for m_key in sorted(by_month.keys()):
            dt = datetime.strptime(m_key, '%Y-%m')
            label = dt.strftime('%b %Y')
            avg_score = round(sum(by_month[m_key]) / len(by_month[m_key]), 1)
            data.append({'date': label, 'frustration_score': avg_score})
            
    elif view == 'weekly':
        from collections import defaultdict
        by_week = defaultdict(list)
        for m in metrics:
            start_of_week = m.recorded_at - timedelta(days=m.recorded_at.weekday())
            week_key = start_of_week.strftime('%Y-%m-%d')
            by_week[week_key].append(level_map.get(m.frustration_level, 1))
        for w_key in sorted(by_week.keys()):
            dt = datetime.strptime(w_key, '%Y-%m-%d')
            label = f"W/C {dt.strftime('%b %d')}"
            avg_score = round(sum(by_week[w_key]) / len(by_week[w_key]), 1)
            data.append({'date': label, 'frustration_score': avg_score})
            
    else: # daily
        by_date = {}
        for m in metrics:
            date_key = m.recorded_at.strftime('%Y-%m-%d')
            by_date[date_key] = m
        for d_key in sorted(by_date.keys()):
            dt = datetime.strptime(d_key, '%Y-%m-%d')
            label = dt.strftime('%b %d')
            m = by_date[d_key]
            data.append({
                'date': label,
                'frustration_score': level_map.get(m.frustration_level, 1)
            })
            
    return jsonify({'data': data})
