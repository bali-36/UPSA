"""
Frustration Service
===================
Tracks user experience friction and adapts security UX accordingly.
"""
from datetime import datetime, timedelta
from ..extensions import db
from ..models.frustration_metric import FrustrationMetric


def record_login_failure(user_id: int) -> None:
    """Record a login failure for frustration tracking."""
    metric = _get_or_create_metric(user_id)
    metric.login_failures_7d += 1
    metric.frustration_level = metric.calculate_level()
    db.session.commit()


def record_password_reset(user_id: int) -> None:
    """Record a password reset request."""
    metric = _get_or_create_metric(user_id)
    metric.password_reset_count_7d += 1
    metric.frustration_level = metric.calculate_level()
    db.session.commit()


def record_mfa_abandonment(user_id: int) -> None:
    """Record when a user starts but doesn't complete MFA."""
    metric = _get_or_create_metric(user_id)
    metric.mfa_abandonment_count += 1
    metric.frustration_level = metric.calculate_level()
    db.session.commit()


def record_help_visit(user_id: int) -> None:
    """Record a visit to the help page."""
    metric = _get_or_create_metric(user_id)
    metric.help_page_visit_count += 1
    metric.frustration_level = metric.calculate_level()
    db.session.commit()


def record_login_completion(user_id: int, seconds: int) -> None:
    """Record how long a login took to complete."""
    metric = _get_or_create_metric(user_id)
    if metric.avg_login_completion_sec is None:
        metric.avg_login_completion_sec = seconds
    else:
        # Rolling average
        metric.avg_login_completion_sec = int(
            (metric.avg_login_completion_sec + seconds) / 2
        )
    db.session.commit()


def get_frustration_status(user_id: int) -> dict:
    """Get the current frustration status with adaptive guidance."""
    metric = _get_or_create_metric(user_id)

    level = metric.frustration_level

    # Generate adaptive guidance based on frustration level
    if level == 'low':
        guidance = {
            'message': 'Your experience has been smooth. Keep up the good security habits!',
            'reduce_mfa': False,
            'extend_session': True,
            'offer_help': False
        }
    elif level == 'medium':
        guidance = {
            'message': ('We noticed you\'ve had some difficulty recently. '
                       'Here are some tips to make things easier.'),
            'reduce_mfa': False,
            'extend_session': True,
            'offer_help': True,
            'tips': [
                'Save this device as trusted to skip MFA next time',
                'Use the password manager to avoid typing errors',
                'Bookmark the login page for quick access'
            ]
        }
    else:  # high
        guidance = {
            'message': ('We\'re sorry you\'ve been frustrated. '
                       'We\'re making some adjustments to improve your experience '
                       'without reducing your security.'),
            'reduce_mfa': True,  # Will extend trusted device period
            'extend_session': True,
            'offer_help': True,
            'tips': [
                'We\'ve extended your trusted session duration',
                'Try saving this browser as a trusted device',
                'Consider using a password manager',
                'Contact support if you need personalized help'
            ],
            'actions': [
                {'label': 'Trust This Device', 'action': 'trust_device'},
                {'label': 'Reset Password', 'action': 'forgot_password'},
                {'label': 'Contact Support', 'action': 'contact_support'}
            ]
        }

    return {
        'level': level,
        'level_label': metric.level_label,
        'metrics': {
            'login_failures_7d': metric.login_failures_7d,
            'password_reset_count_7d': metric.password_reset_count_7d,
            'mfa_abandonment_count': metric.mfa_abandonment_count,
            'avg_login_completion_sec': metric.avg_login_completion_sec,
            'help_page_visit_count': metric.help_page_visit_count
        },
        'guidance': guidance,
        'recorded_at': metric.recorded_at.isoformat() if metric.recorded_at else None
    }


def get_frustration_history(user_id: int, days: int = 30) -> list:
    """Get frustration level history for charting."""
    since = datetime.utcnow() - timedelta(days=days)
    metrics = FrustrationMetric.query.filter(
        FrustrationMetric.user_id == user_id,
        FrustrationMetric.recorded_at >= since
    ).order_by(FrustrationMetric.recorded_at).all()

    level_map = {'low': 1, 'medium': 2, 'high': 3}
    return [
        {
            'date': m.recorded_at.strftime('%Y-%m-%d'),
            'frustration_score': level_map.get(m.frustration_level, 1),
            'level': m.frustration_level
        }
        for m in metrics
    ]


def reset_weekly_counters() -> None:
    """Reset weekly counters (run via scheduled job)."""
    week_ago = datetime.utcnow() - timedelta(days=7)
    FrustrationMetric.query.filter(
        FrustrationMetric.recorded_at < week_ago
    ).update({
        'login_failures_7d': 0,
        'password_reset_count_7d': 0
    })
    db.session.commit()


def _get_or_create_metric(user_id: int) -> FrustrationMetric:
    """Get or create frustration metric for user."""
    metric = FrustrationMetric.query.filter_by(user_id=user_id).order_by(
        FrustrationMetric.recorded_at.desc()
    ).first()

    if not metric:
        metric = FrustrationMetric(user_id=user_id, frustration_level='low')
        db.session.add(metric)
        db.session.commit()

    return metric
