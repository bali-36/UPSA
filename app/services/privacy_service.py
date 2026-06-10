"""
Privacy Service
===============
Calculates privacy health scores and security scores.
"""
from datetime import datetime, timedelta
from flask import current_app
from ..extensions import db
from ..models.privacy_score import PrivacyScore
from ..models.recommendation import Recommendation
from ..models.notification import Notification
from ..models.survey_response import SurveyResponse
from .audit_service import log_action


def seed_default_permissions(user_id: int) -> None:
    """Seed default website permissions for a user if they do not exist."""
    from ..models.website_permission import WebsitePermission
    if WebsitePermission.query.filter_by(user_id=user_id).count() > 0:
        return

    defaults = [
        ('maps.google.com', 'location', 'navigation', 'Used to show maps and routes'),
        ('meet.google.com', 'camera', 'communication', 'Used for video conferencing'),
        ('meet.google.com', 'microphone', 'communication', 'Used for voice conferencing'),
        ('weather.com', 'location', 'weather', 'Used to show local weather forecast'),
        ('coolmathgames.com', 'location', 'gaming', 'Requests location for ads targeting'),
        ('arcade.gaming.com', 'camera', 'gaming', 'Requests camera for avatar customization'),
        ('cheapdeals.com', 'notification', 'shopping', 'Shows sales notifications'),
        ('adtrack.net', 'location', 'ads', 'Tracks location for targeted advertising'),
        ('socialconnect.com', 'microphone', 'social', 'Allows audio messages')
    ]

    for website, perm_type, cat, desc in defaults:
        perm = WebsitePermission(
            user_id=user_id,
            website=website,
            permission_type=perm_type,
            category=cat,
            description=desc,
            is_allowed=True
        )
        db.session.add(perm)
    db.session.commit()


def calculate_privacy_score(user_id: int, user=None) -> PrivacyScore:
    """
    Calculate the complete privacy health score for a user.
    Returns the new PrivacyScore record.
    """
    from ..models.user import User
    if user is None:
        user = User.query.get(user_id)

    # Seed default permissions if they don't exist
    seed_default_permissions(user_id)

    # Get latest survey response
    latest_survey = SurveyResponse.query.filter_by(user_id=user_id).order_by(
        SurveyResponse.completed_at.desc()
    ).first()

    # 1. MFA Score (0-20)
    mfa_score = 20 if user.mfa_enabled else 0

    # 2. Password Strength Score (0-25)
    password_strength_score = getattr(user, 'password_strength', 15) or 15

    # Password Age Score (0-15)
    password_age_days = 999
    if user.password_changed_at:
        password_age_days = (datetime.utcnow() - user.password_changed_at).days
    elif user.created_at:
        password_age_days = (datetime.utcnow() - user.created_at).days

    if password_age_days < 90:
        password_age_score = 15
    elif password_age_days < 180:
        password_age_score = 8
    else:
        password_age_score = 0

    # 3-6. Website Browser Permissions Scoring
    from ..models.website_permission import WebsitePermission
    allowed_perms = WebsitePermission.query.filter_by(user_id=user_id, is_allowed=True).all()
    inappropriate_perms = [p for p in allowed_perms if not p.is_contextually_appropriate]

    bad_location = sum(1 for p in inappropriate_perms if p.permission_type == 'location')
    bad_cam_mic = sum(1 for p in inappropriate_perms if p.permission_type in ('camera', 'microphone'))
    bad_notif = sum(1 for p in inappropriate_perms if p.permission_type == 'notification')

    # Browser Permissions Score (0-15)
    browser_perm_score = max(0, 15 - len(inappropriate_perms) * 3)

    # Location Permissions Score (0-10)
    location_perm_score = max(0, 10 - bad_location * 3)

    # Camera & Microphone (0-5)
    cam_mic_score = max(0, 5 - bad_cam_mic * 2)

    # Notification Permissions Score (0-5)
    notification_score = max(0, 5 - bad_notif * 2)

    # 7. Survey Score (0-15)
    if latest_survey:
        survey_normalized = min(15, int(latest_survey.awareness_score / 100 * 15))
    else:
        survey_normalized = 0

    # Calculate overall score
    raw_sum = (mfa_score + password_strength_score + password_age_score +
               browser_perm_score + location_perm_score + cam_mic_score +
               notification_score + survey_normalized)

    # Calculate overall score as a normalized percentage of the maximum possible points (110)
    overall = int(round((raw_sum / 110) * 100))

    # Determine risk category
    if overall >= 71:
        risk_category = 'low'
    elif overall >= 41:
        risk_category = 'medium'
    else:
        risk_category = 'high'

    score = PrivacyScore(
        user_id=user_id,
        overall_score=overall,
        mfa_score=mfa_score,
        password_strength_score=password_strength_score,
        password_age_score=password_age_score,
        browser_perm_score=browser_perm_score,
        location_perm_score=location_perm_score,
        cam_mic_score=cam_mic_score,
        notification_score=notification_score,
        survey_score=survey_normalized,
        risk_category=risk_category
    )
    db.session.add(score)
    db.session.commit()

    # Generate/update recommendations based on score
    _generate_recommendations(user_id, score)

    log_action('privacy_score_update', user_id=user_id, result='success',
               details={'score': overall, 'category': risk_category})

    return score


def get_latest_privacy_score(user_id: int) -> PrivacyScore:
    """Get the most recent privacy score for a user."""
    return PrivacyScore.query.filter_by(user_id=user_id).order_by(
        PrivacyScore.recorded_at.desc()
    ).first()


def get_privacy_score_history(user_id: int, days: int = 30) -> list:
    """Get privacy score history for charting."""
    since = datetime.utcnow() - timedelta(days=days)
    scores = PrivacyScore.query.filter(
        PrivacyScore.user_id == user_id,
        PrivacyScore.recorded_at >= since
    ).order_by(PrivacyScore.recorded_at).all()

    # Deduplicate by date (keep latest per day)
    by_date = {}
    for s in scores:
        date_key = s.recorded_at.strftime('%Y-%m-%d')
        by_date[date_key] = s

    return [
        {'date': d, 'score': s.overall_score, 'category': s.risk_category}
        for d, s in sorted(by_date.items())
    ]


def calculate_security_score(user_id: int, user=None) -> dict:
    """
    Calculate the security score (separate from privacy score).
    Returns a dict with components.
    """
    from ..models.user import User
    if user is None:
        user = User.query.get(user_id)

    latest_survey = SurveyResponse.query.filter_by(user_id=user_id).order_by(
        SurveyResponse.completed_at.desc()
    ).first()

    # MFA (30 points)
    mfa = 30 if user.mfa_enabled else 0

    # Password Age (25 points)
    pwd_age_days = 999
    if user.password_changed_at:
        pwd_age_days = (datetime.utcnow() - user.password_changed_at).days
    if pwd_age_days < 90:
        pwd_age = 25
    elif pwd_age_days < 180:
        pwd_age = 15
    else:
        pwd_age = 0

    # Survey (30 points)
    survey = 0
    if latest_survey:
        survey = int(latest_survey.awareness_score / 100 * 30)

    # Risk history (15 points) - clean record = full points
    from ..models.risk_event import RiskEvent
    recent_blocks = RiskEvent.query.filter_by(
        user_id=user_id, result='blocked'
    ).filter(
        RiskEvent.created_at >= datetime.utcnow() - timedelta(days=30)
    ).count()
    risk_history = max(0, 15 - recent_blocks * 5)

    total = mfa + pwd_age + survey + risk_history

    return {
        'total_score': total,
        'mfa': {'score': mfa, 'max': 30},
        'password_age': {'score': pwd_age, 'max': 25, 'days_old': pwd_age_days},
        'survey': {'score': survey, 'max': 30},
        'risk_history': {'score': risk_history, 'max': 15},
        'category': 'low' if total >= 60 else 'medium' if total >= 35 else 'high'
    }


def _generate_recommendations(user_id: int, score: PrivacyScore) -> None:
    """Generate personalized recommendations based on privacy score gaps."""
    # Clear old incomplete recommendations
    Recommendation.query.filter_by(
        user_id=user_id, is_completed=False
    ).delete()

    recs = []

    # MFA recommendation
    if score.mfa_score < 20:
        recs.append(Recommendation(
            user_id=user_id,
            category='mfa',
            title='Enable Multi-Factor Authentication',
            description='Add a second verification step to prevent unauthorized access even if your password is compromised.',
            plain_explanation='Think of MFA like a deadbolt on your door. Even if someone has your key (password), they still can\'t get in without the second lock. It stops 99.9% of account hacks.',
            priority='high',
            impact_estimate=15
        ))

    # Password recommendation
    if score.password_age_score < 15:
        recs.append(Recommendation(
            user_id=user_id,
            category='password',
            title='Update Your Password',
            description='Your password is getting old. Regularly updating your password reduces the risk of compromise.',
            plain_explanation='Using the same password for a long time gives attackers more chances to guess it. Changing it every 3 months is like getting new locks on your door.',
            priority='high',
            impact_estimate=10
        ))

    if score.password_strength_score < 20:
        recs.append(Recommendation(
            user_id=user_id,
            category='password',
            title='Strengthen Your Password',
            description='Use a longer, more complex password with uppercase, lowercase, numbers, and special characters.',
            plain_explanation='Short or simple passwords are like using a flimsy lock. A strong password with mixed characters is much harder for attackers to crack — think 12+ characters.',
            priority='medium',
            impact_estimate=8
        ))

    # Browser / Website permissions recommendations
    from ..models.website_permission import WebsitePermission
    allowed_perms = WebsitePermission.query.filter_by(user_id=user_id, is_allowed=True).all()
    inappropriate_perms = [p for p in allowed_perms if not p.is_contextually_appropriate]

    for p in inappropriate_perms:
        recs.append(Recommendation(
            user_id=user_id,
            category='permissions',
            title=f"Revoke {p.permission_type.capitalize()} Access for {p.website}",
            description=f"The website {p.website} ({p.category_label}) has been granted {p.permission_type} permission, which is contextually inappropriate and risky.",
            plain_explanation=f"A site like {p.website} ({p.category_label}) does not need access to your {p.permission_type} to function. Revoking it prevents unnecessary data collection.",
            priority='high' if p.permission_type in ('camera', 'microphone') else 'medium',
            impact_estimate=5
        ))

    # Survey recommendation
    if score.survey_score < 10:
        recs.append(Recommendation(
            user_id=user_id,
            category='general',
            title='Complete the Security Awareness Survey',
            description='Take our short survey to get personalized security tips and improve your awareness score.',
            plain_explanation='The survey helps us understand your current security habits so we can give you advice that actually fits your situation. It only takes 2 minutes.',
            priority='low',
            impact_estimate=8
        ))

    # Backup recommendation
    recs.append(Recommendation(
        user_id=user_id,
        category='backup',
        title='Set Up Regular Data Backups',
        description='Ensure your important data is regularly backed up to prevent loss from attacks or device failure.',
        plain_explanation='Backups are like insurance for your files. If something goes wrong — ransomware, theft, or hardware failure — you won\'t lose everything. Use cloud storage or an external drive.',
        priority='medium',
        impact_estimate=5
    ))

    # Software updates
    recs.append(Recommendation(
        user_id=user_id,
        category='updates',
        title='Keep Software Updated',
        description='Enable automatic updates for your operating system, browser, and apps to patch security vulnerabilities.',
        plain_explanation='Software updates often fix security holes that hackers know how to exploit. Turning on auto-updates is like fixing a broken window — it keeps the bad guys out.',
        priority='medium',
        impact_estimate=5
    ))

    for rec in recs:
        db.session.add(rec)
    db.session.commit()


def get_recommendations(user_id: int, status: str = 'all') -> list:
    """Get recommendations for a user."""
    query = Recommendation.query.filter_by(user_id=user_id)
    if status == 'pending':
        query = query.filter_by(is_completed=False)
    elif status == 'completed':
        query = query.filter_by(is_completed=True)
    return query.order_by(
        db.case(
            (Recommendation.priority == 'high', 1),
            (Recommendation.priority == 'medium', 2),
            (Recommendation.priority == 'low', 3),
            else_=4
        ),
        Recommendation.created_at.desc()
    ).all()


def complete_recommendation(rec_id: int, user_id: int) -> tuple:
    """Mark a recommendation as completed."""
    rec = Recommendation.query.filter_by(id=rec_id, user_id=user_id).first()
    if not rec:
        return False, 'Recommendation not found.'
    if rec.is_completed:
        return False, 'Already completed.'

    rec.mark_completed()

    # Secure the loophole based on the completed recommendation category
    from ..models.user import User
    user = User.query.get(user_id)
    if rec.category == 'mfa':
        if user:
            user.mfa_enabled = True
    elif rec.category == 'password':
        if user:
            user.password_changed_at = datetime.utcnow()
            user.password_strength = 25
    elif rec.category == 'permissions':
        # Find which website permission this matches and revoke it!
        from ..models.website_permission import WebsitePermission
        import re
        match = re.search(r'Revoke (\w+) Access for ([\w.]+)', rec.title)
        if match:
            perm_type = match.group(1).lower()
            website = match.group(2)
            perm = WebsitePermission.query.filter_by(
                user_id=user_id,
                website=website,
                permission_type=perm_type,
                is_allowed=True
            ).first()
            if perm:
                perm.is_allowed = False
        else:
            # Fallback matching for notification
            match_notif = re.search(r'Revoke Notifications for ([\w.]+)', rec.title)
            if match_notif:
                website = match_notif.group(1)
                perm = WebsitePermission.query.filter_by(
                    user_id=user_id,
                    website=website,
                    permission_type='notification',
                    is_allowed=True
                ).first()
                if perm:
                    perm.is_allowed = False

    db.session.commit()

    # Recalculate privacy score
    calculate_privacy_score(user_id)

    log_action('recommendation_complete', user_id=user_id, result='success',
               details={'recommendation_id': rec_id, 'category': rec.category})

    return True, 'Great job! Your privacy score has been updated.'


def seed_analytics_history(user_id: int) -> None:
    """Seed realistic historical data for a user if they are new or have minimal history."""
    from ..models.privacy_score import PrivacyScore
    from ..models.risk_event import RiskEvent
    from ..models.audit_log import AuditLog
    from ..models.frustration_metric import FrustrationMetric
    from ..models.user import User
    import random
    import json

    # Check if we already have seeded history (using PrivacyScore as proxy)
    score_count = PrivacyScore.query.filter_by(user_id=user_id).count()
    if score_count >= 60:
        return

    user = User.query.get(user_id)
    if not user:
        return

    # Get current privacy score to anchor history
    current_score_rec = get_latest_privacy_score(user_id)
    if not current_score_rec:
        current_score_rec = calculate_privacy_score(user_id, user)

    base_score = current_score_rec.overall_score
    mfa_score = current_score_rec.mfa_score
    password_strength_score = current_score_rec.password_strength_score
    password_age_score = current_score_rec.password_age_score
    browser_perm_score = current_score_rec.browser_perm_score
    location_perm_score = current_score_rec.location_perm_score
    cam_mic_score = current_score_rec.cam_mic_score
    notification_score = current_score_rec.notification_score
    survey_score = current_score_rec.survey_score
    risk_category = current_score_rec.risk_category

    # We will generate data points for the past 180 days
    now = datetime.utcnow()

    # 1. Seed PrivacyScore history
    # Delete existing privacy scores for clean seeding of history
    PrivacyScore.query.filter_by(user_id=user_id).delete()

    # Generate scores starting 180 days ago, improving over time
    for i in range(180, -1, -3):  # Every 3 days
        date = now - timedelta(days=i)
        progress = (180 - i) / 180.0
        daily_score = int(base_score - (20 * (1 - progress)) + random.randint(-3, 3))
        daily_score = max(10, min(100, daily_score))

        category = 'low' if daily_score >= 71 else 'medium' if daily_score >= 41 else 'high'

        ps = PrivacyScore(
            user_id=user_id,
            overall_score=daily_score,
            mfa_score=20 if progress > 0.5 and user.mfa_enabled else 0,
            password_strength_score=max(0, password_strength_score - random.randint(0, 5)),
            password_age_score=max(0, password_age_score - random.randint(0, 5)),
            browser_perm_score=max(0, browser_perm_score - random.randint(0, 4)),
            location_perm_score=max(0, location_perm_score - random.randint(0, 3)),
            cam_mic_score=cam_mic_score,
            notification_score=notification_score,
            survey_score=survey_score,
            risk_category=category,
            recorded_at=date
        )
        db.session.add(ps)

    # Add the current score as the latest
    current_rec = PrivacyScore(
        user_id=user_id,
        overall_score=base_score,
        mfa_score=mfa_score,
        password_strength_score=password_strength_score,
        password_age_score=password_age_score,
        browser_perm_score=browser_perm_score,
        location_perm_score=location_perm_score,
        cam_mic_score=cam_mic_score,
        notification_score=notification_score,
        survey_score=survey_score,
        risk_category=risk_category,
        recorded_at=now
    )
    db.session.add(current_rec)

    # 2. Seed RiskEvent history
    # Delete existing risk events
    RiskEvent.query.filter_by(user_id=user_id).delete()

    risk_events_data = [
        (150, 'medium', 'mfa_required', 'MFA verified login from new device.'),
        (130, 'low', 'clean_login', 'Login from trusted device.'),
        (110, 'low', 'clean_login', 'Login from trusted device.'),
        (90, 'medium', 'mfa_required', 'MFA verified login from new device.'),
        (75, 'low', 'clean_login', 'Login from trusted device.'),
        (60, 'low', 'clean_login', 'Login from trusted device.'),
        (45, 'medium', 'mfa_required', 'MFA verified login from new device.'),
        (30, 'low', 'clean_login', 'Login from trusted device.'),
        (25, 'low', 'clean_login', 'Login from trusted device.'),
        (18, 'low', 'clean_login', 'Login from trusted device.'),
        (10, 'medium', 'mfa_required', 'MFA verified login from new device.'),
        (5, 'low', 'clean_login', 'Login from trusted device.'),
        (2, 'low', 'clean_login', 'Login from trusted device.')
    ]

    for days_ago, category, result, details in risk_events_data:
        ev = RiskEvent(
            user_id=user_id,
            event_type='login',
            risk_points=15 if category == 'low' else 45,
            total_score=15 if category == 'low' else 45,
            risk_category=category,
            result=result,
            ip_address='192.168.1.100',
            browser_info='Chrome',
            device_info='Desktop',
            location_info='US',
            explanation=details,
            created_at=now - timedelta(days=days_ago)
        )
        db.session.add(ev)

    # 3. Seed AuditLog history
    # Delete existing login audit logs
    AuditLog.query.filter_by(user_id=user_id).filter(
        AuditLog.action.in_(['user_login', 'login_risk_assessed'])
    ).delete()

    for i in range(180, 0, -1):
        date = now - timedelta(days=i)
        if random.random() < 0.6:  # Logins on 60% of the days
            num_success = random.randint(1, 2)
            num_fail = 1 if random.random() < 0.15 else 0

            for _ in range(num_success):
                log1 = AuditLog(
                    user_id=user_id,
                    action='user_login',
                    result='success',
                    ip_address='127.0.0.1',
                    details_json=json.dumps({'ip': '127.0.0.1'}),
                    created_at=date - timedelta(hours=random.randint(0, 12))
                )
                db.session.add(log1)

            for _ in range(num_fail):
                log2 = AuditLog(
                    user_id=user_id,
                    action='user_login',
                    result='failure',
                    ip_address='127.0.0.1',
                    details_json=json.dumps({'ip': '127.0.0.1', 'reason': 'invalid_password'}),
                    created_at=date - timedelta(hours=random.randint(0, 12))
                )
                db.session.add(log2)

    # 4. Seed FrustrationMetric history
    # Delete existing frustration metrics
    FrustrationMetric.query.filter_by(user_id=user_id).delete()

    frust_levels = ['low', 'medium', 'high']
    for i in range(180, 0, -5):  # Every 5 days
        date = now - timedelta(days=i)
        level = random.choices(frust_levels, weights=[0.7, 0.25, 0.05], k=1)[0]
        fm = FrustrationMetric(
            user_id=user_id,
            login_failures_7d=random.randint(0, 2) if level == 'medium' else random.randint(3, 5) if level == 'high' else 0,
            password_reset_count_7d=0 if level == 'low' else random.randint(0, 1),
            mfa_abandonment_count=random.randint(0, 1) if level == 'medium' else random.randint(2, 3) if level == 'high' else 0,
            avg_login_completion_sec=random.randint(5, 15) if level == 'low' else random.randint(20, 45),
            help_page_visit_count=random.randint(0, 1) if level == 'medium' else random.randint(2, 4) if level == 'high' else 0,
            frustration_level=level,
            recorded_at=date
        )
        db.session.add(fm)

    current_fm = FrustrationMetric(
        user_id=user_id,
        login_failures_7d=0,
        password_reset_count_7d=0,
        mfa_abandonment_count=0,
        avg_login_completion_sec=8,
        help_page_visit_count=0,
        frustration_level='low',
        recorded_at=now
    )
    db.session.add(current_fm)

    db.session.commit()

