"""
Risk Engine
===========
Adaptive risk-based authentication engine.
Scores login attempts based on device, location, time, and behavior patterns.
"""
import hashlib
from datetime import datetime, timedelta
from flask import current_app
from ..extensions import db
from ..models.trusted_device import TrustedDevice
from ..models.risk_event import RiskEvent
from ..models.frustration_metric import FrustrationMetric
from .audit_service import log_action


# Risk factor point values
DEFAULT_RISK_RULES = {
    'new_device': 25,
    'new_browser': 20,
    'new_location': 30,
    'unusual_time': 15,
    'failed_attempts': 25,
    'impossible_travel': 40
}

# Thresholds
LOW_THRESHOLD = 30
MEDIUM_THRESHOLD = 60

# Time window for "unusual time" (outside 6 AM - 11 PM local)
USUAL_HOURS_START = 6
USUAL_HOURS_END = 23


def _get_rules() -> dict:
    """Get current risk rules from config or defaults."""
    return current_app.config.get('RISK_RULES', DEFAULT_RISK_RULES)


def _get_thresholds() -> dict:
    """Get current risk thresholds from config."""
    return current_app.config.get('RISK_THRESHOLDS',
                                   {'low': LOW_THRESHOLD, 'medium': MEDIUM_THRESHOLD})


def _hash_ua(user_agent: str) -> str:
    """Hash user agent string."""
    if not user_agent:
        return ''
    return hashlib.sha256(user_agent.encode()).hexdigest()


def assess_login_risk(user_id: int, ip_address: str, user_agent: str,
                      device_info: str = None, browser_info: str = None,
                      location_info: str = None) -> dict:
    """
    Assess the risk level of a login attempt.

    Returns a dict with:
    - total_score: integer risk score
    - risk_category: 'low', 'medium', 'high'
    - result: 'allowed', 'mfa_required', 'blocked'
    - factors: list of triggered risk factors with explanations
    - explanation: plain-language summary
    """
    rules = _get_rules()
    thresholds = _get_thresholds()
    ua_hash = _hash_ua(user_agent)
    factors = []
    total_score = 0

    # 1. Check trusted device
    trusted = TrustedDevice.query.filter_by(
        user_id=user_id, user_agent_hash=ua_hash, is_trusted=True
    ).first()

    if not trusted:
        total_score += rules['new_device']
        factors.append({
            'name': 'new_device',
            'label': 'New Device',
            'triggered': True,
            'points': rules['new_device'],
            'explanation': "We don't recognize this device. This is the first time we're seeing it."
        })
    else:
        factors.append({
            'name': 'new_device',
            'label': 'Recognized Device',
            'triggered': False,
            'points': 0,
            'explanation': "This is a device you've used before."
        })
        trusted.last_used_at = datetime.utcnow()

    # 2. Check for new browser (if device is trusted but browser changed)
    if trusted and browser_info and trusted.browser != browser_info:
        total_score += rules['new_browser']
        factors.append({
            'name': 'new_browser',
            'label': 'Different Browser',
            'triggered': True,
            'points': rules['new_browser'],
            'explanation': "You're using a different browser than usual on this device."
        })
    else:
        factors.append({
            'name': 'new_browser',
            'label': 'Recognized Browser',
            'triggered': False,
            'points': 0,
            'explanation': "Your browser looks familiar."
        })

    # 3. Check location
    if trusted and location_info and trusted.location:
        # Simple string comparison - in production, use GeoIP
        if location_info != trusted.location:
            total_score += rules['new_location']
            factors.append({
                'name': 'new_location',
                'label': 'New Location',
                'triggered': True,
                'points': rules['new_location'],
                'explanation': f"You're logging in from {location_info}, which differs from your usual location ({trusted.location})."
            })
        else:
            factors.append({
                'name': 'new_location',
                'label': 'Known Location',
                'triggered': False,
                'points': 0,
                'explanation': "Your location matches what we expect."
            })
    elif not trusted and location_info:
        total_score += rules['new_location']
        factors.append({
            'name': 'new_location',
            'label': 'Unknown Location',
            'triggered': True,
            'points': rules['new_location'],
            'explanation': f"We can't verify this location ({location_info}) since this is a new device."
        })
    else:
        factors.append({
            'name': 'new_location',
            'label': 'Location Check',
            'triggered': False,
            'points': 0,
            'explanation': "Location check skipped."
        })

    # 4. Check unusual time
    hour = datetime.utcnow().hour
    if hour < USUAL_HOURS_START or hour >= USUAL_HOURS_END:
        total_score += rules['unusual_time']
        factors.append({
            'name': 'unusual_time',
            'label': 'Unusual Time',
            'triggered': True,
            'points': rules['unusual_time'],
            'explanation': f"It's {hour}:00 UTC — this is outside typical login hours (6 AM - 11 PM)."
        })
    else:
        factors.append({
            'name': 'unusual_time',
            'label': 'Normal Hours',
            'triggered': False,
            'points': 0,
            'explanation': "Your login time looks normal."
        })

    # 5. Check recent failed attempts
    from ..models.user import User
    user = User.query.get(user_id)
    recent_failures = 0
    if user and user.last_failed_login:
        if datetime.utcnow() - user.last_failed_login < timedelta(hours=1):
            recent_failures = user.failed_login_count

    if recent_failures >= 3:
        total_score += rules['failed_attempts']
        factors.append({
            'name': 'failed_attempts',
            'label': 'Recent Failures',
            'triggered': True,
            'points': rules['failed_attempts'],
            'explanation': f"There have been {recent_failures} failed login attempts recently. This could indicate someone is trying to guess your password."
        })
    else:
        factors.append({
            'name': 'failed_attempts',
            'label': 'Clean Record',
            'triggered': False,
            'points': 0,
            'explanation': "No recent failed login attempts."
        })

    # 6. Impossible travel check
    # Compare with last successful login location and time
    last_session = RiskEvent.query.filter_by(
        user_id=user_id, result='allowed'
    ).order_by(RiskEvent.created_at.desc()).first()

    impossible_travel = False
    if last_session and location_info and last_session.location_info:
        time_diff = datetime.utcnow() - last_session.created_at
        if time_diff < timedelta(hours=2) and location_info != last_session.location_info:
            impossible_travel = True
            total_score += rules['impossible_travel']
            factors.append({
                'name': 'impossible_travel',
                'label': 'Impossible Travel',
                'triggered': True,
                'points': rules['impossible_travel'],
                'explanation': f"You logged in from {last_session.location_info} very recently. Logging in from {location_info} now would require physically impossible travel."
            })

    if not impossible_travel:
        factors.append({
            'name': 'impossible_travel',
            'label': 'No Impossible Travel',
            'triggered': False,
            'points': 0,
            'explanation': "No suspicious travel patterns detected."
        })

    # Determine category and result
    low_thresh = thresholds.get('low', LOW_THRESHOLD)
    med_thresh = thresholds.get('medium', MEDIUM_THRESHOLD)

    if total_score <= low_thresh:
        risk_category = 'low'
        result = 'allowed'
        explanation = ("Everything looks normal. You're logging in from a familiar setup, "
                       "so we're letting you through without extra steps.")
    elif total_score <= med_thresh:
        risk_category = 'medium'
        result = 'mfa_required'
        explanation = ("We noticed something slightly unusual — maybe a new device or location. "
                       "Just to be safe, we'll send a quick code to your email to confirm it's really you.")
    else:
        risk_category = 'high'
        result = 'blocked'
        explanation = ("This login raised several red flags — new device, unusual location, "
                       "and possibly suspicious timing combined. For your protection, we've blocked it. "
                       "Please try logging in from a device and location you normally use, or contact support.")

    # Record risk event
    risk_event = RiskEvent(
        user_id=user_id,
        event_type='login_risk_assessment',
        risk_points=total_score,
        total_score=total_score,
        risk_category=risk_category,
        device_info=device_info,
        browser_info=browser_info,
        location_info=location_info,
        ip_address=ip_address or '',
        result=result,
        explanation=explanation
    )
    db.session.add(risk_event)
    db.session.commit()

    log_action('login_risk_assessed', user_id=user_id, result='info',
               details={'risk_score': total_score, 'category': risk_category,
                        'result': result})

    return {
        'total_score': total_score,
        'risk_category': risk_category,
        'result': result,
        'factors': factors,
        'explanation': explanation,
        'risk_event_id': risk_event.id
    }


def trust_device(user_id: int, user_agent: str, device_name: str,
                 browser: str, os_name: str = None, ip_address: str = None,
                 location: str = None) -> TrustedDevice:
    """Mark a device as trusted for a user."""
    ua_hash = _hash_ua(user_agent)

    # Check if device already exists
    existing = TrustedDevice.query.filter_by(
        user_id=user_id, user_agent_hash=ua_hash
    ).first()

    if existing:
        existing.is_trusted = True
        existing.last_used_at = datetime.utcnow()
        if location:
            existing.location = location
        db.session.commit()
        return existing

    device = TrustedDevice(
        user_id=user_id,
        device_name=device_name,
        browser=browser,
        operating_system=os_name,
        ip_address=ip_address or '',
        location=location,
        user_agent_hash=ua_hash,
        is_trusted=True
    )
    db.session.add(device)
    db.session.commit()
    return device


def untrust_device(device_id: int, user_id: int) -> bool:
    """Remove trust from a device."""
    device = TrustedDevice.query.filter_by(
        id=device_id, user_id=user_id
    ).first()
    if not device:
        return False
    device.is_trusted = False
    db.session.commit()
    return True


def get_user_devices(user_id: int) -> list:
    """Get all devices for a user."""
    return TrustedDevice.query.filter_by(user_id=user_id).order_by(
        TrustedDevice.last_used_at.desc()
    ).all()


def get_risk_events(user_id: int, page: int = 1, per_page: int = 10) -> tuple:
    """Get paginated risk events for a user."""
    pagination = RiskEvent.query.filter_by(user_id=user_id).order_by(
        RiskEvent.created_at.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    return pagination.items, pagination.total, pagination.pages


def get_current_risk_status(user_id: int) -> dict:
    """Get the current risk status summary for a user."""
    latest = RiskEvent.query.filter_by(user_id=user_id).order_by(
        RiskEvent.created_at.desc()
    ).first()

    if not latest:
        return {
            'current_level': 'low',
            'current_score': 0,
            'explanation': "No risk events recorded yet. Your risk level is low by default.",
            'factors': []
        }

    # Build factor list from latest event
    return {
        'current_level': latest.risk_category,
        'current_score': latest.total_score,
        'explanation': latest.explanation,
        'factors': []
    }
