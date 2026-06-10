"""
Auth Service
============
User registration, authentication, password management, MFA.
"""
import re
import secrets
import hashlib
from datetime import datetime, timedelta
from flask import current_app, url_for
from flask_mail import Message
from ..extensions import db, mail
from ..models.user import User
from ..models.session import Session
from ..models.password_reset import PasswordReset
from ..models.email_verification import EmailVerification
from ..models.notification import Notification
from .audit_service import log_action

# Email regex
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

# Password must have: uppercase, lowercase, digit, special char, min 8
PASSWORD_REGEX = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#[^()_+\-=\[\]{};:\\|,.<>/~`])[A-Za-z\d@$!%*?&#[^()_+\-=\[\]{};:\\|,.<>/~`]{8,}$'
)


def validate_email(email: str) -> tuple:
    """Validate email format. Returns (is_valid, error_message)."""
    if not email or not email.strip():
        return False, 'Email is required.'
    if not EMAIL_REGEX.match(email.strip()):
        return False, 'Please enter a valid email address.'
    return True, None


def validate_password(password: str) -> tuple:
    """Validate password complexity. Returns (is_valid, error_message)."""
    if not password:
        return False, 'Password is required.'
    if len(password) < 8:
        return False, 'Password must be at least 8 characters long.'
    if not re.search(r'[a-z]', password):
        return False, 'Password must contain a lowercase letter.'
    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain an uppercase letter.'
    if not re.search(r'\d', password):
        return False, 'Password must contain a number.'
    if not re.search(r'[@$!%*?&#[^()_+\-=\[\]{};:\\|,.<>/~`]', password):
        return False, 'Password must contain a special character.'
    return True, None


def get_password_strength(password: str) -> dict:
    """Calculate password strength score and label."""
    score = 0
    feedback = []
    if len(password) >= 8:
        score += 1
    else:
        feedback.append('Use at least 8 characters')
    if len(password) >= 12:
        score += 1
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append('Add lowercase letters')
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append('Add uppercase letters')
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append('Add numbers')
    if re.search(r'[@$!%*?&#[^()_+\-=\[\]{};:\\|,.<>/~`]', password):
        score += 1
    else:
        feedback.append('Add special characters')

    if score <= 2:
        label = 'Weak'
        color = 'danger'
    elif score <= 4:
        label = 'Fair'
        color = 'warning'
    elif score <= 5:
        label = 'Good'
        color = 'info'
    else:
        label = 'Strong'
        color = 'success'

    return {'score': score, 'max': 6, 'label': label, 'color': color, 'feedback': feedback}


def register_user(full_name: str, email: str, password: str,
                  role: str = 'user') -> tuple:
    """
    Register a new user.
    Returns (user, error_message).
    """
    # Validate inputs
    email = email.strip().lower()
    full_name = full_name.strip()

    if not full_name or len(full_name) < 2:
        return None, 'Full name must be at least 2 characters.'

    valid, msg = validate_email(email)
    if not valid:
        return None, msg

    valid, msg = validate_password(password)
    if not valid:
        return None, msg

    # Check existing user
    existing = User.query.filter_by(email=email).first()
    if existing:
        return None, 'An account with this email already exists.'

    if role not in ('user', 'admin'):
        role = 'user'

    # Create user
    user = User(full_name=full_name, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    # Send verification email
    send_verification_email(user)

    log_action('user_register', user_id=user.id, result='success',
               details={'email': email, 'role': role})

    return user, None


def authenticate_user(email: str, password: str) -> tuple:
    """
    Authenticate a user by email and password.
    Returns (user, error_message).
    """
    email = email.strip().lower()
    if not email or not password:
        return None, 'Email and password are required.'

    user = User.query.filter_by(email=email).first()
    if not user:
        return None, 'Invalid email or password.'

    if not user.is_active:
        return None, 'This account has been deactivated. Contact support.'

    if user.is_account_locked():
        remaining = user.last_failed_login + timedelta(minutes=15) - datetime.utcnow()
        mins = int(remaining.total_seconds() / 60) + 1
        return None, f'Too many failed attempts. Try again in {mins} minute{"s" if mins != 1 else ""}.'

    if not user.check_password(password):
        user.record_failed_login()
        db.session.commit()
        remaining_attempts = max(0, 5 - user.failed_login_count)
        log_action('user_login', user_id=user.id, result='failure',
                   details={'reason': 'invalid_password',
                            'remaining_attempts': remaining_attempts})
        if remaining_attempts > 0:
            return None, f'Invalid password. {remaining_attempts} attempt{"s" if remaining_attempts != 1 else ""} remaining.'
        return None, 'Too many failed attempts. Account locked for 15 minutes.'

    # Success
    user.reset_failed_logins()
    db.session.commit()
    return user, None


def create_session(user_id: int, ip_address: str, user_agent: str,
                   device_info: str = None, browser_info: str = None,
                   location_info: str = None, remember: bool = False) -> Session:
    """Create a new authenticated session."""
    token = secrets.token_urlsafe(48)
    ua_hash = hashlib.sha256(user_agent.encode()).hexdigest() if user_agent else ''

    expiry = timedelta(days=14) if remember else timedelta(hours=24)

    session = Session(
        user_id=user_id,
        session_token=token,
        ip_address=ip_address or '',
        user_agent_hash=ua_hash,
        device_info=device_info,
        browser_info=browser_info,
        location_info=location_info,
        expires_at=datetime.utcnow() + expiry
    )
    db.session.add(session)
    db.session.commit()
    return session


def send_verification_email(user: User) -> bool:
    """Send email verification link."""
    try:
        raw_token = user.generate_email_token()
        token_hash = user.hash_token(raw_token)

        # Invalidate previous tokens
        EmailVerification.query.filter_by(
            user_id=user.id, is_used=False
        ).update({'is_used': True})

        ev = EmailVerification(user_id=user.id, token_hash=token_hash)
        db.session.add(ev)
        db.session.commit()

        verify_url = url_for('auth.verify_email', token=raw_token, _external=True)

        msg = Message(
            subject='Verify Your UPSA Account',
            recipients=[user.email],
            body=(f'Hi {user.full_name},\n\n'
                  f'Thank you for registering with UPSA. '
                  f'Please verify your email by clicking this link:\n\n'
                  f'{verify_url}\n\n'
                  f'This link expires in 48 hours.\n\n'
                  f'If you did not create this account, please ignore this email.\n\n'
                  f'— The UPSA Team'),
            html=(f'<p>Hi {user.full_name},</p>'
                  f'<p>Thank you for registering with UPSA. '
                  f'Please verify your email by clicking the button below:</p>'
                  f'<p><a href="{verify_url}" style="background:#2563EB;color:white;'
                  f'padding:12px 24px;text-decoration:none;border-radius:6px;'
                  f'display:inline-block;">Verify My Email</a></p>'
                  f'<p>This link expires in 48 hours.</p>'
                  f'<p>If you did not create this account, please ignore this email.</p>'
                  f'<p>— The UPSA Team</p>')
        )
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f'Failed to send verification email: {e}')
        return False


def verify_email_token(token: str) -> tuple:
    """Verify an email verification token. Returns (user, error_message)."""
    if not token:
        return None, 'Invalid verification link.'

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    ev = EmailVerification.query.filter_by(
        token_hash=token_hash, is_used=False
    ).first()

    if not ev:
        return None, 'This verification link is invalid or has already been used.'

    if not ev.is_valid():
        return None, 'This verification link has expired. Please request a new one.'

    user = User.query.get(ev.user_id)
    if not user:
        return None, 'User not found.'

    user.email_verified = True
    ev.mark_used()
    db.session.commit()

    log_action('email_verify', user_id=user.id, result='success')
    return user, None


def send_password_reset_email(email: str) -> bool:
    """Send password reset link. Always returns True to prevent enumeration."""
    user = User.query.filter_by(email=email.strip().lower()).first()
    if not user:
        return True  # Don't reveal whether email exists

    try:
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        # Invalidate previous tokens
        PasswordReset.query.filter_by(
            user_id=user.id, is_used=False
        ).update({'is_used': True})

        pr = PasswordReset(user_id=user.id, token_hash=token_hash)
        db.session.add(pr)
        db.session.commit()

        reset_url = url_for('auth.reset_password', token=raw_token, _external=True)

        msg = Message(
            subject='Reset Your UPSA Password',
            recipients=[user.email],
            body=(f'Hi {user.full_name},\n\n'
                  f'You requested a password reset. Click this link to set a new password:\n\n'
                  f'{reset_url}\n\n'
                  f'This link expires in 24 hours.\n\n'
                  f'If you did not request this, please ignore this email.\n\n'
                  f'— The UPSA Team'),
            html=(f'<p>Hi {user.full_name},</p>'
                  f'<p>You requested a password reset. Click the button below to set a new password:</p>'
                  f'<p><a href="{reset_url}" style="background:#DC2626;color:white;'
                  f'padding:12px 24px;text-decoration:none;border-radius:6px;'
                  f'display:inline-block;">Reset Password</a></p>'
                  f'<p>This link expires in 24 hours.</p>'
                  f'<p>If you did not request this, please ignore this email.</p>'
                  f'<p>— The UPSA Team</p>')
        )
        mail.send(msg)

        log_action('password_reset_request', user_id=user.id, result='success')
        return True
    except Exception as e:
        current_app.logger.error(f'Failed to send password reset email: {e}')
        return True


def reset_password_with_token(token: str, new_password: str) -> tuple:
    """Reset password using a valid token. Returns (success, message)."""
    if not token:
        return False, 'Invalid reset link.'

    valid, msg = validate_password(new_password)
    if not valid:
        return False, msg

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    pr = PasswordReset.query.filter_by(
        token_hash=token_hash, is_used=False
    ).first()

    if not pr or not pr.is_valid():
        return False, 'This reset link is invalid or has expired.'

    user = User.query.get(pr.user_id)
    if not user:
        return False, 'User not found.'

    user.set_password(new_password)
    pr.mark_used()
    db.session.commit()

    # Invalidate all other sessions for security
    Session.query.filter_by(user_id=user.id, is_active=True).update({'is_active': False})
    db.session.commit()

    log_action('password_reset_complete', user_id=user.id, result='success')
    return True, 'Your password has been reset. Please sign in with your new password.'


def change_password(user: User, old_password: str, new_password: str) -> tuple:
    """Change password with old password verification."""
    if not user.check_password(old_password):
        return False, 'Current password is incorrect.'

    valid, msg = validate_password(new_password)
    if not valid:
        return False, msg

    user.set_password(new_password)
    db.session.commit()

    log_action('password_change', user_id=user.id, result='success')
    return True, 'Password updated successfully.'


def toggle_mfa(user: User, enable: bool) -> tuple:
    """Enable or disable MFA for a user."""
    user.mfa_enabled = enable
    db.session.commit()

    action = 'mfa_enable' if enable else 'mfa_disable'
    log_action(action, user_id=user.id, result='success')

    # Create notification
    notif = Notification(
        user_id=user.id,
        title='MFA ' + ('Enabled' if enable else 'Disabled'),
        message=('Multi-factor authentication has been enabled on your account. '
                 'You will be asked for a verification code when logging in from new devices.'
                 if enable else
                 'Multi-factor authentication has been disabled. '
                 'Your account now relies only on your password for protection.'),
        type='info' if enable else 'warning'
    )
    db.session.add(notif)
    db.session.commit()

    status = 'enabled' if enable else 'disabled'
    return True, f'Multi-factor authentication has been {status}.'


def generate_mfa_code(user_id: int) -> str:
    """Generate and store a 6-digit MFA code."""
    import random
    code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    # Store in a simple in-memory cache or use the database
    # For simplicity, we'll store as a temporary notification or use session
    from flask import session as flask_session
    flask_session[f'mfa_code_{user_id}'] = code
    flask_session[f'mfa_code_expiry_{user_id}'] = (
        datetime.utcnow() + timedelta(minutes=5)).isoformat()
    return code


def verify_mfa_code(user_id: int, code: str) -> bool:
    """Verify an MFA code."""
    from flask import session as flask_session
    stored = flask_session.get(f'mfa_code_{user_id}')
    expiry_str = flask_session.get(f'mfa_code_expiry_{user_id}')
    if not stored or not expiry_str:
        return False
    expiry = datetime.fromisoformat(expiry_str)
    if datetime.utcnow() > expiry:
        return False
    if stored != code:
        return False
    # Clear used code
    flask_session.pop(f'mfa_code_{user_id}', None)
    flask_session.pop(f'mfa_code_expiry_{user_id}', None)
    return True


def send_mfa_code_email(user: User, code: str) -> bool:
    """
    Send MFA code via email.
    
    DEVELOPMENT/TESTING CONFIGURATION:
    For development and testing convenience, the MFA code is also printed directly to the terminal.
    
    PRODUCTION CONFIGURATION:
    To ensure proper delivery of MFA codes to users' actual email addresses (mailing addresses)
    in production:
    1. Set the environment variable `FLASK_ENV` to 'production' (which configures `DEBUG = False`).
    2. Configure the mail server settings in your production environment (e.g. `MAIL_SERVER`, 
       `MAIL_PORT`, `MAIL_USE_TLS`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_DEFAULT_SENDER`).
    """
    # Print the MFA code to the terminal for development and testing purposes
    print(f"\n[DEV/TEST] MFA Code for {user.email}: {code}\n")
    
    try:
        msg = Message(
            subject='Your UPSA Verification Code',
            recipients=[user.email],
            body=(f'Hi {user.full_name},\n\n'
                  f'Your verification code is: {code}\n\n'
                  f'This code expires in 5 minutes.\n\n'
                  f'If you did not request this code, please secure your account immediately.\n\n'
                  f'— The UPSA Team'),
            html=(f'<p>Hi {user.full_name},</p>'
                  f'<p>Your verification code is:</p>'
                  f'<p style="font-size:24px;font-weight:bold;letter-spacing:4px;'
                  f'background:#f0f0f0;padding:12px 24px;display:inline-block;'
                  f'border-radius:4px;">{code}</p>'
                  f'<p>This code expires in 5 minutes.</p>'
                  f'<p>If you did not request this code, please secure your account immediately.</p>'
                  f'<p>— The UPSA Team</p>')
        )
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f'Failed to send MFA code: {e}')
        return False


def get_active_session_count(user_id: int) -> int:
    """Count active non-expired sessions for a user."""
    return Session.query.filter_by(
        user_id=user_id, is_active=True
    ).filter(Session.expires_at > datetime.utcnow()).count()
