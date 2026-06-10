"""
Auth Routes
===========
Registration, login, logout, password reset, email verification, MFA.
"""
import hashlib
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from ..services import auth_service, risk_engine as risk_svc
from ..services.frustration_service import record_login_failure, record_mfa_abandonment
from ..extensions import db

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page."""
    if current_user.is_authenticated:
        from .dashboard import index as dashboard_index
        return dashboard_index()

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('auth/register.html')

        user, error = auth_service.register_user(full_name, email, password)
        if error:
            flash(error, 'danger')
            return render_template('auth/register.html')

        flash('Account created successfully! Please check your email to verify your address.', 'success')
        return login()

    return render_template('auth/register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login page with risk-based authentication."""
    if current_user.is_authenticated:
        from .dashboard import index as dashboard_index
        return dashboard_index()

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember_me') == 'on'

        # Authenticate
        user, error = auth_service.authenticate_user(email, password)
        if error:
            flash(error, 'danger')
            if user:
                record_login_failure(user.id)
            return render_template('auth/login.html')

        # Risk-based authentication
        ip_address = request.remote_addr or ''
        user_agent = request.headers.get('User-Agent', '')
        device_info = _parse_device(user_agent)
        browser_info = _parse_browser(user_agent)
        location_info = 'Unknown'  # In production, use GeoIP

        risk_result = risk_svc.assess_login_risk(
            user.id, ip_address, user_agent,
            device_info=device_info, browser_info=browser_info,
            location_info=location_info
        )

        if risk_result['result'] == 'blocked':
            flash(risk_result['explanation'], 'danger')
            return render_template('auth/login.html')

        if risk_result['result'] == 'mfa_required':
            # Store pending login in session
            session['pending_login_user_id'] = user.id
            session['pending_login_remember'] = remember
            session['pending_login_risk'] = risk_result

            # Generate and send MFA code
            code = auth_service.generate_mfa_code(user.id)
            auth_service.send_mfa_code_email(user, code)

            flash('We sent a verification code to your email. Please enter it below.', 'info')
            return mfa_verify()

        # Low risk — login directly
        _complete_login(user, ip_address, user_agent, device_info, browser_info, location_info, remember)
        flash(f'Welcome back, {user.full_name}!', 'success')
        from .dashboard import index as dashboard_index
        return dashboard_index()

    return render_template('auth/login.html')


@auth_bp.route('/mfa-verify', methods=['GET', 'POST'])
def mfa_verify():
    """MFA verification page for medium-risk logins."""
    pending_user_id = session.get('pending_login_user_id')
    if not pending_user_id:
        flash('Session expired. Please log in again.', 'warning')
        return login()

    from ..models.user import User
    user = User.query.get(pending_user_id)
    if not user:
        flash('User not found.', 'danger')
        return login()

    if request.method == 'POST':
        code = request.form.get('mfa_code', '').strip()
        if auth_service.verify_mfa_code(user.id, code):
            # Clear pending state
            risk_data = session.pop('pending_login_risk', {})
            remember = session.pop('pending_login_remember', False)
            session.pop('pending_login_user_id', None)

            ip_address = request.remote_addr or ''
            user_agent = request.headers.get('User-Agent', '')
            device_info = _parse_device(user_agent)
            browser_info = _parse_browser(user_agent)
            location_info = 'Unknown'

            _complete_login(user, ip_address, user_agent, device_info,
                          browser_info, location_info, remember)

            flash('Login successful! Your device has been verified.', 'success')
            from .dashboard import index as dashboard_index
            return dashboard_index()
        else:
            record_mfa_abandonment(user.id)
            flash('Invalid or expired verification code. Please try again.', 'danger')

    return render_template('auth/mfa_verify.html', user=user)


@auth_bp.route('/logout')
def logout():
    """Log out the current user."""
    if current_user.is_authenticated:
        # Deactivate session
        from ..models.session import Session
        session_token = session.get('session_token')
        if session_token:
            sess = Session.query.filter_by(session_token=session_token).first()
            if sess:
                sess.deactivate()
                db.session.commit()

        logout_user()
        session.pop('session_token', None)
        flash('You have been signed out.', 'info')
    
    return render_template('landing.html')


@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Forgot password page."""
    if current_user.is_authenticated:
        from .dashboard import index as dashboard_index
        return dashboard_index()

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        auth_service.send_password_reset_email(email)
        flash('If an account exists with that email, we have sent a password reset link.', 'info')
        return login()

    return render_template('auth/forgot_password.html')


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Password reset page with token validation."""
    if current_user.is_authenticated:
        from .dashboard import index as dashboard_index
        return dashboard_index()

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('auth/reset_password.html', token=token)

        success, message = auth_service.reset_password_with_token(token, password)
        if success:
            flash(message, 'success')
            return login()
        else:
            flash(message, 'danger')

    return render_template('auth/reset_password.html', token=token)


@auth_bp.route('/verify-email/<token>')
def verify_email(token):
    """Email verification endpoint."""
    user, error = auth_service.verify_email_token(token)
    if error:
        flash(error, 'danger')
        return login()

    flash('Your email has been verified! You can now log in.', 'success')
    return login()


@auth_bp.route('/verify', methods=['GET', 'POST'])
def verify_redirect():
    """Redirect /auth/verify to /auth/mfa-verify for compatibility/fixes."""
    return redirect(url_for('auth.mfa_verify'))


def _complete_login(user, ip_address, user_agent, device_info,
                    browser_info, location_info, remember):
    """Complete the login process by creating a session and logging in."""
    sess = auth_service.create_session(
        user.id, ip_address, user_agent,
        device_info=device_info, browser_info=browser_info,
        location_info=location_info, remember=remember
    )
    session['session_token'] = sess.session_token
    login_user(user, remember=remember)
    user.reset_failed_logins()
    db.session.commit()


def _parse_device(user_agent: str) -> str:
    """Parse device info from user agent."""
    ua = user_agent.lower()
    if 'windows' in ua:
        return 'Windows PC'
    elif 'macintosh' in ua or 'mac os' in ua:
        return 'Mac'
    elif 'linux' in ua:
        return 'Linux PC'
    elif 'iphone' in ua:
        return 'iPhone'
    elif 'ipad' in ua:
        return 'iPad'
    elif 'android' in ua:
        return 'Android Device'
    return 'Unknown Device'


def _parse_browser(user_agent: str) -> str:
    """Parse browser info from user agent."""
    ua = user_agent.lower()
    if 'chrome' in ua and 'edg' not in ua:
        return 'Chrome'
    elif 'firefox' in ua:
        return 'Firefox'
    elif 'safari' in ua and 'chrome' not in ua:
        return 'Safari'
    elif 'edg' in ua:
        return 'Edge'
    elif 'opera' in ua:
        return 'Opera'
    return 'Unknown Browser'
