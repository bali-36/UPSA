"""
Security Center Routes
======================
Security score, MFA management, password management.
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from ..services.auth_service import toggle_mfa, change_password
from ..services.privacy_service import calculate_security_score

security_bp = Blueprint('security', __name__)


@security_bp.route('/security-center')
@login_required
def index():
    """Security center page."""
    security_score = calculate_security_score(current_user.id, current_user)
    return render_template('security_center.html',
                         security_score=security_score,
                         user=current_user)


@security_bp.route('/security-center/mfa/toggle', methods=['POST'])
@login_required
def toggle_mfa_route():
    """Enable or disable MFA."""
    enable = request.form.get('action') == 'enable'
    success, message = toggle_mfa(current_user, enable)
    flash(message, 'success' if success else 'danger')
    return redirect(url_for('security.index'))


@security_bp.route('/security-center/change-password', methods=['POST'])
@login_required
def change_password_route():
    """Change user password."""
    old_password = request.form.get('old_password', '')
    new_password = request.form.get('new_password', '')
    confirm = request.form.get('confirm_password', '')

    if new_password != confirm:
        flash('New passwords do not match.', 'danger')
        return redirect(url_for('security.index'))

    success, message = change_password(current_user, old_password, new_password)
    flash(message, 'success' if success else 'danger')
    return redirect(url_for('security.index'))
