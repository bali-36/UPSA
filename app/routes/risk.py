"""
Risk Center Routes
==================
Risk status, trusted devices, risk event history.
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from ..services.risk_engine import (
    get_current_risk_status, get_risk_events, get_user_devices,
    trust_device, untrust_device
)

risk_bp = Blueprint('risk', __name__)


@risk_bp.route('/risk-center')
@login_required
def index():
    """Risk center page."""
    user_id = current_user.id

    risk_status = get_current_risk_status(user_id)

    # Risk events
    page = request.args.get('page', 1, type=int)
    events, total, pages = get_risk_events(user_id, page=page, per_page=10)

    # Trusted devices
    devices = get_user_devices(user_id)

    return render_template('risk_center.html',
                         risk_status=risk_status,
                         events=events,
                         total_events=total,
                         pages=pages,
                         current_page=page,
                         devices=devices)


@risk_bp.route('/risk-center/trust-device', methods=['POST'])
@login_required
def add_trusted_device():
    """Add current device as trusted."""
    from flask import request
    user_agent = request.headers.get('User-Agent', '')
    ip_address = request.remote_addr or ''

    device_name = request.form.get('device_name', 'My Device')
    browser = request.form.get('browser', 'Unknown')
    location = request.form.get('location', 'Unknown')

    trust_device(
        current_user.id, user_agent, device_name,
        browser, ip_address=ip_address, location=location
    )
    flash('This device has been added to your trusted devices.', 'success')
    return redirect(url_for('risk.index'))


@risk_bp.route('/risk-center/devices/<int:device_id>/toggle', methods=['POST'])
@login_required
def toggle_device(device_id):
    """Toggle device trust status."""
    is_trusted = request.form.get('is_trusted') == 'true'
    if is_trusted:
        device = untrust_device(device_id, current_user.id)
        flash('Device trust removed.', 'info')
    else:
        flash('Use the Trust Device button to add trust.', 'info')
    return redirect(url_for('risk.index'))
