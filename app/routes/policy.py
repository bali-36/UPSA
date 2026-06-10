"""
Policy Analyzer Routes
======================
Privacy policy upload, analysis, and history.
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from ..services.policy_analyzer import process_upload, process_paste, get_user_reports, get_report

policy_bp = Blueprint('policy', __name__)


@policy_bp.route('/policy-analyzer')
@login_required
def index():
    """Policy analyzer page."""
    reports = get_user_reports(current_user.id)
    return render_template('policy_analyzer.html', reports=reports)


@policy_bp.route('/policy-analyzer/upload', methods=['POST'])
@login_required
def upload():
    """Handle policy file upload."""
    if 'file' not in request.files:
        flash('No file selected.', 'warning')
        return redirect(url_for('policy.index'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected.', 'warning')
        return redirect(url_for('policy.index'))

    report, error = process_upload(current_user.id, file, file.filename)
    if error:
        flash(error, 'danger')
        return redirect(url_for('policy.index'))

    flash('Privacy policy analyzed successfully!', 'success')
    return redirect(url_for('policy.view_report', report_id=report.id))


@policy_bp.route('/policy-analyzer/paste', methods=['POST'])
@login_required
def paste():
    """Handle policy text paste."""
    text = request.form.get('policy_text', '').strip()
    title = request.form.get('policy_title', '').strip()

    if not text:
        flash('No privacy policy text provided.', 'warning')
        return redirect(url_for('policy.index'))

    report, error = process_paste(current_user.id, text, title)
    if error:
        flash(error, 'danger')
        return redirect(url_for('policy.index'))

    flash('Privacy policy analyzed successfully!', 'success')
    return redirect(url_for('policy.view_report', report_id=report.id))


@policy_bp.route('/policy-analyzer/report/<int:report_id>')
@login_required
def view_report(report_id):
    """View a specific policy analysis report."""
    report = get_report(report_id, current_user.id)
    if not report:
        flash('Report not found.', 'danger')
        return redirect(url_for('policy.index'))
    return render_template('policy_report.html', report=report)
