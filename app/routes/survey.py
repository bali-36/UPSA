"""
Survey Center Routes
====================
Security awareness survey and SUS evaluation.
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from ..services.survey_service import (
    get_survey_questions, get_sus_questions,
    submit_awareness_survey, submit_sus_survey,
    get_latest_survey_response, get_latest_sus_response
)

survey_bp = Blueprint('survey', __name__)


@survey_bp.route('/survey-center')
@login_required
def index():
    """Survey center page."""
    latest_survey = get_latest_survey_response(current_user.id)
    latest_sus = get_latest_sus_response(current_user.id)
    return render_template('survey_center.html',
                         latest_survey=latest_survey,
                         latest_sus=latest_sus)


@survey_bp.route('/survey-center/security-awareness', methods=['GET', 'POST'])
@login_required
def security_survey():
    """Security awareness survey."""
    if request.method == 'POST':
        answers = {k: v for k, v in request.form.items() if k.startswith('q')}
        response, result = submit_awareness_survey(current_user.id, answers)
        if result.get('error'):
            flash(result['error'], 'danger')
            questions = get_survey_questions()
            return render_template('security_survey.html', questions=questions)
        flash(result['message'], 'success')
        return redirect(url_for('survey.survey_results'))

    questions = get_survey_questions()
    return render_template('security_survey.html', questions=questions)


@survey_bp.route('/survey-center/sus', methods=['GET', 'POST'])
@login_required
def sus_survey():
    """System Usability Scale evaluation."""
    if request.method == 'POST':
        answers = {k: int(v) for k, v in request.form.items() if k.startswith('q')}
        response, result = submit_sus_survey(current_user.id, answers)
        if result.get('error'):
            flash(result['error'], 'danger')
            questions = get_sus_questions()
            return render_template('sus_survey.html', questions=questions)
        flash(result['message'], 'success')
        return redirect(url_for('survey.sus_results'))

    questions = get_sus_questions()
    return render_template('sus_survey.html', questions=questions)


@survey_bp.route('/survey-center/results')
@login_required
def survey_results():
    """Survey results page."""
    survey = get_latest_survey_response(current_user.id)
    return render_template('survey_results.html', survey=survey)


@survey_bp.route('/survey-center/sus-results')
@login_required
def sus_results():
    """SUS results page."""
    sus = get_latest_sus_response(current_user.id)
    return render_template('sus_results.html', sus=sus)
