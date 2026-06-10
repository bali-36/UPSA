"""
Survey Service
==============
Handles security awareness surveys and SUS evaluations.
"""
from datetime import datetime
from ..extensions import db
from ..models.survey_response import SurveyResponse
from ..models.sus_response import SUSResponse
from ..models.privacy_score import PrivacyScore
from .privacy_service import calculate_privacy_score
from .ml_service import predict
from .audit_service import log_action


# Security Awareness Survey Questions
SURVEY_QUESTIONS = [
    {
        'id': 'q1',
        'text': 'How often do you reuse the same password across different websites?',
        'options': [
            {'value': 1, 'label': 'Always — I use the same password everywhere'},
            {'value': 2, 'label': 'Often — I reuse passwords for most sites'},
            {'value': 3, 'label': 'Sometimes — I reuse for a few less important sites'},
            {'value': 4, 'label': 'Never — I use a unique password for every site'}
        ]
    },
    {
        'id': 'q2',
        'text': 'Do you use multi-factor authentication when available?',
        'options': [
            {'value': 1, 'label': 'Never — I find it too inconvenient'},
            {'value': 2, 'label': 'Rarely — Only if forced by the service'},
            {'value': 3, 'label': 'On important accounts — Banking, email, etc.'},
            {'value': 4, 'label': 'On all accounts — Whenever it\'s offered'}
        ]
    },
    {
        'id': 'q3',
        'text': 'How do you verify that an email is legitimate before clicking links?',
        'options': [
            {'value': 1, 'label': 'I click links to see where they go'},
            {'value': 2, 'label': 'I check the sender display name'},
            {'value': 3, 'label': 'I check the actual email address and look for signs of fraud'},
            {'value': 4, 'label': 'I never click links in emails — I go directly to the website'}
        ]
    },
    {
        'id': 'q4',
        'text': 'What do you do when a website asks for permission to access your location?',
        'options': [
            {'value': 1, 'label': 'Always allow — I don\'t mind sharing my location'},
            {'value': 2, 'label': 'Usually allow — If I trust the website'},
            {'value': 3, 'label': 'Sometimes deny — I think about whether it\'s needed'},
            {'value': 4, 'label': 'Always deny — Websites rarely need my location'}
        ]
    },
    {
        'id': 'q5',
        'text': 'How often do you review the privacy settings on your social media accounts?',
        'options': [
            {'value': 1, 'label': 'Never — I never change privacy settings'},
            {'value': 2, 'label': 'Once a year — If I remember'},
            {'value': 3, 'label': 'Every few months — When something prompts me'},
            {'value': 4, 'label': 'Monthly or more — I actively manage my privacy'}
        ]
    },
    {
        'id': 'q6',
        'text': 'How do you handle public Wi-Fi networks (cafes, airports, hotels)?',
        'options': [
            {'value': 1, 'label': 'I connect freely — No special precautions'},
            {'value': 2, 'label': 'I connect but avoid banking or sensitive sites'},
            {'value': 3, 'label': 'I use a VPN whenever possible on public Wi-Fi'},
            {'value': 4, 'label': 'I avoid public Wi-Fi entirely — I use my mobile data'}
        ]
    },
    {
        'id': 'q7',
        'text': 'How do you handle software and app updates?',
        'options': [
            {'value': 1, 'label': 'I ignore them — I update when forced'},
            {'value': 2, 'label': 'I delay them — I update when convenient'},
            {'value': 3, 'label': 'I install within a few days of notification'},
            {'value': 4, 'label': 'I enable automatic updates on all devices'}
        ]
    },
    {
        'id': 'q8',
        'text': 'How do you back up your important data?',
        'options': [
            {'value': 1, 'label': 'I don\'t back up — I haven\'t thought about it'},
            {'value': 2, 'label': 'Occasionally — I copy files to a USB drive sometimes'},
            {'value': 3, 'label': 'Regularly — I use cloud storage for important files'},
            {'value': 4, 'label': 'Automatically — I have automated backups of everything'}
        ]
    },
    {
        'id': 'q9',
        'text': 'When you receive an unexpected attachment, what do you do?',
        'options': [
            {'value': 1, 'label': 'Open it — Curiosity gets the better of me'},
            {'value': 2, 'label': 'Check the sender name — If it looks familiar, I open it'},
            {'value': 3, 'label': 'Verify with the sender — I contact them through another channel'},
            {'value': 4, 'label': 'Delete it — I never open unexpected attachments'}
        ]
    },
    {
        'id': 'q10',
        'text': 'Do you use a password manager?',
        'options': [
            {'value': 1, 'label': 'No — I memorize all my passwords'},
            {'value': 2, 'label': 'No — I write them down or store them in a file'},
            {'value': 3, 'label': 'Yes — I use my browser\'s built-in password manager'},
            {'value': 4, 'label': 'Yes — I use a dedicated password manager like Bitwarden or 1Password'}
        ]
    }
]

# SUS Questions
SUS_QUESTIONS = [
    {'id': 1, 'text': 'I think that I would like to use this system frequently.'},
    {'id': 2, 'text': 'I found the system unnecessarily complex.'},
    {'id': 3, 'text': 'I thought the system was easy to use.'},
    {'id': 4, 'text': 'I think that I would need the support of a technical person to be able to use this system.'},
    {'id': 5, 'text': 'I found the various functions in this system were well integrated.'},
    {'id': 6, 'text': 'I thought there was too much inconsistency in this system.'},
    {'id': 7, 'text': 'I would imagine that most people would learn to use this system very quickly.'},
    {'id': 8, 'text': 'I found the system very cumbersome to use.'},
    {'id': 9, 'text': 'I felt very confident using the system.'},
    {'id': 10, 'text': 'I needed to learn a lot of things before I could get going with this system.'}
]


def submit_awareness_survey(user_id: int, answers: dict) -> tuple:
    """
    Submit and score security awareness survey.
    answers: dict with keys q1_reuse_password through q10_password_manager, values 1-4.
    Returns (response_record, result_dict).
    """
    required_keys = [f'q{i}_{suffix}' for i, suffix in enumerate([
        '1_reuse_password', '2_mfa_usage', '3_email_verify', '4_location_perm',
        '5_privacy_review', '6_public_wifi', '7_software_updates', '8_backup_habits',
        '9_phishing_recognition', '10_password_manager'
    ], 1)]

    # Map to correct field names
    field_mapping = {
        'q1': 'q1_reuse_password', 'q2': 'q2_mfa_usage',
        'q3': 'q3_email_verify', 'q4': 'q4_location_perm',
        'q5': 'q5_privacy_review', 'q6': 'q6_public_wifi',
        'q7': 'q7_software_updates', 'q8': 'q8_backup_habits',
        'q9': 'q9_phishing_recognition', 'q10': 'q10_password_manager'
    }

    # Normalize answers
    normalized = {}
    for i in range(1, 11):
        key_short = f'q{i}'
        key_long = field_mapping[key_short]
        val = answers.get(key_short) or answers.get(key_long)
        if val is None:
            return None, {'error': f'Missing answer for question {i}'}
        try:
            val = int(val)
            if val < 1 or val > 4:
                return None, {'error': f'Question {i} answer must be 1-4'}
        except (ValueError, TypeError):
            return None, {'error': f'Invalid answer for question {i}'}
        normalized[key_long] = val

    # Calculate score
    answer_list = [normalized[field_mapping[f'q{i}']] for i in range(1, 11)]
    score, category = SurveyResponse.calculate_score(answer_list)

    # Create record
    response = SurveyResponse(
        user_id=user_id,
        **normalized,
        awareness_score=score,
        score_category=category
    )
    db.session.add(response)
    db.session.commit()

    # Recalculate privacy score (survey affects it)
    calculate_privacy_score(user_id)

    # Run ML prediction
    predict(user_id)

    log_action('survey_submit', user_id=user_id, result='success',
               details={'score': score, 'category': category})

    result = {
        'success': True,
        'awareness_score': score,
        'score_category': category,
        'category_label': response.category_label,
        'message': f'Thank you! Your Security Awareness Score is {score}/100.',
        'breakdown': response.breakdown
    }

    return response, result


def submit_sus_survey(user_id: int, answers: dict) -> tuple:
    """
    Submit and score SUS evaluation.
    answers: dict with keys q1 through q10, values 1-5.
    Returns (response_record, result_dict).
    """
    answer_list = []
    for i in range(1, 11):
        val = answers.get(f'q{i}')
        if val is None:
            return None, {'error': f'Missing answer for question {i}'}
        try:
            val = int(val)
            if val < 1 or val > 5:
                return None, {'error': f'Question {i} answer must be 1-5'}
        except (ValueError, TypeError):
            return None, {'error': f'Invalid answer for question {i}'}
        answer_list.append(val)

    score, interpretation = SUSResponse.calculate_score(answer_list)

    response = SUSResponse(
        user_id=user_id,
        q1=answer_list[0], q2=answer_list[1], q3=answer_list[2],
        q4=answer_list[3], q5=answer_list[4], q6=answer_list[5],
        q7=answer_list[6], q8=answer_list[7], q9=answer_list[8],
        q10=answer_list[9],
        sus_score=score,
        interpretation=interpretation
    )
    db.session.add(response)
    db.session.commit()

    log_action('sus_submit', user_id=user_id, result='success',
               details={'score': score, 'interpretation': interpretation})

    labels = {
        'excellent': 'Excellent! The system is highly usable.',
        'good': 'Good. The system is reasonably easy to use.',
        'average': 'Average. There is room for improvement.',
        'poor': 'Poor. Significant usability improvements are needed.'
    }

    result = {
        'success': True,
        'sus_score': score,
        'interpretation': interpretation,
        'interpretation_label': response.interpretation_label,
        'message': f'Thank you for your feedback! Your SUS score is {score} ({response.interpretation_label}).',
        'description': labels.get(interpretation, '')
    }

    return response, result


def get_survey_questions() -> list:
    """Get the list of security awareness survey questions."""
    return SURVEY_QUESTIONS


def get_sus_questions() -> list:
    """Get the list of SUS evaluation questions."""
    return SUS_QUESTIONS


def get_latest_survey_response(user_id: int) -> SurveyResponse:
    """Get the most recent survey response for a user."""
    return SurveyResponse.query.filter_by(user_id=user_id).order_by(
        SurveyResponse.completed_at.desc()
    ).first()


def get_latest_sus_response(user_id: int) -> SUSResponse:
    """Get the most recent SUS response for a user."""
    return SUSResponse.query.filter_by(user_id=user_id).order_by(
        SUSResponse.completed_at.desc()
    ).first()
