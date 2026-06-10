"""
Policy Analyzer Service
=======================
Extracts and analyzes privacy policy documents using rule-based NLP.
Supports PDF, DOCX, and TXT files.
"""
import os
import re
import json
import hashlib
from datetime import datetime, timezone
from flask import current_app
from ..extensions import db
from ..models.policy_report import PolicyReport
from .audit_service import log_action


# Risk keyword dictionaries
DATA_COLLECTION_KEYWORDS = {
    'high': [
        'name', 'email address', 'phone number', 'physical address',
        'precise location', 'gps', 'geolocation', 'biometric',
        'social security', 'government id', 'financial information',
        'credit card', 'bank account', 'purchase history', 'browsing history',
        'search history', 'clickstream', 'device fingerprint', 'ip address',
        'mac address', 'contacts', 'address book', 'photos', 'videos',
        'voice recording', 'health information', 'medical data'
    ],
    'medium': [
        'device information', 'browser type', 'operating system',
        'language preference', 'time zone', 'screen resolution',
        'cookies', 'usage data', 'analytics', 'crash reports',
        ' approximate location', 'city', 'country', 'postal code'
    ],
    'low': [
        'aggregated data', 'anonymized data', 'technical data'
    ]
}

DATA_SHARING_KEYWORDS = {
    'high': [
        'sell data', 'sell your data', 'sell personal information',
        'data brokers', 'advertising partners', 'marketing partners',
        'third party advertisers', 'behavioral advertising',
        'targeted advertising', 'profiling', 'automated decision'
    ],
    'medium': [
        'share with third parties', 'service providers', 'vendors',
        'contractors', 'affiliates', 'subsidiaries', 'business partners',
        'payment processors', 'cloud hosting'
    ],
    'low': [
        'share with consent', 'share with your permission',
        'legal requirement', 'law enforcement', 'court order'
    ]
}

TRACKING_KEYWORDS = {
    'high': [
        'tracking pixels', 'web beacons', 'clear gifs', 'device fingerprinting',
        'cross-site tracking', 'cross-device tracking', 'retargeting',
        'behavioral tracking', 'third-party cookies'
    ],
    'medium': [
        'cookies', 'local storage', 'session storage', 'analytics',
        'google analytics', 'facebook pixel', 'mixpanel', 'segment'
    ],
    'low': [
        'first-party cookies', 'essential cookies', 'necessary cookies',
        'functional cookies'
    ]
}

RETENTION_KEYWORDS = {
    'high': [
        'indefinitely', 'permanently', 'forever', 'as long as necessary',
        'unlimited', 'no deletion', 'cannot be deleted', 'irretrievable'
    ],
    'medium': [
        'up to', 'maximum of', 'at least', 'minimum of', 'retention period',
        'seven years', 'ten years', 'several years'
    ],
    'low': [
        '30 days', '90 days', 'six months', 'one year', 'deleted upon request',
        'right to deletion', 'data portability', 'you can delete'
    ]
}

USER_RIGHTS_KEYWORDS = {
    'positive': [
        'access your data', 'request a copy', 'data portability',
        'delete your account', 'right to deletion', 'opt out',
        'withdraw consent', 'unsubscribe', 'turn off', 'disable tracking',
        'download your data', 'rectify', 'update your information',
        'complain to regulator', 'data protection officer'
    ],
    'negative': [
        'no right to', 'cannot opt out', 'no deletion', 'irreversible',
        'we reserve the right', 'may refuse', 'at our discretion',
        'not responsible', 'no liability', ' binding arbitration',
        'waive your right', 'class action waiver'
    ]
}


def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed."""
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']


def extract_text(file_path: str, file_type: str) -> str:
    """Extract text from PDF, DOCX, or TXT file."""
    text = ''
    try:
        if file_type == 'pdf':
            import PyPDF2
            with open(file_path, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                for page in reader.pages:
                    page_text = page.extract_text()
                    if page_text:
                        text += page_text + '\n'

        elif file_type == 'docx':
            from docx import Document
            doc = Document(file_path)
            for para in doc.paragraphs:
                text += para.text + '\n'

        elif file_type == 'txt':
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()

    except Exception as e:
        current_app.logger.error(f'Text extraction error: {e}')
        return ''

    return text


def analyze_policy(text: str) -> dict:
    """
    Analyze privacy policy text using rule-based keyword matching.
    Returns a structured analysis result.
    """
    text_lower = text.lower()
    sentences = re.split(r'[.!?\n]+', text_lower)
    sentences = [s.strip() for s in sentences if len(s.strip()) > 10]

    # Score each category
    data_collection_score = _score_category(text_lower, sentences, DATA_COLLECTION_KEYWORDS)
    data_sharing_score = _score_category(text_lower, sentences, DATA_SHARING_KEYWORDS)
    tracking_score = _score_category(text_lower, sentences, TRACKING_KEYWORDS)
    retention_score = _score_category(text_lower, sentences, RETENTION_KEYWORDS)
    user_rights_score = _score_user_rights(text_lower, sentences)

    # Calculate overall
    overall = int((data_collection_score + data_sharing_score +
                   tracking_score + retention_score + (100 - user_rights_score)) / 5)

    # Determine risk
    if overall >= 60:
        overall_risk = 'high'
    elif overall >= 35:
        overall_risk = 'medium'
    else:
        overall_risk = 'low'

    # Generate summary
    summary = _generate_summary(
        data_collection_score, data_sharing_score,
        tracking_score, retention_score, user_rights_score,
        overall_risk
    )

    # Generate key findings
    findings = _generate_findings(
        text_lower, sentences, data_collection_score,
        data_sharing_score, tracking_score, retention_score, user_rights_score
    )

    return {
        'overall_risk': overall_risk,
        'overall_policy_score': overall,
        'data_collection_score': data_collection_score,
        'data_sharing_score': data_sharing_score,
        'third_party_score': tracking_score,
        'retention_score': retention_score,
        'user_rights_score': user_rights_score,
        'summary': summary,
        'findings': findings
    }


def _score_category(text: str, sentences: list, keyword_dict: dict) -> int:
    """Score a category based on keyword matches."""
    score = 0
    matched_high = set()
    matched_medium = set()
    matched_low = set()

    for sentence in sentences:
        for kw in keyword_dict.get('high', []):
            if kw in sentence:
                matched_high.add(kw)
        for kw in keyword_dict.get('medium', []):
            if kw in sentence:
                matched_medium.add(kw)
        for kw in keyword_dict.get('low', []):
            if kw in sentence:
                matched_low.add(kw)

    score += min(len(matched_high) * 8, 60)
    score += min(len(matched_medium) * 4, 25)
    score -= min(len(matched_low) * 3, 15)

    return max(0, min(100, score))


def _score_user_rights(text: str, sentences: list) -> int:
    """Score user rights — higher is better (more rights)."""
    positive = set()
    negative = set()

    for sentence in sentences:
        for kw in USER_RIGHTS_KEYWORDS.get('positive', []):
            if kw in sentence:
                positive.add(kw)
        for kw in USER_RIGHTS_KEYWORDS.get('negative', []):
            if kw in sentence:
                negative.add(kw)

    score = min(len(positive) * 8, 70)
    score -= min(len(negative) * 6, 30)
    return max(0, min(100, score))


def _generate_summary(dc: int, ds: int, tp: int, ret: int, ur: int, risk: str) -> str:
    """Generate a plain-language, layman-friendly summary in HTML format."""
    html_parts = []
    
    # Simple, direct intro based on overall risk
    if risk == 'high':
        html_parts.append(
            '<div class="alert alert-danger border-0 p-3 mb-3" style="border-radius: 8px;">'
            '<strong><i class="fa-solid fa-triangle-exclamation me-2"></i>Warning:</strong> '
            'This privacy policy contains several red flags. The service collects a lot of your personal information, '
            'shares it with advertisers, and gives you very little control over your own data.'
            '</div>'
        )
    elif risk == 'medium':
        html_parts.append(
            '<div class="alert alert-warning border-0 p-3 mb-3" style="border-radius: 8px;">'
            '<strong><i class="fa-solid fa-circle-info me-2"></i>Caution:</strong> '
            'This policy is moderately privacy-friendly. While they collect standard details and share it '
            'with business partners, they provide some options to manage your data.'
            '</div>'
        )
    else:
        html_parts.append(
            '<div class="alert alert-success border-0 p-3 mb-3" style="border-radius: 8px;">'
            '<strong><i class="fa-solid fa-circle-check me-2"></i>Good News:</strong> '
            'This service is very protective of your privacy. They collect only what is necessary, '
            'do not sell your details, and respect your right to control and delete your data.'
            '</div>'
        )

    html_parts.append('<p class="mb-3">Here is a simple breakdown of what this means for you in plain language:</p>')
    html_parts.append('<ul class="list-group list-group-flush mb-0" style="border-radius: 8px;">')

    # Data collection layman translation
    if dc >= 60:
        html_parts.append(
            '<li class="list-group-item bg-transparent px-0 py-2 border-0">'
            '🔍 <strong>Data Collection:</strong> They track and collect sensitive details, including your real name, email, physical address, and even your precise GPS location.'
            '</li>'
        )
    elif dc >= 30:
        html_parts.append(
            '<li class="list-group-item bg-transparent px-0 py-2 border-0">'
            '🔍 <strong>Data Collection:</strong> They collect standard info like what device you are using, your web browser, and general app usage statistics.'
            '</li>'
        )
    else:
        html_parts.append(
            '<li class="list-group-item bg-transparent px-0 py-2 border-0">'
            '🔍 <strong>Data Collection:</strong> They only collect minimal information that is strictly required to run the service.'
            '</li>'
        )

    # Data sharing layman translation
    if ds >= 60:
        html_parts.append(
            '<li class="list-group-item bg-transparent px-0 py-2 border-0">'
            '🤝 <strong>Data Sharing:</strong> They share (and potentially sell) your information with advertising partners, marketers, and data brokers to target you with ads.'
            '</li>'
        )
    elif ds >= 30:
        html_parts.append(
            '<li class="list-group-item bg-transparent px-0 py-2 border-0">'
            '🤝 <strong>Data Sharing:</strong> They share your data with business partners and companies that help them run their website/service.'
            '</li>'
        )
    else:
        html_parts.append(
            '<li class="list-group-item bg-transparent px-0 py-2 border-0">'
            '🤝 <strong>Data Sharing:</strong> They do not share or sell your details, and restrict sharing to essential, trusted service providers.'
            '</li>'
        )

    # Tracking layman translation
    if tp >= 60:
        html_parts.append(
            '<li class="list-group-item bg-transparent px-0 py-2 border-0">'
            '🌐 <strong>Tracking:</strong> They use pixels, web beacons, and other tools to track your activity across different devices and websites.'
            '</li>'
        )
    elif tp >= 30:
        html_parts.append(
            '<li class="list-group-item bg-transparent px-0 py-2 border-0">'
            '🌐 <strong>Tracking:</strong> They use standard cookies and analytics tools (like Google Analytics) to see how people use their site.'
            '</li>'
        )
    else:
        html_parts.append(
            '<li class="list-group-item bg-transparent px-0 py-2 border-0">'
            '🌐 <strong>Tracking:</strong> They use minimal tracking, mostly relying on first-party cookies that are essential for the site to function.'
            '</li>'
        )

    # Retention layman translation
    if ret >= 60:
        html_parts.append(
            '<li class="list-group-item bg-transparent px-0 py-2 border-0">'
            '⏰ <strong>Data Retention:</strong> They keep your information for a very long time, indefinitely (forever), or do not clearly state when they will delete it.'
            '</li>'
        )
    elif ret >= 30:
        html_parts.append(
            '<li class="list-group-item bg-transparent px-0 py-2 border-0">'
            '⏰ <strong>Data Retention:</strong> They keep your information for standard business or legal periods (e.g. several years).'
            '</li>'
        )
    else:
        html_parts.append(
            '<li class="list-group-item bg-transparent px-0 py-2 border-0">'
            '⏰ <strong>Data Retention:</strong> They delete your data as soon as it\'s no longer needed, with clear and short deletion timelines.'
            '</li>'
        )

    # User rights layman translation
    if ur >= 60:
        html_parts.append(
            '<li class="list-group-item bg-transparent px-0 py-2 border-0">'
            '🛡️ <strong>Your Rights:</strong> You have strong rights. You can easily request a copy of your data, ask them to delete it, or opt out of tracking.'
            '</li>'
        )
    elif ur >= 30:
        html_parts.append(
            '<li class="list-group-item bg-transparent px-0 py-2 border-0">'
            '🛡️ <strong>Your Rights:</strong> You have basic rights to see and delete your data, though there may be some limits or procedures to follow.'
            '</li>'
        )
    else:
        html_parts.append(
            '<li class="list-group-item bg-transparent px-0 py-2 border-0">'
            '🛡️ <strong>Your Rights:</strong> You have very few rights. It is difficult or impossible to delete your account or download your information.'
            '</li>'
        )

    html_parts.append('</ul>')
    return ''.join(html_parts)


def _generate_findings(text: str, sentences: list, dc: int, ds: int, tp: int, ret: int, ur: int) -> list:
    """Generate specific key findings with category classification."""
    findings = []

    # 1. Data Collection
    if 'precise location' in text or 'gps' in text or 'geolocation' in text:
        findings.append({'category': 'data_collection', 'type': 'negative', 'text': 'Tracks your precise physical location using GPS.'})
    if 'browsing history' in text or 'search history' in text:
        findings.append({'category': 'data_collection', 'type': 'negative', 'text': 'Monitors your internet browsing and search history.'})
    if 'contacts' in text or 'address book' in text:
        findings.append({'category': 'data_collection', 'type': 'negative', 'text': 'Accesses your personal contacts and address book.'})
    if 'biometric' in text:
        findings.append({'category': 'data_collection', 'type': 'negative', 'text': 'Collects sensitive biometric data (like face scans or fingerprints).'})

    # Default category state if no specific keyword matched
    has_dc = any(f['category'] == 'data_collection' for f in findings)
    if not has_dc:
        if dc >= 60:
            findings.append({'category': 'data_collection', 'type': 'negative', 'text': 'Collects extensive personal details (like names, emails, phone numbers).'})
        elif dc >= 30:
            findings.append({'category': 'data_collection', 'type': 'warning', 'text': 'Collects basic details like your device type and usage info.'})
        else:
            findings.append({'category': 'data_collection', 'type': 'positive', 'text': 'Collects very minimal personal information, only what is absolutely necessary.'})

    # 2. Data Sharing
    if ds >= 60:
        findings.append({'category': 'data_sharing', 'type': 'negative', 'text': 'Shares your personal data widely with advertisers, marketers, and data brokers.'})
    if 'sell' in text and ('data' in text or 'information' in text):
        findings.append({'category': 'data_sharing', 'type': 'negative', 'text': 'May sell your personal data to third-party companies.'})
    
    has_ds = any(f['category'] == 'data_sharing' for f in findings)
    if not has_ds:
        if ds >= 30:
            findings.append({'category': 'data_sharing', 'type': 'warning', 'text': 'Shares some information with service providers and business partners.'})
        else:
            findings.append({'category': 'data_sharing', 'type': 'positive', 'text': 'Limits data sharing to essential service providers only.'})

    # 3. Third Party Tracking
    if 'device fingerprinting' in text or 'fingerprint' in text:
        findings.append({'category': 'third_party_tracking', 'type': 'negative', 'text': 'Uses device fingerprinting (a hard-to-block tracking method).'})
    if 'third-party cookies' in text or 'third party cookies' in text:
        findings.append({'category': 'third_party_tracking', 'type': 'negative', 'text': 'Uses third-party cookies to track you across other websites.'})
    
    if tp >= 60:
        findings.append({'category': 'third_party_tracking', 'type': 'negative', 'text': 'Uses multiple tracking technologies across the web.'})

    has_tp = any(f['category'] == 'third_party_tracking' for f in findings)
    if not has_tp:
        if tp >= 30:
            findings.append({'category': 'third_party_tracking', 'type': 'warning', 'text': 'Uses standard tracking cookies and analytics.'})
        else:
            findings.append({'category': 'third_party_tracking', 'type': 'positive', 'text': 'Only uses essential first-party cookies.'})

    # 4. Retention
    if 'indefinitely' in text or 'permanently' in text:
        findings.append({'category': 'retention', 'type': 'negative', 'text': 'Retains your personal data forever (indefinitely).'})
    
    if ret >= 60:
        findings.append({'category': 'retention', 'type': 'negative', 'text': 'Data retention periods are very long or not clearly specified.'})

    has_ret = any(f['category'] == 'retention' for f in findings)
    if not has_ret:
        if ret >= 30:
            findings.append({'category': 'retention', 'type': 'warning', 'text': 'Keeps your data for moderate periods (e.g., several years).'})
        else:
            findings.append({'category': 'retention', 'type': 'positive', 'text': 'Deletes your data quickly once it is no longer needed.'})

    # 5. User Rights
    if 'delete your account' in text or 'right to deletion' in text:
        findings.append({'category': 'user_rights', 'type': 'positive', 'text': 'Allows you to delete your account and all associated data.'})
    if 'opt out' in text or 'withdraw consent' in text:
        findings.append({'category': 'user_rights', 'type': 'positive', 'text': 'Provides clear options to opt out of tracking and data collection.'})
    if 'data protection officer' in text or 'dpo' in text:
        findings.append({'category': 'user_rights', 'type': 'positive', 'text': 'Has a dedicated Data Protection Officer you can contact.'})

    if ur < 30:
        findings.append({'category': 'user_rights', 'type': 'negative', 'text': 'Offers very little control or rights over your own personal data.'})
    elif ur >= 60:
        findings.append({'category': 'user_rights', 'type': 'positive', 'text': 'Provides strong user rights, including data deletion and access.'})

    return findings


def process_upload(user_id: int, file_storage, original_filename: str) -> tuple:
    """
    Process an uploaded privacy policy file.
    Returns (report, error_message).
    """
    if not allowed_file(original_filename):
        return None, 'Invalid file type. Only PDF, DOCX, and TXT files are allowed.'

    # Generate safe filename
    file_type = original_filename.rsplit('.', 1)[1].lower()
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    random_suffix = hashlib.md5(
        f'{user_id}{timestamp}{original_filename}'.encode()
    ).hexdigest()[:8]
    stored_filename = f'policy_{user_id}_{timestamp}_{random_suffix}.{file_type}'
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], stored_filename)

    try:
        file_storage.save(file_path)
    except Exception as e:
        current_app.logger.error(f'File save error: {e}')
        return None, 'Failed to save uploaded file.'

    # Extract and analyze
    text = extract_text(file_path, file_type)
    if not text or len(text.strip()) < 50:
        os.remove(file_path)
        return None, 'Could not extract readable text from the file. Please try a different file.'

    analysis = analyze_policy(text)

    report = PolicyReport(
        user_id=user_id,
        original_filename=original_filename,
        stored_filename=stored_filename,
        file_type=file_type,
        overall_risk=analysis['overall_risk'],
        data_collection_score=analysis['data_collection_score'],
        data_sharing_score=analysis['data_sharing_score'],
        third_party_score=analysis['third_party_score'],
        retention_score=analysis['retention_score'],
        user_rights_score=analysis['user_rights_score'],
        overall_policy_score=analysis['overall_policy_score'],
        summary_text=analysis['summary'],
        key_findings_json=json.dumps(analysis['findings']),
        extracted_text_sample=text[:2000]
    )
    db.session.add(report)
    db.session.commit()

    log_action('policy_upload', user_id=user_id, result='success',
               details={'filename': original_filename, 'risk': analysis['overall_risk']})

    return report, None


def process_paste(user_id: int, text: str, title: str = None) -> tuple:
    """
    Process pasted privacy policy text.
    Returns (report, error_message).
    """
    if not text or len(text.strip()) < 50:
        return None, 'Please paste a policy text of at least 50 characters.'

    if not title or not title.strip():
        title = f"Pasted Policy {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}"

    # We treat it as a .txt file
    file_type = 'txt'
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    random_suffix = hashlib.md5(
        f'{user_id}{timestamp}{title}'.encode()
    ).hexdigest()[:8]
    
    # Safe original filename (append .txt if not present)
    original_filename = title if title.endswith('.txt') else f"{title}.txt"
    # Replace invalid chars in original filename
    original_filename = re.sub(r'[\\/*?:"<>|]', "", original_filename)
    
    stored_filename = f'policy_{user_id}_{timestamp}_{random_suffix}.txt'
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], stored_filename)

    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(text)
    except Exception as e:
        current_app.logger.error(f'File save error: {e}')
        return None, 'Failed to save pasted text.'

    analysis = analyze_policy(text)

    report = PolicyReport(
        user_id=user_id,
        original_filename=original_filename,
        stored_filename=stored_filename,
        file_type=file_type,
        overall_risk=analysis['overall_risk'],
        data_collection_score=analysis['data_collection_score'],
        data_sharing_score=analysis['data_sharing_score'],
        third_party_score=analysis['third_party_score'],
        retention_score=analysis['retention_score'],
        user_rights_score=analysis['user_rights_score'],
        overall_policy_score=analysis['overall_policy_score'],
        summary_text=analysis['summary'],
        key_findings_json=json.dumps(analysis['findings']),
        extracted_text_sample=text[:2000]
    )
    db.session.add(report)
    db.session.commit()

    log_action('policy_upload', user_id=user_id, result='success',
               details={'filename': original_filename, 'risk': analysis['overall_risk']})

    return report, None


def get_user_reports(user_id: int) -> list:
    """Get all policy reports for a user."""
    return PolicyReport.query.filter_by(user_id=user_id).order_by(
        PolicyReport.created_at.desc()
    ).all()


def get_report(report_id: int, user_id: int) -> PolicyReport:
    """Get a specific policy report."""
    return PolicyReport.query.filter_by(id=report_id, user_id=user_id).first()
