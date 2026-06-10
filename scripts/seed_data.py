"""
Seed Data Script
================
Populates the database with realistic demo data for testing and demonstration.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from datetime import datetime, timedelta
import random

from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.session import Session
from app.models.trusted_device import TrustedDevice
from app.models.risk_event import RiskEvent
from app.models.privacy_score import PrivacyScore
from app.models.frustration_metric import FrustrationMetric
from app.models.survey_response import SurveyResponse
from app.models.sus_response import SUSResponse
from app.models.ml_prediction import MLPrediction
from app.models.notification import Notification
from app.models.audit_log import AuditLog
from app.models.recommendation import Recommendation
from app.models.policy_report import PolicyReport

app = create_app('development')


def seed():
    """Seed the database with demo data."""
    with app.app_context():
        # Clear existing data
        db.drop_all()
        db.create_all()
        print("Database created.")

        # Create admin user
        admin = User(
            full_name='Admin User',
            email='admin@upsa.local',
            role='admin',
            email_verified=True,
            mfa_enabled=True
        )
        admin.set_password('AdminPass123!')
        db.session.add(admin)

        # Create demo users
        demo_users = [
            ('Alice Johnson', 'alice@example.com', 'user', True, True),
            ('Bob Smith', 'bob@example.com', 'user', True, False),
            ('Carol White', 'carol@example.com', 'user', False, True),
            ('David Brown', 'david@example.com', 'user', True, False),
            ('Emma Davis', 'emma@example.com', 'user', False, False),
            ('Frank Miller', 'frank@example.com', 'user', True, True),
            ('Grace Wilson', 'grace@example.com', 'user', True, False),
            ('Henry Taylor', 'henry@example.com', 'user', False, True),
            ('Iris Anderson', 'iris@example.com', 'user', True, False),
            ('Jack Thomas', 'jack@example.com', 'user', False, False),
        ]

        users = [admin]
        for full_name, email, role, verified, mfa in demo_users:
            u = User(
                full_name=full_name,
                email=email,
                role=role,
                email_verified=verified,
                mfa_enabled=mfa
            )
            u.set_password('DemoPass123!')
            # Set password changed at various times
            days_ago = random.randint(10, 200)
            u.password_changed_at = datetime.utcnow() - timedelta(days=days_ago)
            db.session.add(u)
            users.append(u)

        db.session.commit()
        print(f"Created {len(users)} users.")

        # Create privacy scores for each user
        for user in users:
            for days_ago in [0, 7, 14, 21, 28]:
                mfa_s = 20 if user.mfa_enabled else 0
                pwd_age_days = (datetime.utcnow() - user.password_changed_at).days if user.password_changed_at else 180
                pwd_age_s = 15 if pwd_age_days < 90 else 8 if pwd_age_days < 180 else 0
                pwd_str_s = random.randint(15, 25)
                browser_s = random.randint(5, 15)
                loc_s = random.randint(3, 10)
                cm_s = random.randint(3, 5)
                notif_s = random.randint(2, 5)
                survey_s = random.randint(5, 15)

                raw_sum = mfa_s + pwd_str_s + pwd_age_s + browser_s + loc_s + cm_s + notif_s + survey_s
                overall = int(round((raw_sum / 110) * 100))
                category = 'low' if overall >= 71 else 'medium' if overall >= 41 else 'high'

                score = PrivacyScore(
                    user_id=user.id,
                    overall_score=overall,
                    mfa_score=mfa_s,
                    password_strength_score=pwd_str_s,
                    password_age_score=pwd_age_s,
                    browser_perm_score=browser_s,
                    location_perm_score=loc_s,
                    cam_mic_score=cm_s,
                    notification_score=notif_s,
                    survey_score=survey_s,
                    risk_category=category,
                    recorded_at=datetime.utcnow() - timedelta(days=days_ago)
                )
                db.session.add(score)

        db.session.commit()
        print("Created privacy scores.")

        # Create risk events
        event_types = ['login_risk_assessment', 'new_device', 'new_location', 'unusual_time']
        results = ['allowed', 'mfa_required', 'blocked']
        categories = ['low', 'medium', 'high']

        for user in users:
            for _ in range(random.randint(2, 8)):
                score = random.randint(0, 100)
                cat = 'low' if score <= 30 else 'medium' if score <= 60 else 'high'
                result = 'allowed' if score <= 30 else 'mfa_required' if score <= 60 else 'blocked'
                event = RiskEvent(
                    user_id=user.id,
                    event_type=random.choice(event_types),
                    risk_points=random.randint(5, 40),
                    total_score=score,
                    risk_category=cat,
                    ip_address=f'192.168.1.{random.randint(1, 255)}',
                    result=result,
                    explanation='Demo risk event for testing purposes.',
                    created_at=datetime.utcnow() - timedelta(days=random.randint(0, 30))
                )
                db.session.add(event)

        db.session.commit()
        print("Created risk events.")

        # Create survey responses
        for user in users:
            if random.random() > 0.3:  # 70% have surveys
                answers = [random.randint(1, 4) for _ in range(10)]
                raw = sum(answers)
                awareness = int(((raw - 10) / 30) * 100)
                cat = 'high' if awareness > 70 else 'medium' if awareness > 40 else 'low'
                sr = SurveyResponse(
                    user_id=user.id,
                    q1_reuse_password=answers[0], q2_mfa_usage=answers[1],
                    q3_email_verify=answers[2], q4_location_perm=answers[3],
                    q5_privacy_review=answers[4], q6_public_wifi=answers[5],
                    q7_software_updates=answers[6], q8_backup_habits=answers[7],
                    q9_phishing_recognition=answers[8], q10_password_manager=answers[9],
                    awareness_score=awareness,
                    score_category=cat
                )
                db.session.add(sr)

        db.session.commit()
        print("Created survey responses.")

        # Create SUS responses
        for user in users:
            if random.random() > 0.5:
                answers = [random.randint(1, 5) for _ in range(10)]
                total = 0
                for i, ans in enumerate(answers):
                    if (i + 1) % 2 == 1:
                        total += (ans - 1)
                    else:
                        total += (5 - ans)
                sus_score = round(total * 2.5, 1)
                interp = 'excellent' if sus_score >= 81 else 'good' if sus_score >= 69 else 'average' if sus_score >= 51 else 'poor'
                sr = SUSResponse(
                    user_id=user.id,
                    q1=answers[0], q2=answers[1], q3=answers[2],
                    q4=answers[3], q5=answers[4], q6=answers[5],
                    q7=answers[6], q8=answers[7], q9=answers[8], q10=answers[9],
                    sus_score=sus_score,
                    interpretation=interp
                )
                db.session.add(sr)

        db.session.commit()
        print("Created SUS responses.")

        # Create ML predictions
        for user in users:
            phishing = random.choice(['low', 'medium', 'high'])
            phishing_prob = round(random.random(), 2)
            account_prob = round(random.random(), 2)
            pred = MLPrediction(
                user_id=user.id,
                phishing_susceptibility=phishing,
                phishing_probability=phishing_prob,
                account_risk_probability=account_prob,
                model_version='1.0.0',
                features_json='{"demo": true}'
            )
            db.session.add(pred)

        db.session.commit()
        print("Created ML predictions.")

        # Create recommendations
        rec_data = [
            ('mfa', 'Enable Multi-Factor Authentication', 'high', 15),
            ('password', 'Update Your Password', 'high', 10),
            ('privacy', 'Review Browser Permissions', 'medium', 5),
            ('updates', 'Keep Software Updated', 'medium', 5),
            ('backup', 'Set Up Regular Data Backups', 'medium', 5),
            ('phishing', 'Learn to Recognize Phishing Emails', 'medium', 5),
            ('general', 'Complete the Security Awareness Survey', 'low', 8),
        ]

        for user in users:
            for cat, title, priority, impact in rec_data:
                if random.random() > 0.5:
                    rec = Recommendation(
                        user_id=user.id,
                        category=cat,
                        title=title,
                        description=f'Demo recommendation: {title}',
                        plain_explanation=f'This is why {title.lower()} matters for your security.',
                        priority=priority,
                        impact_estimate=impact,
                        is_completed=random.random() > 0.7
                    )
                    db.session.add(rec)

        db.session.commit()
        print("Created recommendations.")

        # Create audit logs
        actions = ['user_login', 'user_logout', 'privacy_score_update', 'survey_submit', 'settings_update']
        for user in users:
            for _ in range(random.randint(3, 10)):
                log = AuditLog(
                    user_id=user.id,
                    action=random.choice(actions),
                    result=random.choice(['success', 'success', 'success', 'failure']),
                    ip_address=f'192.168.1.{random.randint(1, 255)}',
                    created_at=datetime.utcnow() - timedelta(days=random.randint(0, 30))
                )
                db.session.add(log)

        db.session.commit()
        print("Created audit logs.")

        # Create frustration metrics
        for user in users:
            fm = FrustrationMetric(
                user_id=user.id,
                login_failures_7d=random.randint(0, 5),
                password_reset_count_7d=random.randint(0, 2),
                mfa_abandonment_count=random.randint(0, 3),
                help_page_visit_count=random.randint(0, 5),
                frustration_level=random.choice(['low', 'low', 'low', 'medium', 'high'])
            )
            db.session.add(fm)

        db.session.commit()
        print("Created frustration metrics.")

        # Create notifications
        for user in users:
            for _ in range(random.randint(0, 5)):
                notif = Notification(
                    user_id=user.id,
                    title=random.choice(['Score Updated', 'New Recommendation', 'Login Alert', 'Security Tip']),
                    message='This is a demo notification for testing purposes.',
                    type=random.choice(['info', 'success', 'warning']),
                    is_read=random.random() > 0.5
                )
                db.session.add(notif)

        db.session.commit()
        print("Created notifications.")

        print("\n=== Seed complete! ===")
        print(f"Total users: {len(users)}")
        print("Admin: admin@upsa.local / AdminPass123!")
        print("Demo users: [name]@example.com / DemoPass123!")
        print("========================")


if __name__ == '__main__':
    seed()
