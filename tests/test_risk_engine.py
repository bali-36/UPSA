"""
Risk Engine Tests
=================
Tests for adaptive risk-based authentication.
"""
import pytest
from app.services.risk_engine import assess_login_risk, trust_device, get_user_devices
from app.services.risk_engine import LOW_THRESHOLD, MEDIUM_THRESHOLD


class TestRiskAssessment:
    """Risk assessment algorithm tests."""

    def test_low_risk_trusted_device(self, app):
        """Login from trusted device gets low risk."""
        with app.app_context():
            from app.extensions import db
            from app.models.user import User
            from app.models.trusted_device import TrustedDevice
            import hashlib

            user = User(full_name='Risk Test', email='risk@test.com')
            user.set_password('TestPass123!')
            db.session.add(user)
            db.session.commit()

            # Trust the device first
            ua = 'Mozilla/5.0 Test Browser'
            ua_hash = hashlib.sha256(ua.encode()).hexdigest()
            device = TrustedDevice(
                user_id=user.id, device_name='Test Device',
                browser='TestBrowser', user_agent_hash=ua_hash,
                ip_address='192.168.1.1', location='TestCity',
                is_trusted=True
            )
            db.session.add(device)
            db.session.commit()

            result = assess_login_risk(
                user.id, '192.168.1.1', ua,
                device_info='Test Device', browser_info='TestBrowser',
                location_info='TestCity'
            )

            assert result['risk_category'] == 'low'
            assert result['result'] == 'allowed'
            assert result['total_score'] <= LOW_THRESHOLD

    def test_medium_risk_new_device(self, app):
        """Login from new device gets medium risk requiring MFA."""
        with app.app_context():
            from app.extensions import db
            from app.models.user import User

            user = User(full_name='Risk Test2', email='risk2@test.com')
            user.set_password('TestPass123!')
            db.session.add(user)
            db.session.commit()

            result = assess_login_risk(
                user.id, '192.168.1.100',
                'Mozilla/5.0 NewDevice',
                device_info='New Device', browser_info='NewBrowser',
                location_info='NewCity'
            )

            assert result['risk_category'] == 'medium'
            assert result['result'] == 'mfa_required'
            assert LOW_THRESHOLD < result['total_score'] <= MEDIUM_THRESHOLD

    def test_high_risk_combined_factors(self, app):
        """Multiple risk factors result in blocked login."""
        with app.app_context():
            from app.extensions import db
            from app.models.user import User

            user = User(full_name='Risk Test3', email='risk3@test.com')
            user.set_password('TestPass123!')
            user.failed_login_count = 5  # Recent failures
            user.last_failed_login = db.func.now()
            db.session.add(user)
            db.session.commit()

            result = assess_login_risk(
                user.id, '10.0.0.1',
                'UnknownDevice/1.0',
                device_info='Unknown', browser_info='Unknown',
                location_info='FarAway'
            )

            assert result['risk_category'] == 'high'
            assert result['result'] == 'blocked'
            assert result['total_score'] > MEDIUM_THRESHOLD


class TestTrustedDevices:
    """Trusted device management tests."""

    def test_trust_new_device(self, app):
        """Can add a device as trusted."""
        with app.app_context():
            from app.extensions import db
            from app.models.user import User

            user = User(full_name='Device Test', email='dev@test.com')
            user.set_password('TestPass123!')
            db.session.add(user)
            db.session.commit()

            device = trust_device(
                user.id, 'TestAgent/1.0', 'My Laptop',
                'Chrome', ip_address='192.168.1.1', location='Home'
            )

            assert device.is_trusted is True
            assert device.device_name == 'My Laptop'

            devices = get_user_devices(user.id)
            assert len(devices) == 1

    def test_dedup_same_device(self, app):
        """Same device is not duplicated."""
        with app.app_context():
            from app.extensions import db
            from app.models.user import User
            import hashlib

            user = User(full_name='Dedup Test', email='dedup@test.com')
            user.set_password('TestPass123!')
            db.session.add(user)
            db.session.commit()

            ua = 'SameAgent/1.0'
            trust_device(user.id, ua, 'Device', 'Chrome')
            trust_device(user.id, ua, 'Device', 'Chrome')

            devices = get_user_devices(user.id)
            assert len(devices) == 1
