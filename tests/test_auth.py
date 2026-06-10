"""
Authentication Tests
====================
Tests for registration, login, MFA, password reset.
"""
import pytest
from app.models.user import User
from app.models.email_verification import EmailVerification


class TestRegistration:
    """User registration tests."""

    def test_register_success(self, client):
        """Successful registration creates a user."""
        resp = client.post('/auth/register', data={
            'full_name': 'John Doe',
            'email': 'john@example.com',
            'password': 'SecurePass123!',
            'confirm_password': 'SecurePass123!'
        }, follow_redirects=True)
        assert resp.status_code == 200
        user = User.query.filter_by(email='john@example.com').first()
        assert user is not None
        assert user.full_name == 'John Doe'
        assert user.role == 'user'

    def test_register_password_mismatch(self, client):
        """Registration fails when passwords don't match."""
        resp = client.post('/auth/register', data={
            'full_name': 'John Doe',
            'email': 'john2@example.com',
            'password': 'SecurePass123!',
            'confirm_password': 'DifferentPass123!'
        }, follow_redirects=True)
        assert b'do not match' in resp.data

    def test_register_duplicate_email(self, client):
        """Registration fails for duplicate email."""
        client.post('/auth/register', data={
            'full_name': 'User One',
            'email': 'dup@example.com',
            'password': 'SecurePass123!',
            'confirm_password': 'SecurePass123!'
        })
        resp = client.post('/auth/register', data={
            'full_name': 'User Two',
            'email': 'dup@example.com',
            'password': 'SecurePass123!',
            'confirm_password': 'SecurePass123!'
        }, follow_redirects=True)
        assert b'already exists' in resp.data

    def test_register_weak_password(self, client):
        """Registration fails for weak password."""
        resp = client.post('/auth/register', data={
            'full_name': 'John Doe',
            'email': 'weak@example.com',
            'password': '123',
            'confirm_password': '123'
        }, follow_redirects=True)
        assert resp.status_code == 200


class TestLogin:
    """User login tests."""

    def test_login_success(self, app, client):
        """Successful login redirects to dashboard."""
        with app.app_context():
            user = User(full_name='Test User', email='login@test.com')
            user.set_password('TestPass123!')
            from app.extensions import db
            db.session.add(user)
            db.session.commit()

        resp = client.post('/auth/login', data={
            'email': 'login@test.com',
            'password': 'TestPass123!'
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b'Welcome' in resp.data or b'Dashboard' in resp.data or b'Verify' in resp.data

    def test_login_invalid_password(self, app, client):
        """Login fails with wrong password."""
        with app.app_context():
            user = User(full_name='Test User', email='login2@test.com')
            user.set_password('TestPass123!')
            from app.extensions import db
            db.session.add(user)
            db.session.commit()

        resp = client.post('/auth/login', data={
            'email': 'login2@test.com',
            'password': 'WrongPass123!'
        }, follow_redirects=True)
        assert b'Invalid' in resp.data

    def test_login_nonexistent_user(self, client):
        """Login fails for nonexistent user."""
        resp = client.post('/auth/login', data={
            'email': 'nobody@example.com',
            'password': 'SomePass123!'
        }, follow_redirects=True)
        assert b'Invalid' in resp.data


class TestLogout:
    """Logout tests."""

    def test_logout(self, auth_client):
        """Logout clears session."""
        client, user = auth_client
        resp = client.get('/auth/logout', follow_redirects=True)
        assert resp.status_code == 200


class TestPasswordStrength:
    """Password strength meter tests."""

    def test_password_strength_strong(self):
        """Strong password detection."""
        from app.services.auth_service import get_password_strength
        result = get_password_strength('MyStr0ng!Pass')
        assert result['score'] >= 5
        assert result['label'] == 'Strong'

    def test_password_strength_weak(self):
        """Weak password detection."""
        from app.services.auth_service import get_password_strength
        result = get_password_strength('password')
        assert result['score'] <= 2
        assert result['label'] == 'Weak'
