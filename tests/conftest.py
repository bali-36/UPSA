"""
Test Configuration
==================
Pytest fixtures for UPSA tests.
"""
import pytest
from app import create_app
from app.extensions import db
from app.models.user import User


@pytest.fixture
def app():
    """Create application for testing."""
    app = create_app('testing')
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test client."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """Test CLI runner."""
    return app.test_cli_runner()


@pytest.fixture
def auth_client(app):
    """Authenticated test client."""
    with app.test_client() as client:
        # Create test user
        user = User(full_name='Test User', email='test@example.com')
        user.set_password('TestPass123!')
        db.session.add(user)
        db.session.commit()

        # Add trusted device to avoid MFA during tests
        import hashlib
        from app.models.trusted_device import TrustedDevice
        ua = 'TestBrowser'
        ua_hash = hashlib.sha256(ua.encode()).hexdigest()
        device = TrustedDevice(
            user_id=user.id,
            device_name='Unknown Device',
            browser='Unknown Browser',
            user_agent_hash=ua_hash,
            ip_address='127.0.0.1',
            location='Unknown',
            is_trusted=True
        )
        db.session.add(device)
        db.session.commit()

        # Login
        resp = client.post('/auth/login', data={
            'email': 'test@example.com',
            'password': 'TestPass123!'
        }, headers={'User-Agent': ua}, environ_base={'REMOTE_ADDR': '127.0.0.1'}, follow_redirects=True)

        yield client, user
