"""
Tests for route and header fixes.
"""

def test_favicon(client):
    """Test that favicon.ico returns 200 OK and is served as image/png."""
    resp = client.get('/favicon.ico')
    assert resp.status_code == 200
    assert resp.mimetype == 'image/png'


def test_recalculate_get(auth_client):
    """Test that GET /privacy-center/recalculate returns 200 OK directly."""
    client, user = auth_client
    resp = client.get('/privacy-center/recalculate')
    assert resp.status_code == 200
    assert b'Privacy Center' in resp.data


def test_static_cache_and_200(client):
    """Test that static files ignore conditional headers and disable cache, returning 200."""
    headers = {
        'If-None-Match': 'some-etag',
        'If-Modified-Since': 'Fri, 05 Jun 2026 01:27:30 GMT'
    }
    resp = client.get('/static/css/custom.css', headers=headers)
    assert resp.status_code == 200
    assert 'no-cache' in resp.headers.get('Cache-Control', '')
    assert 'no-store' in resp.headers.get('Cache-Control', '')
    assert resp.headers.get('Expires') == '0'


def test_logout_direct(auth_client):
    """Test that logout returns 200 directly and clears session."""
    client, user = auth_client
    # Verify we can access a login-protected page first
    resp = client.get('/dashboard')
    assert resp.status_code == 200

    # Logout
    resp = client.get('/auth/logout')
    assert resp.status_code == 200
    assert b'You have been signed out' in resp.data

    # Try to access dashboard again - should redirect to login (since it requires auth)
    resp = client.get('/dashboard')
    assert resp.status_code == 302


def test_logout_with_remember_me(app, client):
    """Test that logging in with remember_me and then logging out clears the remember cookie."""
    with app.app_context():
        from app.models.user import User
        from app.extensions import db
        user = User(full_name='Remember User', email='remember@example.com')
        user.set_password('RememberPass123!')
        db.session.add(user)
        db.session.commit()

        # Add trusted device to avoid MFA
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

    # Login with remember_me
    resp = client.post('/auth/login', data={
        'email': 'remember@example.com',
        'password': 'RememberPass123!',
        'remember_me': 'on'
    }, headers={'User-Agent': ua}, environ_base={'REMOTE_ADDR': '127.0.0.1'}, follow_redirects=True)
    
    # Assert remember cookie is set
    cookie = client.get_cookie('remember_token')
    assert cookie is not None
    assert cookie.value != ''

    # Logout
    resp = client.get('/auth/logout')
    
    # Assert remember cookie is deleted or cleared
    cookie_after = client.get_cookie('remember_token')
    assert cookie_after is None or cookie_after.value == '' or cookie_after._should_delete()


def test_login_direct_200(app, client):
    """Test that POST /auth/login returns 200 OK directly on success instead of a redirect."""
    with app.app_context():
        from app.models.user import User
        from app.extensions import db
        user = User(full_name='Direct User', email='direct@example.com')
        user.set_password('DirectPass123!')
        db.session.add(user)
        db.session.commit()

        # Add trusted device to avoid MFA
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

    # Login without follow_redirects
    resp = client.post('/auth/login', data={
        'email': 'direct@example.com',
        'password': 'DirectPass123!'
    }, headers={'User-Agent': ua}, environ_base={'REMOTE_ADDR': '127.0.0.1'})
    
    # Assert it returns 200 directly
    assert resp.status_code == 200
    assert b'Dashboard' in resp.data or b'Welcome' in resp.data


def test_survey_results_filtering(app, auth_client):
    """Test that survey results screen filters questions correctly, explaining only weak/moderate items."""
    client, user = auth_client
    
    # Create a survey response: some questions are 4 (good), others are 1-3 (weak/moderate)
    with app.app_context():
        from app.models.survey_response import SurveyResponse
        from app.extensions import db
        
        survey = SurveyResponse(
            user_id=user.id,
            q1_reuse_password=4,  # Good
            q2_mfa_usage=4,       # Good
            q3_email_verify=2,    # Weak
            q4_location_perm=4,   # Good
            q5_privacy_review=4,  # Good
            q6_public_wifi=1,     # Very Weak
            q7_software_updates=4,# Good
            q8_backup_habits=4,   # Good
            q9_phishing_recognition=3, # Moderate
            q10_password_manager=4,# Good
            awareness_score=75,
            score_category='medium'
        )
        db.session.add(survey)
        db.session.commit()

    # Request the results page
    resp = client.get('/survey-center/results')
    assert resp.status_code == 200
    
    # Weak/moderate questions should be explained
    assert b'Email Link Verification' in resp.data
    assert b'Public Wi-Fi Safety' in resp.data
    assert b'Unexpected Email Attachments' in resp.data
    
    # Good questions should NOT be explained
    assert b'Password Reuse' not in resp.data
    assert b'Multi-Factor Authentication (MFA)' not in resp.data


def test_complete_recommendation_ajax(app, auth_client):
    """Test that completing a recommendation via AJAX returns 200 OK with JSON details."""
    client, user = auth_client
    
    with app.app_context():
        from app.models.recommendation import Recommendation
        from app.extensions import db
        
        # Create a mock recommendation for this user
        rec = Recommendation(
            user_id=user.id,
            category='mfa',
            title='Enable MFA',
            description='Enable Multi-Factor Authentication',
            plain_explanation='This will keep your account extra secure.',
            priority='high',
            is_completed=False
        )
        db.session.add(rec)
        db.session.commit()
        
        rec_id = rec.id

    # Now make the AJAX call to complete it
    headers = {
        'X-Requested-With': 'XMLHttpRequest'
    }
    resp = client.post(f'/recommendations/{rec_id}/complete', headers=headers)
    assert resp.status_code == 200
    
    data = resp.get_json()
    assert data is not None
    assert data['success'] is True
    assert 'overall_score' in data
    assert 'category_label' in data
    assert 'breakdown' in data
    
    # Verify in DB that it is marked completed
    with app.app_context():
        from app.models.recommendation import Recommendation
        updated_rec = Recommendation.query.get(rec_id)
        assert updated_rec.is_completed is True


def test_password_strength_calculation(app):
    """Test that setting user password calculates and stores password strength."""
    with app.app_context():
        from app.models.user import User
        from app.extensions import db
        
        user = User(full_name='Strength Tester', email='strength@example.com')
        # Weak password (length < 8)
        user.set_password('pass123')
        db.session.add(user)
        db.session.commit()
        
        # Weak password should score low (max score out of 25)
        assert user.password_strength <= 10

        # Strong password
        user2 = User(full_name='Strong Tester', email='strong@example.com')
        user2.set_password('StrongPass123!@#')
        db.session.add(user2)
        db.session.commit()
        
        # Strong password should score high (25/25)
        assert user2.password_strength == 25


def test_permissions_scoring_and_revocation_ajax(app, auth_client):
    """Test that website permissions are seeded, scored contextually, and can be revoked via AJAX."""
    client, user = auth_client
    
    # 1. Trigger calculate_privacy_score to seed default permissions
    with app.app_context():
        from app.services.privacy_service import calculate_privacy_score
        from app.models.website_permission import WebsitePermission
        
        score = calculate_privacy_score(user.id)
        
        # Check permissions seeded
        perms = WebsitePermission.query.filter_by(user_id=user.id).all()
        assert len(perms) == 9
        
        # Check inappropriate allowed permissions:
        # location: coolmathgames.com, adtrack.net (2) -> location_perm_score = max(0, 10 - 2*3) = 4
        assert score.location_perm_score == 4
        
        # Save a permission ID to revoke (coolmathgames.com location)
        bad_perm = WebsitePermission.query.filter_by(
            user_id=user.id,
            website='coolmathgames.com',
            permission_type='location'
        ).first()
        bad_perm_id = bad_perm.id

    # 2. Revoke it via AJAX
    headers = {
        'X-Requested-With': 'XMLHttpRequest'
    }
    resp = client.post(f'/privacy-center/permissions/{bad_perm_id}/revoke', headers=headers)
    assert resp.status_code == 200
    
    data = resp.get_json()
    assert data is not None
    assert data['success'] is True
    
    # After revoking 1 location permission, remaining bad location perm is 1 (adtrack.net)
    # New location_perm_score = 10 - 1*3 = 7
    assert data['breakdown']['location_perm_score'] == 7
    
    # Check database status
    with app.app_context():
        from app.models.website_permission import WebsitePermission
        revoked_perm = WebsitePermission.query.get(bad_perm_id)
        assert revoked_perm.is_allowed is False


def test_analytics_page_seeding(app, auth_client):
    """Test that rendering the analytics dashboard seeds historical data and endpoints return JSON trends."""
    client, user = auth_client

    # 1. Load the analytics page which triggers seeding
    resp = client.get('/analytics')
    assert resp.status_code == 200
    assert b'Behavioral Analytics' in resp.data

    # 2. Verify database records are seeded
    with app.app_context():
        from app.models.privacy_score import PrivacyScore
        from app.models.risk_event import RiskEvent
        from app.models.audit_log import AuditLog
        from app.models.frustration_metric import FrustrationMetric

        # We should have seeded multiple records for each metric type over 180 days
        assert PrivacyScore.query.filter_by(user_id=user.id).count() >= 50
        assert RiskEvent.query.filter_by(user_id=user.id).count() == 13
        assert AuditLog.query.filter_by(user_id=user.id).count() >= 50
        assert FrustrationMetric.query.filter_by(user_id=user.id).count() >= 30

    # 3. Verify endpoints return data in ChartJS-ready JSON format for views
    for view in ['daily', 'weekly', 'monthly']:
        resp_priv = client.get(f'/api/analytics/privacy-trend?view={view}')
        assert resp_priv.status_code == 200
        data_priv = resp_priv.get_json()
        assert 'data' in data_priv
        assert len(data_priv['data']) > 0
        assert 'score' in data_priv['data'][0]

        resp_risk = client.get(f'/api/analytics/risk-trend?view={view}')
        assert resp_risk.status_code == 200
        data_risk = resp_risk.get_json()
        assert 'data' in data_risk
        assert len(data_risk['data']) > 0
        assert 'risk_score' in data_risk['data'][0]

        resp_login = client.get(f'/api/analytics/login-activity?view={view}')
        assert resp_login.status_code == 200
        data_login = resp_login.get_json()
        assert 'data' in data_login
        assert len(data_login['data']) > 0
        assert 'successful' in data_login['data'][0]
        assert 'failed' in data_login['data'][0]

        resp_frust = client.get(f'/api/analytics/frustration-trend?view={view}')
        assert resp_frust.status_code == 200
        data_frust = resp_frust.get_json()
        assert 'data' in data_frust
        assert len(data_frust['data']) > 0
        assert 'frustration_score' in data_frust['data'][0]


def test_auth_verify_redirect(client):
    """Test that GET/POST /auth/verify redirects to /auth/mfa-verify."""
    resp = client.get('/auth/verify')
    assert resp.status_code == 302
    assert '/auth/mfa-verify' in resp.location

    resp_post = client.post('/auth/verify')
    assert resp_post.status_code == 302
    assert '/auth/mfa-verify' in resp_post.location


def test_privacy_score_normalization(app):
    """Test that overall privacy score is normalized (overall / 110 * 100)."""
    with app.app_context():
        from app.models.user import User
        from app.services.privacy_service import calculate_privacy_score
        from app.extensions import db

        # Create user with strong password (25) but no MFA (0), no survey (0)
        # default permissions will be seeded (browser=0, loc=4, cam=1, notif=3)
        # pwd age = 15
        # sum of scores = 0 + 25 + 15 + 0 + 4 + 1 + 3 + 0 = 48
        # normalized = round((48 / 110) * 100) = 44
        user = User(full_name='Normal Test', email='normal@test.com')
        user.set_password('StrongPass123!@#')
        db.session.add(user)
        db.session.commit()

        score = calculate_privacy_score(user.id, user)
        assert score.overall_score == 44




