"""
Policy Paste Feature Tests
==========================
Tests for pasting privacy policy text.
"""
import os
import pytest
from flask import current_app
from app.models.policy_report import PolicyReport
from app.services.policy_analyzer import process_paste


class TestPolicyPasteService:
    """Tests for the process_paste service function."""

    def test_process_paste_too_short(self, app):
        """Service should fail if pasted text is less than 50 characters."""
        with app.app_context():
            report, error = process_paste(user_id=1, text="Short text.")
            assert report is None
            assert "at least 50 characters" in error

    def test_process_paste_success(self, app):
        """Service should successfully save, analyze, and store the report."""
        with app.app_context():
            # A longer dummy policy text to pass keyword matching rules and length requirement
            policy_text = (
                "We collect personal data like your name, email address, physical address, and gps location. "
                "We also collect device information and browser type. "
                "We sell data and share your data with advertising partners and marketing partners. "
                "We use tracking pixels, web beacons, and cookies. "
                "We retain your data indefinitely, but you can opt out and download your data."
            )
            report, error = process_paste(user_id=1, text=policy_text, title="Test Paste Policy")
            assert error is None
            assert report is not None
            assert report.original_filename == "Test Paste Policy.txt"
            assert report.file_type == "txt"
            assert report.overall_policy_score > 0
            
            # Verify the stored file exists
            file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], report.stored_filename)
            assert os.path.exists(file_path)
            
            # Clean up the file
            os.remove(file_path)


class TestPolicyPasteRoute:
    """Tests for the policy pasting route handler."""

    def test_paste_route_unauthenticated(self, client):
        """Unauthenticated requests should be redirected to login page."""
        resp = client.post('/policy-analyzer/paste', data={
            'policy_title': 'Test Policy',
            'policy_text': 'This is a test privacy policy that is long enough to satisfy character constraints.'
        })
        assert resp.status_code == 302
        assert '/auth/login' in resp.location

    def test_paste_route_empty_text(self, auth_client):
        """Route should show warning if no text is provided."""
        client, user = auth_client
        resp = client.post('/policy-analyzer/paste', data={
            'policy_title': 'Test Policy',
            'policy_text': ''
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b'No privacy policy text provided.' in resp.data

    def test_paste_route_success(self, auth_client, app):
        """Route should successfully process valid policy text and redirect to report."""
        client, user = auth_client
        policy_text = (
            "We collect personal data like your name, email address, physical address, and gps location. "
            "We also collect device information and browser type. "
            "We sell data and share your data with advertising partners and marketing partners. "
            "We use tracking pixels, web beacons, and cookies. "
            "We retain your data indefinitely, but you can opt out and download your data."
        )
        resp = client.post('/policy-analyzer/paste', data={
            'policy_title': 'Acme Corp Policy',
            'policy_text': policy_text
        }, follow_redirects=True)
        
        assert resp.status_code == 200
        assert b'Privacy policy analyzed successfully!' in resp.data
        
        # Verify database record is created
        with app.app_context():
            report = PolicyReport.query.filter_by(user_id=user.id, original_filename="Acme Corp Policy.txt").first()
            assert report is not None
            assert report.file_type == "txt"
            
            # Clean up the created physical file
            file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], report.stored_filename)
            if os.path.exists(file_path):
                os.remove(file_path)
