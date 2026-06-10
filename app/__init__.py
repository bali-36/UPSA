"""
UPSA Application Factory
========================
Creates and configures the Flask application instance.
"""
import os
import logging
from flask import Flask, render_template, request
from .config import get_config
from .extensions import db, login_manager, mail, migrate, csrf, limiter, init_extensions


def create_app(env=None):
    """Application factory pattern — creates and configures the Flask app."""
    app = Flask(
        __name__,
        template_folder='templates',
        static_folder='static'
    )

    # Load configuration
    config_class = get_config(env)
    app.config.from_object(config_class)

    # Ensure upload folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['ML_MODEL_PATH'], exist_ok=True)

    # Initialize extensions
    init_extensions(app)

    # Register blueprints
    _register_blueprints(app)

    # Register error handlers
    _register_error_handlers(app)

    # Force 200 OK instead of 304 Not Modified for static files
    @app.before_request
    def remove_conditional_headers():
        if request.path.startswith('/static/'):
            request.environ.pop('HTTP_IF_NONE_MATCH', None)
            request.environ.pop('HTTP_IF_MODIFIED_SINCE', None)

    @app.after_request
    def disable_static_caching(response):
        if request.path.startswith('/static/'):
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

    # Setup logging
    _setup_logging(app)

    # Shell context
    @app.shell_context_processor
    def shell_context():
        from .models import (
            User, Session, TrustedDevice, RiskEvent, PrivacyScore,
            FrustrationMetric, PolicyReport, Recommendation, SurveyResponse,
            SUSResponse, MLPrediction, Notification, AuditLog,
            PasswordReset, EmailVerification, WebsitePermission
        )
        return {
            'db': db,
            'User': User,
            'Session': Session,
            'TrustedDevice': TrustedDevice,
            'RiskEvent': RiskEvent,
            'PrivacyScore': PrivacyScore,
            'FrustrationMetric': FrustrationMetric,
            'PolicyReport': PolicyReport,
            'Recommendation': Recommendation,
            'SurveyResponse': SurveyResponse,
            'SUSResponse': SUSResponse,
            'MLPrediction': MLPrediction,
            'Notification': Notification,
            'AuditLog': AuditLog,
            'PasswordReset': PasswordReset,
            'EmailVerification': EmailVerification,
            'WebsitePermission': WebsitePermission
        }

    # Create tables
    with app.app_context():
        db.create_all()
        # Self-healing database migration for users table
        try:
            db.session.execute(db.text("ALTER TABLE users ADD COLUMN password_strength INTEGER DEFAULT 15"))
            db.session.commit()
        except Exception:
            db.session.rollback()

    return app


def _register_blueprints(app):
    """Register all Flask blueprints."""
    from .routes.auth import auth_bp
    from .routes.main import main_bp
    from .routes.dashboard import dashboard_bp
    from .routes.privacy import privacy_bp
    from .routes.risk import risk_bp
    from .routes.security import security_bp
    from .routes.policy import policy_bp
    from .routes.recommendations import recommendations_bp
    from .routes.survey import survey_bp
    from .routes.analytics import analytics_bp
    from .routes.admin import admin_bp
    from .routes.settings import settings_bp
    from .routes.api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(privacy_bp)
    app.register_blueprint(risk_bp)
    app.register_blueprint(security_bp)
    app.register_blueprint(policy_bp)
    app.register_blueprint(recommendations_bp)
    app.register_blueprint(survey_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(api_bp)


def _register_error_handlers(app):
    """Register custom error pages."""
    @app.errorhandler(400)
    def bad_request(error):
        return render_template('errors/400.html'), 400

    @app.errorhandler(403)
    def forbidden(error):
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(429)
    def rate_limited(error):
        return render_template('errors/429.html'), 429

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('errors/500.html'), 500


def _setup_logging(app):
    """Configure application logging."""
    if not app.debug:
        # Production logging
        handler = logging.StreamHandler()
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        app.logger.addHandler(handler)
        app.logger.setLevel(logging.INFO)
    else:
        app.logger.setLevel(logging.DEBUG)
