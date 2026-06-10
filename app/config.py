"""
UPSA Configuration
==================
Environment-based configuration for the Flask application.
"""
import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Base configuration shared across all environments."""

    # Flask core
    SECRET_KEY = os.environ.get('SECRET_KEY') or (
        'upsa-dev-secret-key-change-in-production-2026')

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL') or f'sqlite:///{os.path.join(basedir, "..", "instance", "upsa.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'connect_args': {'check_same_thread': False}
    }

    # Mail settings
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'localhost')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ('true', '1', 'yes')
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'false').lower() in ('true', '1', 'yes')
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get(
        'MAIL_DEFAULT_SENDER', 'UPSA <noreply@upsa.local>')

    # Session / Security
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = False  # Set True in production with HTTPS
    REMEMBER_COOKIE_DURATION = timedelta(days=14)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = 'Lax'

    # Upload
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB
    UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads')
    ALLOWED_EXTENSIONS = {'pdf', 'docx', 'txt'}

    # bcrypt
    BCRYPT_LOG_ROUNDS = 12

    # CSRF
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour

    # Rate limiting
    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')
    RATELIMIT_STRATEGY = 'fixed-window'
    RATELIMIT_DEFAULT = '200 per hour'

    # Auth rate limits
    LOGIN_RATE_LIMIT = '5 per 5 minutes'
    REGISTER_RATE_LIMIT = '3 per 15 minutes'
    PASSWORD_RESET_RATE_LIMIT = '3 per hour'

    # MFA
    MFA_CODE_EXPIRY = 300  # 5 minutes
    MFA_CODE_LENGTH = 6

    # Account lockout
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = 900  # 15 minutes

    # ML
    ML_MODEL_PATH = os.path.join(basedir, '..', 'ml', 'models')

    # Risk engine defaults
    RISK_RULES = {
        'new_device': 25,
        'new_browser': 20,
        'new_location': 30,
        'unusual_time': 15,
        'failed_attempts': 25,
        'impossible_travel': 40
    }
    RISK_THRESHOLDS = {
        'low': 30,
        'medium': 60
    }

    # Pagination
    DEFAULT_PAGE_SIZE = 10
    MAX_PAGE_SIZE = 100


class DevelopmentConfig(Config):
    """Development environment configuration."""
    DEBUG = True
    TESTING = False
    SESSION_COOKIE_SECURE = False


class TestingConfig(Config):
    """Testing environment configuration."""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    MAIL_SUPPRESS_SEND = True
    RATELIMIT_ENABLED = False
    BCRYPT_LOG_ROUNDS = 4  # Faster for tests
    LOGIN_RATE_LIMIT = '1000 per minute'
    REGISTER_RATE_LIMIT = '1000 per minute'


class ProductionConfig(Config):
    """Production environment configuration."""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    BCRYPT_LOG_ROUNDS = 13


def get_config(env=None):
    """Return the appropriate configuration class."""
    if env is None:
        env = os.environ.get('FLASK_ENV', 'development')
    configs = {
        'development': DevelopmentConfig,
        'testing': TestingConfig,
        'production': ProductionConfig
    }
    return configs.get(env, DevelopmentConfig)
