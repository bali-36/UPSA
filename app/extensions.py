"""
UPSA Flask Extensions
=====================
Centralized initialization of all Flask extensions.
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# SQLAlchemy ORM
db = SQLAlchemy()

# Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please sign in to access this page.'
login_manager.login_message_category = 'warning'

# Flask-Mail
mail = Mail()

# Flask-Migrate (Alembic)
migrate = Migrate()

# CSRF Protection
csrf = CSRFProtect()

# Rate Limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=['200 per hour']
)


def init_extensions(app):
    """Initialize all extensions with the Flask app instance."""
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    limiter.init_app(app)

    # Register user loader for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        from .models import User
        return User.query.get(int(user_id))
