"""
Main Routes
===========
Landing page and static pages.
"""
import base64
from flask import Blueprint, render_template, Response

main_bp = Blueprint('main', __name__)


@main_bp.route('/favicon.ico')
def favicon():
    """Serve a 1x1 transparent PNG as a favicon to prevent 404 errors."""
    png_data = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=')
    return Response(png_data, mimetype='image/png')


@main_bp.route('/')
def index():
    """Landing page."""
    return render_template('landing.html')


@main_bp.route('/about')
def about():
    """About page."""
    return render_template('landing.html', scroll_to='about')


@main_bp.route('/contact')
def contact():
    """Contact/support page."""
    return render_template('landing.html', scroll_to='contact')
