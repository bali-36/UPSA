#!/usr/bin/env python3
"""
UPSA Entry Point
================
Run the Unified Privacy & Security Assistant application.
"""
import os
from app import create_app

# Determine environment from FLASK_ENV
env = os.environ.get('FLASK_ENV', 'development')
app = create_app(env)

if __name__ == '__main__':
    debug = env == 'development'
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=debug
    )
