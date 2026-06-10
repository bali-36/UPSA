"""
API Routes
==========
RESTful API endpoints for AJAX requests and data retrieval.
"""
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from ..services.notification_service import (
    get_notifications as get_notifs, mark_read, mark_all_read, get_unread_count
)

api_bp = Blueprint('api', __name__, url_prefix='/api')


@api_bp.route('/notifications')
@login_required
def get_notifications():
    """Get notifications for current user."""
    unread_only = request.args.get('unread_only', 'false').lower() == 'true'
    page = request.args.get('page', 1, type=int)
    notifs, total, pages = get_notifs(
        current_user.id, unread_only=unread_only, page=page
    )
    return jsonify({
        'notifications': [{
            'id': n.id,
            'title': n.title,
            'message': n.message,
            'type': n.type,
            'is_read': n.is_read,
            'created_at': n.created_at.isoformat() if n.created_at else None
        } for n in notifs],
        'total': total,
        'pages': pages
    })


@api_bp.route('/notifications/unread-count')
@login_required
def unread_count():
    """Get unread notification count."""
    return jsonify({'count': get_unread_count(current_user.id)})


@api_bp.route('/notifications/<int:notif_id>/read', methods=['PUT'])
@login_required
def mark_notification_read(notif_id):
    """Mark a notification as read."""
    success = mark_read(notif_id, current_user.id)
    return jsonify({'success': success})


@api_bp.route('/notifications/read-all', methods=['PUT'])
@login_required
def mark_all_notifications_read():
    """Mark all notifications as read."""
    count = mark_all_read(current_user.id)
    return jsonify({'success': True, 'count': count})
