"""
Notification Service
====================
Manages in-app notifications for users.
"""
from datetime import datetime
from ..extensions import db
from ..models.notification import Notification


def create_notification(user_id: int, title: str, message: str,
                        notif_type: str = 'info',
                        entity_type: str = None, entity_id: int = None) -> Notification:
    """Create a new notification for a user."""
    notif = Notification(
        user_id=user_id,
        title=title,
        message=message,
        type=notif_type,
        related_entity_type=entity_type,
        related_entity_id=entity_id
    )
    db.session.add(notif)
    db.session.commit()
    return notif


def get_notifications(user_id: int, unread_only: bool = False,
                      page: int = 1, per_page: int = 20) -> tuple:
    """Get paginated notifications for a user."""
    query = Notification.query.filter_by(user_id=user_id)
    if unread_only:
        query = query.filter_by(is_read=False)
    pagination = query.order_by(
        Notification.created_at.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    return pagination.items, pagination.total, pagination.pages


def get_unread_count(user_id: int) -> int:
    """Count unread notifications for a user."""
    return Notification.query.filter_by(user_id=user_id, is_read=False).count()


def mark_read(notification_id: int, user_id: int) -> bool:
    """Mark a notification as read."""
    notif = Notification.query.filter_by(
        id=notification_id, user_id=user_id
    ).first()
    if not notif:
        return False
    notif.mark_read()
    db.session.commit()
    return True


def mark_all_read(user_id: int) -> int:
    """Mark all notifications as read for a user. Returns count."""
    count = Notification.query.filter_by(
        user_id=user_id, is_read=False
    ).update({'is_read': True})
    db.session.commit()
    return count


def delete_notification(notification_id: int, user_id: int) -> bool:
    """Delete a notification."""
    notif = Notification.query.filter_by(
        id=notification_id, user_id=user_id
    ).first()
    if not notif:
        return False
    db.session.delete(notif)
    db.session.commit()
    return True
