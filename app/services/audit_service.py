"""
Audit Service
=============
Centralized audit logging for all security-relevant actions.
"""
import json
from flask import request
from ..extensions import db
from ..models.audit_log import AuditLog


def log_action(action: str, user_id: int = None, entity_type: str = None,
               entity_id: int = None, result: str = 'success',
               details: dict = None) -> AuditLog:
    """
    Create an audit log entry.

    Args:
        action: Action code (e.g., 'user_login', 'password_change')
        user_id: ID of the acting user (None for anonymous)
        entity_type: Type of affected entity
        entity_id: ID of affected entity
        result: 'success', 'failure', 'blocked', or 'info'
        details: Arbitrary JSON-serializable details dict
    """
    try:
        log = AuditLog(
            user_id=user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            ip_address=_get_client_ip(),
            user_agent=request.headers.get('User-Agent', '')[:500] if request else None,
            result=result,
            details_json=json.dumps(details) if details else None
        )
        db.session.add(log)
        db.session.commit()
        return log
    except Exception:
        db.session.rollback()
        return None


def get_recent_logs(user_id: int = None, action: str = None,
                    result: str = None, limit: int = 50) -> list:
    """Get recent audit logs with optional filtering."""
    query = AuditLog.query
    if user_id:
        query = query.filter_by(user_id=user_id)
    if action:
        query = query.filter_by(action=action)
    if result:
        query = query.filter_by(result=result)
    return query.order_by(AuditLog.created_at.desc()).limit(limit).all()


def get_logs_paginated(page: int = 1, per_page: int = 20,
                       user_id: int = None, action: str = None,
                       result: str = None) -> tuple:
    """Get paginated audit logs with filtering."""
    query = AuditLog.query
    if user_id:
        query = query.filter_by(user_id=user_id)
    if action:
        query = query.filter_by(action=action)
    if result:
        query = query.filter_by(result=result)
    pagination = query.order_by(
        AuditLog.created_at.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    return pagination.items, pagination.total, pagination.pages


def _get_client_ip() -> str:
    """Extract client IP from request."""
    if not request:
        return None
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr
