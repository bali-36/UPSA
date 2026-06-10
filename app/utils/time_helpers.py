"""
Time Helpers
============
Human-readable time formatting utilities.
"""
from datetime import datetime, timedelta


def time_ago(dt: datetime) -> str:
    """Convert a datetime to a human-readable 'time ago' string."""
    if dt is None:
        return 'unknown'
    now = datetime.utcnow()
    diff = now - dt
    if diff < timedelta(minutes=1):
        return 'just now'
    elif diff < timedelta(hours=1):
        mins = int(diff.total_seconds() / 60)
        return f'{mins} minute{"s" if mins != 1 else ""} ago'
    elif diff < timedelta(days=1):
        hours = int(diff.total_seconds() / 3600)
        return f'{hours} hour{"s" if hours != 1 else ""} ago'
    elif diff < timedelta(days=30):
        days = diff.days
        return f'{days} day{"s" if days != 1 else ""} ago'
    elif diff < timedelta(days=365):
        months = int(diff.days / 30)
        return f'{months} month{"s" if months != 1 else ""} ago'
    else:
        years = int(diff.days / 365)
        return f'{years} year{"s" if years != 1 else ""} ago'


def format_datetime(dt: datetime, fmt: str = '%Y-%m-%d %H:%M') -> str:
    """Format datetime safely."""
    if dt is None:
        return 'N/A'
    return dt.strftime(fmt)


def days_since(dt: datetime) -> int:
    """Calculate days since a given datetime."""
    if dt is None:
        return 9999
    return (datetime.utcnow() - dt).days
