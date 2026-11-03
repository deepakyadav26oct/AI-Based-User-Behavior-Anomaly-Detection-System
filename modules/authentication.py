from functools import wraps
from flask import abort, redirect, url_for, flash, request
from flask_login import LoginManager, current_user
from models.database import User, AuditLog, db

login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Authentication required to access CyberGuard Sentinel.'
login_manager.login_message_category = 'warning'

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login', next=request.url))
        if not current_user.is_admin:
            flash('Access denied: Administrator privileges required for this section.', 'danger')
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def analyst_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login', next=request.url))
        if not current_user.is_analyst:
            flash('Access denied: Security Analyst or Admin role required.', 'danger')
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def log_audit_event(action: str, details: str, user=None, ip: str = None):
    """Utility to record administrative and security actions in AuditLog."""
    try:
        username = user.username if user and hasattr(user, 'username') else (
            current_user.username if current_user.is_authenticated else 'SYSTEM'
        )
        user_id = user.id if user and hasattr(user, 'id') else (
            current_user.id if current_user.is_authenticated else None
        )
        client_ip = ip or (request.remote_addr if request else '127.0.0.1')
        
        entry = AuditLog(
            user_id=user_id,
            username=username,
            action=action,
            details=details,
            ip_address=client_ip
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
