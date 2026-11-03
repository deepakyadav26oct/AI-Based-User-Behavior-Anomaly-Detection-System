from .auth_routes import auth_bp
from .dashboard_routes import dashboard_bp
from .activity_routes import activity_bp
from .alert_routes import alert_bp
from .user_routes import user_bp
from .detection_routes import detection_bp
from .testing_routes import testing_bp
from .report_routes import report_bp
from .settings_routes import settings_bp

__all__ = [
    'auth_bp',
    'dashboard_bp',
    'activity_bp',
    'alert_bp',
    'user_bp',
    'detection_bp',
    'testing_bp',
    'report_bp',
    'settings_bp',
]
