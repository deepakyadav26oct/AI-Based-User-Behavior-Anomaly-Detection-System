import json
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='analyst', nullable=False)  # admin, analyst, user
    department = db.Column(db.String(64), default='Security Operations')
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_locked = db.Column(db.Boolean, default=False, nullable=False)
    lock_reason = db.Column(db.String(256), nullable=True)
    locked_at = db.Column(db.DateTime, nullable=True)
    last_latitude = db.Column(db.Float, nullable=True)
    last_longitude = db.Column(db.Float, nullable=True)
    last_city = db.Column(db.String(64), nullable=True)
    last_country = db.Column(db.String(64), nullable=True)
    last_activity_time = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    activities = db.relationship('LoginActivity', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    profile = db.relationship('UserBehaviourProfile', backref='user', uselist=False, cascade='all, delete-orphan')
    alerts = db.relationship('SecurityAlert', backref='user', lazy='dynamic')
    detection_results = db.relationship('DetectionResult', backref='user', lazy='dynamic')

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        return self.role.lower() == 'admin'

    @property
    def is_analyst(self) -> bool:
        return self.role.lower() in ('admin', 'analyst')

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'department': self.department,
            'is_active': self.is_active,
            'is_locked': self.is_locked,
            'lock_reason': self.lock_reason,
            'locked_at': self.locked_at.strftime('%Y-%m-%d %H:%M:%S') if self.locked_at else None,
            'last_city': self.last_city,
            'last_country': self.last_country,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login_at': self.last_login_at.isoformat() if self.last_login_at else None,
            'has_profile': self.profile is not None
        }


class LoginActivity(db.Model):
    __tablename__ = 'login_activities'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    username = db.Column(db.String(64), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    device_info = db.Column(db.String(64), nullable=False, default='Desktop Workstation')
    browser = db.Column(db.String(64), nullable=False, default='Chrome')
    operating_system = db.Column(db.String(64), nullable=False, default='Windows 11')
    login_status = db.Column(db.String(20), nullable=False, default='SUCCESS')  # SUCCESS, FAILED
    login_hour = db.Column(db.Integer, nullable=False)  # 0-23
    day_of_week = db.Column(db.Integer, nullable=False)  # 0-6 (Mon-Sun)
    accessed_resource = db.Column(db.String(200), nullable=False, default='/dashboard')
    resource_sensitivity = db.Column(db.String(20), nullable=False, default='LOW')  # LOW, MEDIUM, HIGH, CRITICAL
    session_duration = db.Column(db.Integer, default=1800)  # seconds
    failed_login_count = db.Column(db.Integer, default=0)
    is_simulated = db.Column(db.Boolean, default=False, nullable=False, index=True)
    location = db.Column(db.String(100), default='Corporate HQ')
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    city = db.Column(db.String(64), default='Delhi')
    country = db.Column(db.String(64), default='India')

    # Relationships
    detection_result = db.relationship('DetectionResult', backref='activity', uselist=False, cascade='all, delete-orphan')
    alert = db.relationship('SecurityAlert', backref='activity', uselist=False)

    def to_dict(self):
        det = self.detection_result
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.username,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'ip_address': self.ip_address,
            'device_info': self.device_info,
            'browser': self.browser,
            'operating_system': self.operating_system,
            'login_status': self.login_status,
            'login_hour': self.login_hour,
            'day_of_week': self.day_of_week,
            'accessed_resource': self.accessed_resource,
            'resource_sensitivity': self.resource_sensitivity,
            'session_duration': self.session_duration,
            'failed_login_count': self.failed_login_count,
            'is_simulated': self.is_simulated,
            'location': self.location,
            'city': self.city,
            'country': self.country,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'risk_score': det.calculated_risk_score if det else None,
            'risk_level': det.risk_level if det else 'Unknown',
            'is_ml_anomaly': det.is_ml_anomaly if det else False
        }


class UserBehaviourProfile(db.Model):
    __tablename__ = 'user_behaviour_profiles'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), unique=True, nullable=False)
    typical_login_hours_raw = db.Column(db.Text, default='[8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]')
    known_ips_raw = db.Column(db.Text, default='[]')
    known_devices_raw = db.Column(db.Text, default='[]')
    known_browsers_raw = db.Column(db.Text, default='[]')
    typical_resources_raw = db.Column(db.Text, default='["/dashboard", "/profile"]')
    avg_session_duration = db.Column(db.Float, default=1800.0)
    total_logins = db.Column(db.Integer, default=0)
    total_failed_logins = db.Column(db.Integer, default=0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    is_baseline_locked = db.Column(db.Boolean, default=False, nullable=False)

    @property
    def typical_login_hours(self):
        try:
            return json.loads(self.typical_login_hours_raw or '[]')
        except Exception:
            return [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]

    @typical_login_hours.setter
    def typical_login_hours(self, val):
        self.typical_login_hours_raw = json.dumps(list(set(int(x) for x in val)))

    @property
    def known_ips(self):
        try:
            return json.loads(self.known_ips_raw or '[]')
        except Exception:
            return []

    @known_ips.setter
    def known_ips(self, val):
        self.known_ips_raw = json.dumps(list(set(str(x) for x in val)))

    @property
    def known_devices(self):
        try:
            return json.loads(self.known_devices_raw or '[]')
        except Exception:
            return []

    @known_devices.setter
    def known_devices(self, val):
        self.known_devices_raw = json.dumps(list(set(str(x) for x in val)))

    @property
    def known_browsers(self):
        try:
            return json.loads(self.known_browsers_raw or '[]')
        except Exception:
            return []

    @known_browsers.setter
    def known_browsers(self, val):
        self.known_browsers_raw = json.dumps(list(set(str(x) for x in val)))

    @property
    def typical_resources(self):
        try:
            return json.loads(self.typical_resources_raw or '[]')
        except Exception:
            return []

    @typical_resources.setter
    def typical_resources(self, val):
        self.typical_resources_raw = json.dumps(list(set(str(x) for x in val)))

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'typical_login_hours': self.typical_login_hours,
            'known_ips': self.known_ips,
            'known_devices': self.known_devices,
            'known_browsers': self.known_browsers,
            'typical_resources': self.typical_resources,
            'avg_session_duration': round(self.avg_session_duration, 1),
            'total_logins': self.total_logins,
            'total_failed_logins': self.total_failed_logins,
            'is_baseline_locked': self.is_baseline_locked,
            'last_updated': self.last_updated.strftime('%Y-%m-%d %H:%M:%S') if self.last_updated else None
        }


class DetectionResult(db.Model):
    __tablename__ = 'detection_results'

    id = db.Column(db.Integer, primary_key=True)
    activity_id = db.Column(db.Integer, db.ForeignKey('login_activities.id', ondelete='CASCADE'), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    ml_anomaly_score = db.Column(db.Float, nullable=False)  # Normalized decision score
    is_ml_anomaly = db.Column(db.Boolean, default=False, nullable=False)
    rule_flags_raw = db.Column(db.Text, default='[]')
    calculated_risk_score = db.Column(db.Float, nullable=False)  # 0 to 100
    risk_level = db.Column(db.String(20), nullable=False)  # Low, Medium, High
    reasons_raw = db.Column(db.Text, default='[]')
    evaluated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    @property
    def rule_flags(self):
        try:
            return json.loads(self.rule_flags_raw or '[]')
        except Exception:
            return []

    @rule_flags.setter
    def rule_flags(self, val):
        self.rule_flags_raw = json.dumps(list(val))

    @property
    def reasons(self):
        try:
            return json.loads(self.reasons_raw or '[]')
        except Exception:
            return []

    @reasons.setter
    def reasons(self, val):
        self.reasons_raw = json.dumps(list(val))

    def to_dict(self):
        return {
            'id': self.id,
            'activity_id': self.activity_id,
            'user_id': self.user_id,
            'ml_anomaly_score': round(self.ml_anomaly_score, 4),
            'is_ml_anomaly': self.is_ml_anomaly,
            'rule_flags': self.rule_flags,
            'calculated_risk_score': round(self.calculated_risk_score, 1),
            'risk_level': self.risk_level,
            'reasons': self.reasons,
            'evaluated_at': self.evaluated_at.strftime('%Y-%m-%d %H:%M:%S')
        }


class SecurityAlert(db.Model):
    __tablename__ = 'security_alerts'

    id = db.Column(db.Integer, primary_key=True)
    activity_id = db.Column(db.Integer, db.ForeignKey('login_activities.id', ondelete='CASCADE'), nullable=True)
    detection_result_id = db.Column(db.Integer, db.ForeignKey('detection_results.id', ondelete='SET NULL'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    username = db.Column(db.String(64), nullable=False, index=True)
    alert_title = db.Column(db.String(150), nullable=False)
    alert_type = db.Column(db.String(64), nullable=False)  # UNUSUAL_HOUR, NEW_IP, NEW_DEVICE, BRUTE_FORCE, etc.
    severity = db.Column(db.String(20), nullable=False)  # Low, Medium, High, Critical
    risk_score = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='OPEN', nullable=False, index=True)  # OPEN, IN_REVIEW, RESOLVED, DISMISSED
    reasons_raw = db.Column(db.Text, default='[]')
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by = db.Column(db.String(64), nullable=True)
    resolution_notes = db.Column(db.Text, nullable=True)
    is_simulated = db.Column(db.Boolean, default=False, nullable=False, index=True)

    @property
    def reasons(self):
        try:
            return json.loads(self.reasons_raw or '[]')
        except Exception:
            return []

    @reasons.setter
    def reasons(self, val):
        self.reasons_raw = json.dumps(list(val))

    def to_dict(self):
        act = self.activity
        return {
            'id': self.id,
            'activity_id': self.activity_id,
            'user_id': self.user_id,
            'username': self.username,
            'alert_title': self.alert_title,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'risk_score': round(self.risk_score, 1),
            'status': self.status,
            'reasons': self.reasons,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'resolved_at': self.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if self.resolved_at else None,
            'resolved_by': self.resolved_by,
            'resolution_notes': self.resolution_notes,
            'is_simulated': self.is_simulated,
            'ip_address': act.ip_address if act else 'N/A',
            'device_info': act.device_info if act else 'N/A'
        }


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    user_id = db.Column(db.Integer, nullable=True)
    username = db.Column(db.String(64), nullable=False)
    action = db.Column(db.String(64), nullable=False)
    details = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'user_id': self.user_id,
            'username': self.username,
            'action': self.action,
            'details': self.details,
            'ip_address': self.ip_address
        }


class SystemSetting(db.Model):
    __tablename__ = 'system_settings'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.String(256), nullable=False)
    description = db.Column(db.String(256), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @classmethod
    def get_setting(cls, key: str, default: str = None) -> str:
        row = cls.query.filter_by(key=key).first()
        return row.value if row else default

    @classmethod
    def set_setting(cls, key: str, value: str, description: str = None):
        row = cls.query.filter_by(key=key).first()
        if row:
            row.value = str(value)
            if description:
                row.description = description
        else:
            row = cls(key=key, value=str(value), description=description)
            db.session.add(row)
        db.session.commit()


class BlockedIP(db.Model):
    __tablename__ = 'blocked_ips'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    reason = db.Column(db.String(256), nullable=False)
    blocked_by = db.Column(db.String(64), default='Sentinel SOAR Engine', nullable=False)
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'reason': self.reason,
            'blocked_by': self.blocked_by,
            'blocked_at': self.blocked_at.strftime('%Y-%m-%d %H:%M:%S'),
            'is_active': self.is_active
        }
