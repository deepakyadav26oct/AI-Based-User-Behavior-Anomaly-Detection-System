import os
from pathlib import Path
from datetime import datetime, timedelta
from flask import Flask, redirect, url_for, request, render_template
from config import Config
from models.database import (
    db, User, LoginActivity, UserBehaviourProfile, DetectionResult, SecurityAlert, SystemSetting, BlockedIP
)
from modules.authentication import login_manager
from modules.behaviour_profiler import BehaviourProfiler
from modules.anomaly_detector import AnomalyDetectorService
from routes import (
    auth_bp, dashboard_bp, activity_bp, alert_bp,
    user_bp, detection_bp, testing_bp, report_bp, settings_bp
)

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure required directories exist
    os.makedirs(app.config['BASE_DIR'] / 'instance', exist_ok=True)
    os.makedirs(app.config['MODEL_DIR'], exist_ok=True)
    os.makedirs(app.config['DATASET_DIR'] / 'raw', exist_ok=True)
    os.makedirs(app.config['DATASET_DIR'] / 'processed', exist_ok=True)
    os.makedirs(app.config['REPORTS_DIR'], exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(activity_bp)
    app.register_blueprint(alert_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(detection_bp)
    app.register_blueprint(testing_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(settings_bp)

    @app.context_processor
    def inject_global_vars():
        open_alerts = 0
        try:
            open_alerts = SecurityAlert.query.filter_by(status='OPEN').count()
        except Exception:
            pass
        return {
            'now': datetime.utcnow(),
            'open_alerts_badge': open_alerts,
            'app_version': 'Sentinel AI v2.4 (CyberGuard)',
        }

    @app.before_request
    def ip_firewall_filter():
        # Bypass static files, health check, and unblock endpoints
        if request.path.startswith('/static') or request.path.startswith('/api/firewall/unblock') or request.path == '/health':
            return
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1').split(',')[0].strip()
        try:
            blocked = BlockedIP.query.filter_by(ip_address=client_ip, is_active=True).first()
            if blocked:
                return render_template('firewall_blocked.html', blocked=blocked, client_ip=client_ip), 403
        except Exception:
            pass

    @app.route('/health')
    def health_check():
        return {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'model_loaded': AnomalyDetectorService.get_service().is_model_trained
        }

    return app

def initialize_database_and_seed(app):
    """Seed initial administrator, test accounts, and baseline telemetry."""
    with app.app_context():
        db.create_all()

        # 1. Seed Admin User
        admin_username = Config.DEFAULT_ADMIN_USERNAME
        admin = User.query.filter_by(username=admin_username).first()
        if not admin:
            admin = User(
                username=admin_username,
                email=Config.DEFAULT_ADMIN_EMAIL,
                role='admin',
                department='Cyber Security Operations Center (SOC)',
                is_active=True
            )
            admin.set_password(Config.DEFAULT_ADMIN_PASSWORD)
            db.session.add(admin)
            db.session.commit()
            print(f"[Seed] Created Administrator: {admin_username} / {Config.DEFAULT_ADMIN_PASSWORD}")
            
            # Create admin profile
            BehaviourProfiler.get_or_create_profile(admin.id)

        # 2. Seed Default Staff Users & Profiles
        sample_users = [
            ('alice.chen', 'alice@cyberguard.internal', 'user', 'Software Engineering'),
            ('bob.martinez', 'bob@cyberguard.internal', 'user', 'Corporate Finance'),
            ('david.kim', 'david@cyberguard.internal', 'analyst', 'DevOps & Infrastructure'),
            ('eva.rossi', 'eva@cyberguard.internal', 'user', 'Human Resources'),
            ('frank.wright', 'frank@cyberguard.internal', 'analyst', 'Threat Intelligence')
        ]

        created_user_objects = []
        for uname, uemail, urole, udept in sample_users:
            u = User.query.filter_by(username=uname).first()
            if not u:
                u = User(
                    username=uname,
                    email=uemail,
                    role=urole,
                    department=udept,
                    is_active=True
                )
                u.set_password('User@SecurePass2026!')
                db.session.add(u)
                db.session.commit()
                created_user_objects.append(u)
                
                # Setup specific realistic baselines
                profile = BehaviourProfiler.get_or_create_profile(u.id)
                profile.known_ips = ['10.0.12.14', '10.0.12.25', '192.168.1.45']
                profile.known_devices = ['Desktop Workstation (Corporate Dell)', 'Laptop (ThinkPad X1)']
                profile.known_browsers = ['Google Chrome', 'Mozilla Firefox']
                profile.typical_login_hours = [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]
                db.session.commit()

        # 3. Seed initial historical activity logs if empty
        if LoginActivity.query.count() == 0:
            print("[Seed] Populating initial telemetry and detection history...")
            from modules.activity_monitor import ActivityMonitor
            import random

            now = datetime.utcnow()

            # Seed 35 normal past activities
            for i in range(35):
                u = random.choice(sample_users)
                past_time = now - timedelta(days=random.randint(0, 6), hours=random.randint(1, 12))
                ActivityMonitor.record_and_evaluate(
                    username=u[0],
                    login_status='SUCCESS',
                    ip_address=random.choice(['10.0.12.14', '10.0.12.25', '192.168.1.45']),
                    device_info='Desktop Workstation (Corporate Dell)',
                    browser='Google Chrome',
                    operating_system='Windows 11',
                    accessed_resource=random.choice(['/dashboard', '/profile', '/documents/shared', '/projects/tickets']),
                    resource_sensitivity='LOW',
                    session_duration=random.randint(900, 3600),
                    failed_login_count=0,
                    access_frequency=random.randint(1, 4),
                    is_simulated=False,
                    location='Corporate HQ / Domestic',
                    custom_hour=past_time.hour,
                    custom_day=past_time.weekday()
                )

            # Seed 5 suspicious / anomalous past activities
            suspicious_samples = [
                ('alice.chen', 'FAILED', '185.220.101.5', 'Automated Attack Rig', 'Automated CLI / Script', 'Ubuntu Linux', '/api/v1/auth/login', 'MEDIUM', 30, 8, 25, 2),
                ('bob.martinez', 'SUCCESS', '194.26.29.112', 'Penetration Testing Virtual Machine', 'Tor Browser', 'Kali Linux', '/admin/system-logs', 'HIGH', 600, 1, 6, 3),
                ('eva.rossi', 'SUCCESS', '91.240.118.23', 'Unknown Headless Machine', 'Mozilla Firefox', 'Windows 11', '/database/credentials', 'CRITICAL', 200, 0, 14, 1),
                ('david.kim', 'SUCCESS', '103.152.220.10', 'Laptop (ThinkPad X1)', 'Google Chrome', 'Windows 11', '/financial/payroll', 'HIGH', 1800, 0, 5, 23),
                ('alice.chen', 'FAILED', '45.154.255.89', 'Automated Attack Rig', 'Automated CLI / Script', 'Ubuntu Linux', '/api/v1/auth/login', 'MEDIUM', 25, 6, 20, 4),
            ]

            for uname, status, ip, dev, brw, os_name, res, sens, dur, fails, freq, hr in suspicious_samples:
                ActivityMonitor.record_and_evaluate(
                    username=uname,
                    login_status=status,
                    ip_address=ip,
                    device_info=dev,
                    browser=brw,
                    operating_system=os_name,
                    accessed_resource=res,
                    resource_sensitivity=sens,
                    session_duration=dur,
                    failed_login_count=fails,
                    access_frequency=freq,
                    is_simulated=False,
                    location='External Suspicious Ingress',
                    custom_hour=hr,
                    custom_day=2
                )
            print("[Seed] Successfully seeded initial activity records.")

app = create_app()

if __name__ == '__main__':
    initialize_database_and_seed(app)
    print("\n" + "=" * 65)
    print("  CYBERGUARD SENTINEL - AI USER BEHAVIOR ANOMALY DETECTION")
    print("=" * 65)
    print(f"  Access Portal: http://127.0.0.1:5000")
    print(f"  Default Admin Credentials:")
    print(f"    Username : {Config.DEFAULT_ADMIN_USERNAME}")
    print(f"    Password : {Config.DEFAULT_ADMIN_PASSWORD}")
    print("=" * 65 + "\n")
    app.run(host='127.0.0.1', port=5000, debug=True)
