import pytest
from app import create_app
from config import Config
from models.database import db, User, LoginActivity, DetectionResult, SecurityAlert, UserBehaviourProfile
from modules.risk_engine import RiskEngine
from modules.alert_manager import AlertManager
from modules.behaviour_profiler import BehaviourProfiler

class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False

@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        # Seed test user
        user = User(username='target_user', email='target@test.local', role='user')
        user.set_password('Pass123!')
        db.session.add(user)
        db.session.commit()
        BehaviourProfiler.get_or_create_profile(user.id)

        yield app
        db.session.remove()
        db.drop_all()

def test_risk_engine_low_risk():
    activity_data = {
        'login_hour': 10,
        'failed_login_count': 0,
        'login_status': 'SUCCESS',
        'resource_sensitivity': 'LOW',
        'accessed_resource': '/dashboard',
        'session_duration': 1800,
        'access_frequency': 1
    }
    deviations = {
        'is_unusual_hour': False,
        'is_new_ip': False,
        'is_new_device': False,
        'is_abnormal_resource': False
    }
    ml_result = {
        'is_ml_anomaly': False,
        'ml_anomaly_score': 0.05
    }
    res = RiskEngine.evaluate(activity_data, deviations, ml_result)
    assert res['risk_level'] == 'Low'
    assert res['calculated_risk_score'] < 30.0

def test_risk_engine_high_risk_brute_force():
    activity_data = {
        'login_hour': 2,
        'failed_login_count': 8,
        'login_status': 'FAILED',
        'resource_sensitivity': 'CRITICAL',
        'accessed_resource': '/database/credentials',
        'operating_system': 'Kali Linux',
        'browser': 'Tor Browser',
        'session_duration': 30,
        'access_frequency': 25
    }
    deviations = {
        'is_unusual_hour': True,
        'is_new_ip': True,
        'is_new_device': True,
        'is_abnormal_resource': True
    }
    ml_result = {
        'is_ml_anomaly': True,
        'ml_anomaly_score': 0.85
    }
    res = RiskEngine.evaluate(activity_data, deviations, ml_result)
    assert res['risk_level'] == 'High'
    assert res['calculated_risk_score'] >= 70.0
    assert 'RULE_BRUTE_FORCE' in res['rule_flags']
    assert 'RULE_CRITICAL_RESOURCE' in res['rule_flags']
    assert 'RULE_UNUSUAL_HOUR' in res['rule_flags']

def test_alert_lifecycle(app):
    with app.app_context():
        user = User.query.filter_by(username='target_user').first()
        act = LoginActivity(
            user_id=user.id,
            username=user.username,
            ip_address='198.51.100.1',
            device_info='Unknown VM',
            browser='Tor Browser',
            operating_system='Kali Linux',
            login_status='SUCCESS',
            login_hour=2,
            day_of_week=0,
            accessed_resource='/database/credentials',
            resource_sensitivity='CRITICAL'
        )
        db.session.add(act)
        db.session.commit()

        det = DetectionResult(
            activity_id=act.id,
            user_id=user.id,
            ml_anomaly_score=0.9,
            is_ml_anomaly=True,
            calculated_risk_score=95.0,
            risk_level='High',
            reasons=['Critical asset breach signature']
        )
        db.session.add(det)
        db.session.commit()

        # Create alert
        risk_data = {
            'calculated_risk_score': 95.0,
            'rule_flags': ['RULE_CRITICAL_RESOURCE', 'RULE_ML_ANOMALY'],
            'reasons': ['Critical asset breach signature']
        }
        alert = AlertManager.create_alert_if_warranted(act, det, risk_data)
        assert alert is not None
        assert alert.status == 'OPEN'
        assert alert.severity == 'Critical'

        # Review alert
        AlertManager.review_alert(alert.id, 'analyst_reviewer')
        assert alert.status == 'IN_REVIEW'

        # Resolve alert
        AlertManager.resolve_alert(alert.id, 'Identity checked, authorized', 'analyst_resolver')
        assert alert.status == 'RESOLVED'
        assert alert.resolved_by == 'analyst_resolver'

def test_baseline_safeguards_against_contamination(app):
    with app.app_context():
        user = User.query.filter_by(username='target_user').first()
        profile = user.profile
        initial_ips = list(profile.known_ips)

        # 1. High risk event must NOT update baseline
        act_malicious = LoginActivity(
            user_id=user.id,
            username=user.username,
            ip_address='185.220.101.5',
            login_status='SUCCESS',
            login_hour=3,
            day_of_week=0,
            accessed_resource='/admin/system-logs'
        )
        db.session.add(act_malicious)
        db.session.commit()

        updated, msg = BehaviourProfiler.update_baseline(user.id, act_malicious, risk_score=85.0)
        assert updated is False
        assert 'exceeds safety threshold' in msg
        assert '185.220.101.5' not in profile.known_ips  # Baseline remains clean!

        # 2. Failed login must NOT update baseline
        act_failed = LoginActivity(
            user_id=user.id,
            username=user.username,
            ip_address='10.0.12.99',
            login_status='FAILED',
            login_hour=10,
            day_of_week=1,
            accessed_resource='/dashboard'
        )
        db.session.add(act_failed)
        db.session.commit()

        updated_fail, _ = BehaviourProfiler.update_baseline(user.id, act_failed, risk_score=15.0)
        assert updated_fail is False

        # 3. Legitimate low-risk login safely updates baseline
        act_legit = LoginActivity(
            user_id=user.id,
            username=user.username,
            ip_address='10.0.12.99',
            login_status='SUCCESS',
            login_hour=11,
            day_of_week=1,
            accessed_resource='/dashboard'
        )
        db.session.add(act_legit)
        db.session.commit()

        updated_legit, _ = BehaviourProfiler.update_baseline(user.id, act_legit, risk_score=5.0)
        assert updated_legit is True
        assert '10.0.12.99' in profile.known_ips

def test_impossible_travel_geo_velocity():
    from modules.geo_velocity import GeoVelocityEngine
    from datetime import datetime, timedelta

    # Delhi coordinates
    delhi_lat, delhi_lon = 28.6139, 77.2090
    # London coordinates
    london_lat, london_lon = 51.5074, -0.1278

    distance = GeoVelocityEngine.haversine_distance(delhi_lat, delhi_lon, london_lat, london_lon)
    assert distance > 6000.0  # Approx 6,700 km

    t1 = datetime(2026, 11, 1, 10, 0, 0)
    # 15 minutes later in London -> impossible!
    t2 = t1 + timedelta(minutes=15)

    eval_impossible = GeoVelocityEngine.evaluate_impossible_travel(
        last_lat=delhi_lat, last_lon=delhi_lon, last_time=t1, last_city='Delhi',
        curr_lat=london_lat, curr_lon=london_lon, curr_time=t2, curr_city='London'
    )
    assert eval_impossible['is_impossible_travel'] is True
    assert eval_impossible['velocity_kmh'] > 20000.0
    assert 'Impossible Travel Detected' in eval_impossible['reason']

    # 14 hours later in London -> realistic flight transit!
    t3 = t1 + timedelta(hours=14)
    eval_realistic = GeoVelocityEngine.evaluate_impossible_travel(
        last_lat=delhi_lat, last_lon=delhi_lon, last_time=t1, last_city='Delhi',
        curr_lat=london_lat, curr_lon=london_lon, curr_time=t3, curr_city='London'
    )
    assert eval_realistic['is_impossible_travel'] is False
    assert eval_realistic['velocity_kmh'] < 800.0

def test_automated_account_defense_and_unlock(app):
    with app.app_context():
        from modules.activity_monitor import ActivityMonitor
        user = User.query.filter_by(username='target_user').first()
        assert user.is_locked is False

        # Ingest a severe brute-force attack (8 failures, kali linux, critical asset)
        res = ActivityMonitor.record_and_evaluate(
            username=user.username,
            login_status='FAILED',
            ip_address='194.26.29.112',
            operating_system='Kali Linux',
            browser='Tor Browser',
            accessed_resource='/database/credentials',
            resource_sensitivity='CRITICAL',
            failed_login_count=8,
            access_frequency=20,
            is_simulated=False
        )

        db.session.refresh(user)
        assert res['calculated_risk_score'] >= 70.0
        assert user.is_locked is True
        assert 'Automated AI Lockdown' in user.lock_reason

def test_webhook_notifier_payloads():
    from modules.webhook_notifier import WebhookNotifier
    # 1. Platform Detection
    assert WebhookNotifier.detect_platform('https://discord.com/api/webhooks/123/abc') == 'discord'
    assert WebhookNotifier.detect_platform('https://discordapp.com/api/webhooks/456/def') == 'discord'
    assert WebhookNotifier.detect_platform('https://hooks.slack.com/services/T00/B00/X00') == 'slack'
    assert WebhookNotifier.detect_platform('https://soc.enterprise.internal/webhook') == 'generic'

    # 2. Discord Payload Schema
    discord_payload = WebhookNotifier.build_discord_payload(
        title="Impossible Travel Attack",
        description="Geographic speed violation",
        severity="Critical",
        risk_score=95.0,
        username="john.doe",
        ip_address="185.220.101.5",
        location="London, United Kingdom",
        resource="/admin/logs",
        rule_flags=["RULE_IMPOSSIBLE_TRAVEL"],
        reasons=["Velocity exceeded 800 km/h"],
        lockout_info="Account locked automatically",
        is_simulated=False
    )
    assert 'embeds' in discord_payload
    embed = discord_payload['embeds'][0]
    assert embed['color'] == 0xFF0033
    assert any(f['name'] == '👤 Target Principal' and 'john.doe' in f['value'] for f in embed['fields'])
    assert any(f['name'] == '🔒 Active Defense' and '[AI LOCKED]' in f['value'] for f in embed['fields'])

    # 3. Slack Payload Schema
    slack_payload = WebhookNotifier.build_slack_payload(
        title="Brute Force Authentication Storm",
        description="High failed attempts",
        severity="High",
        risk_score=85.0,
        username="jane.smith",
        ip_address="194.26.29.112",
        location="Frankfurt, Germany",
        resource="/database/credentials",
        rule_flags=["RULE_BRUTE_FORCE"],
        reasons=["8 failed login attempts"],
        lockout_info=None,
        is_simulated=True
    )
    assert 'attachments' in slack_payload
    assert 'SIMULATION' in slack_payload['text']

    # 4. Invalid ping check
    ping_res = WebhookNotifier.send_test_ping('not-a-valid-url')
    assert ping_res['success'] is False
    assert ping_res['status_code'] == 400

def test_webhook_settings_api(app):
    from models.database import User, SystemSetting
    client = app.test_client()
    with app.app_context():
        # Authenticate admin
        admin = User.query.filter_by(username='admin_webhook_tester').first()
        if not admin:
            admin = User(username='admin_webhook_tester', email='admin_webhook_tester@cyberguard.local', role='ADMIN')
            admin.set_password('AdminTest123!')
            db.session.add(admin)
            db.session.commit()

        with client.session_transaction() as sess:
            sess['_user_id'] = str(admin.id)
            sess['_fresh'] = True

        # Test invalid webhook endpoint call
        resp = client.post('/settings/test-webhook', json={'webhook_url': 'ftp://invalid'})
        assert resp.status_code == 200 or resp.status_code == 400
        data = resp.get_json()
        assert data['success'] is False

        # Test updating settings with webhook
        resp_update = client.post('/settings/update', data={
            'contamination': '0.08',
            'n_estimators': '150',
            'risk_low_max': '29',
            'risk_high_min': '70',
            'alert_trigger': '30',
            'webhook_enabled': 'true',
            'webhook_url': 'https://discord.com/api/webhooks/mock/test',
            'webhook_min_severity': 'HIGH'
        }, follow_redirects=True)
        assert resp_update.status_code == 200

        # Verify saved in database
        assert SystemSetting.get_setting('WEBHOOK_ENABLED') == 'true'
        assert 'discord.com' in SystemSetting.get_setting('WEBHOOK_URL')
        assert SystemSetting.get_setting('WEBHOOK_MIN_SEVERITY') == 'HIGH'
