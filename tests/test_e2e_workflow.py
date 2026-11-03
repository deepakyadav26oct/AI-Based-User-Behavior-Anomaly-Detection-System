import pytest
from app import create_app, initialize_database_and_seed
from config import Config
from models.database import db, User, SecurityAlert, LoginActivity

class E2EConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False

@pytest.fixture
def test_app():
    app = create_app(E2EConfig)
    initialize_database_and_seed(app)
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()

@pytest.fixture
def admin_client(test_app):
    client = test_app.test_client()
    # Log in as seeded administrator
    res = client.post('/login', data={
        'username': Config.DEFAULT_ADMIN_USERNAME,
        'password': Config.DEFAULT_ADMIN_PASSWORD
    }, follow_redirects=True)
    assert res.status_code == 200
    return client

def test_dashboard_page(admin_client):
    res = admin_client.get('/')
    assert res.status_code == 200
    assert b'Security Monitoring Dashboard' in res.data
    assert b'Total Users' in res.data
    assert b'Isolation Forest' in res.data

def test_dashboard_api_stats_and_charts(admin_client):
    res_stats = admin_client.get('/api/dashboard/stats')
    assert res_stats.status_code == 200
    data = res_stats.get_json()
    assert 'total_users' in data
    assert 'suspicious_activities' in data

    res_charts = admin_client.get('/api/dashboard/charts')
    assert res_charts.status_code == 200
    chart_data = res_charts.get_json()
    assert 'anomaly_doughnut' in chart_data
    assert 'risk_distribution' in chart_data
    assert 'activity_trend' in chart_data

def test_activities_page_and_api(admin_client):
    res = admin_client.get('/activities')
    assert res.status_code == 200
    assert b'Monitored User Activities' in res.data

    # Test single activity detail JSON API
    with admin_client.application.app_context():
        act = LoginActivity.query.first()
        act_id = act.id

    res_detail = admin_client.get(f'/api/activities/{act_id}')
    assert res_detail.status_code == 200
    detail_data = res_detail.get_json()
    assert 'activity' in detail_data
    assert detail_data['activity']['id'] == act_id

def test_alerts_page_and_triage(admin_client):
    res = admin_client.get('/alerts')
    assert res.status_code == 200
    assert b'Security Alerts Management' in res.data

    with admin_client.application.app_context():
        alert = SecurityAlert.query.first()
        alert_id = alert.id if alert else None

    if alert_id:
        # Test review
        res_rev = admin_client.post(f'/alerts/{alert_id}/review', follow_redirects=True)
        assert res_rev.status_code == 200

        # Test resolve
        res_res = admin_client.post(f'/alerts/{alert_id}/resolve', data={
            'resolution_notes': 'E2E Test Resolution Verified'
        }, follow_redirects=True)
        assert res_res.status_code == 200

def test_detection_center_and_interactive_inspector(admin_client):
    res = admin_client.get('/detection')
    assert res.status_code == 200
    assert b'Machine Learning Anomaly Detection Center' in res.data
    assert b'Isolation Forest' in res.data

    # Test inspection API
    payload = {
        'login_hour': 2,
        'failed_login_count': 6,
        'session_duration': 30,
        'access_frequency': 20,
        'accessed_resource': '/database/credentials',
        'resource_sensitivity': 'CRITICAL',
        'operating_system': 'Kali Linux',
        'is_new_ip': True,
        'is_new_device': True
    }
    res_insp = admin_client.post('/api/detection/inspect', json=payload)
    assert res_insp.status_code == 200
    insp_data = res_insp.get_json()
    assert 'ml_evaluation' in insp_data
    assert 'risk_evaluation' in insp_data
    assert insp_data['risk_evaluation']['risk_level'] == 'High'

def test_testing_simulation_lab(admin_client):
    res = admin_client.get('/testing')
    assert res.status_code == 200
    assert b'Security Simulation &amp; Testing Lab' in res.data or b'Security Simulation' in res.data

    # Run brute force simulation
    res_sim = admin_client.post('/api/simulation/run', json={
        'scenario': 'brute_force',
        'username': 'alice.chen'
    })
    assert res_sim.status_code == 200
    sim_data = res_sim.get_json()
    assert sim_data['is_simulated'] is True
    assert sim_data['calculated_risk_score'] >= 70.0

def test_users_management_page(admin_client):
    res = admin_client.get('/users')
    assert res.status_code == 200
    assert b'User Management &amp; Profile Baselines' in res.data or b'User Management' in res.data
    assert b'alice.chen' in res.data

def test_reports_page_and_generation(admin_client):
    res = admin_client.get('/reports')
    assert res.status_code == 200
    assert b'Security Reports &amp; Compliance Audit' in res.data or b'Security Reports' in res.data

    # Test report generation
    res_gen = admin_client.post('/reports/generate', follow_redirects=True)
    assert res_gen.status_code == 200
    assert b'generated successfully' in res_gen.data

def test_settings_page_and_update(admin_client):
    res = admin_client.get('/settings')
    assert res.status_code == 200
    assert b'System Settings &amp; Operational Governance' in res.data or b'System Settings' in res.data

    # Update settings
    res_update = admin_client.post('/settings/update', data={
        'contamination': '0.09',
        'n_estimators': '160',
        'risk_low_max': '28',
        'risk_high_min': '72',
        'alert_trigger': '32'
    }, follow_redirects=True)
    assert res_update.status_code == 200
    assert b'System operational parameters updated' in res_update.data

def test_sse_broadcaster_pubsub():
    from modules.sse_broadcaster import SSEBroadcaster
    q = SSEBroadcaster.subscribe()
    assert SSEBroadcaster.active_subscribers_count() >= 1

    SSEBroadcaster.publish('test_event', {'message': 'probe', 'risk': 10})
    msg = q.get(timeout=2.0)
    assert msg['event'] == 'test_event'
    assert msg['data']['risk'] == 10

    SSEBroadcaster.unsubscribe(q)

def test_mitre_matrix_page_and_api(admin_client):
    res = admin_client.get('/mitre-matrix')
    assert res.status_code == 200
    assert b'MITRE ATT&amp;CK Enterprise Threat Matrix' in res.data or b'MITRE' in res.data
    assert b'T1110.001' in res.data
    assert b'T1078.004' in res.data

    res_api = admin_client.get('/api/mitre-matrix')
    assert res_api.status_code == 200
    data = res_api.get_json()
    assert 'techniques' in data
    assert len(data['techniques']) >= 5

def test_threat_map_api(admin_client):
    res = admin_client.get('/api/dashboard/threat-map')
    assert res.status_code == 200
    data = res.get_json()
    assert 'points' in data
    assert 'impossible_vectors' in data
    assert len(data['impossible_vectors']) >= 1

def test_firewall_block_unblock_api(admin_client):
    test_ip = '198.51.100.99'
    # Block IP
    res_block = admin_client.post('/api/firewall/block-ip', json={
        'ip_address': test_ip,
        'reason': 'Automated unit test brute force quarantine'
    })
    assert res_block.status_code == 200
    assert res_block.get_json()['success'] is True

    # Check blocked list
    res_list = admin_client.get('/api/firewall/blocked-ips')
    assert res_list.status_code == 200
    ips = [b['ip_address'] for b in res_list.get_json()['blocked_ips']]
    assert test_ip in ips

    # Unblock IP
    res_unblock = admin_client.post('/api/firewall/unblock-ip', json={
        'ip_address': test_ip
    })
    assert res_unblock.status_code == 200
    assert res_unblock.get_json()['success'] is True
