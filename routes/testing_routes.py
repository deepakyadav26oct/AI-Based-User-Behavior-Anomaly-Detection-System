import random
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from models.database import db, User, LoginActivity
from modules.activity_monitor import ActivityMonitor
from modules.authentication import analyst_required

testing_bp = Blueprint('testing', __name__)

SCENARIO_DEFINITIONS = {
    'normal': {
        'title': '1. Normal Business Login',
        'desc': 'Standard daytime login from an internal workstation during verified business hours.',
        'expected_risk': 'Low (0-29)',
        'hour': 10,
        'ip': '10.0.12.14',
        'device': 'Desktop Workstation (Corporate Dell)',
        'os': 'Windows 11',
        'browser': 'Google Chrome',
        'resource': '/dashboard',
        'sensitivity': 'LOW',
        'failed_count': 0,
        'frequency': 2,
        'duration': 2400,
        'status': 'SUCCESS'
    },
    'midnight': {
        'title': '2. Midnight / Off-Hours Login',
        'desc': 'Authentication attempt at 03:00 AM outside standard corporate schedule.',
        'expected_risk': 'Medium / High (30-75)',
        'hour': 3,
        'ip': '10.0.12.88',
        'device': 'Desktop Workstation (Corporate Dell)',
        'os': 'Windows 11',
        'browser': 'Google Chrome',
        'resource': '/documents/shared',
        'sensitivity': 'MEDIUM',
        'failed_count': 0,
        'frequency': 3,
        'duration': 600,
        'status': 'SUCCESS'
    },
    'new_ip': {
        'title': '3. Unrecognized External IP Ingress',
        'desc': 'Login origin from an external, never-before-seen foreign IP address (185.220.101.5).',
        'expected_risk': 'Medium (35-65)',
        'hour': 14,
        'ip': '185.220.101.5',
        'device': 'Laptop (ThinkPad X1)',
        'os': 'Windows 11',
        'browser': 'Mozilla Firefox',
        'resource': '/projects/tickets',
        'sensitivity': 'LOW',
        'failed_count': 0,
        'frequency': 4,
        'duration': 1800,
        'status': 'SUCCESS'
    },
    'unknown_device': {
        'title': '4. Unknown Device & Kali Linux Environment',
        'desc': 'Connection from an untrusted virtual machine running Kali Linux and Tor Browser.',
        'expected_risk': 'High (70-90)',
        'hour': 16,
        'ip': '194.26.29.112',
        'device': 'Penetration Testing Virtual Machine',
        'os': 'Kali Linux',
        'browser': 'Tor Browser',
        'resource': '/admin/system-logs',
        'sensitivity': 'HIGH',
        'failed_count': 1,
        'frequency': 6,
        'duration': 1200,
        'status': 'SUCCESS'
    },
    'brute_force': {
        'title': '5. Brute-Force Password Spray Attack',
        'desc': 'Aggressive credential stuffing storm: 9 consecutive authentication failures within 60 seconds.',
        'expected_risk': 'Critical / High (85-100)',
        'hour': 2,
        'ip': '45.154.255.89',
        'device': 'Automated Attack Rig',
        'os': 'Ubuntu Linux',
        'browser': 'Automated CLI / Script',
        'resource': '/api/v1/auth/login',
        'sensitivity': 'MEDIUM',
        'failed_count': 9,
        'frequency': 35,
        'duration': 30,
        'status': 'FAILED'
    },
    'abnormal_resource': {
        'title': '6. Abnormal Critical Asset Exfiltration',
        'desc': 'Off-hours access attempt targeting mission-critical database credentials repository.',
        'expected_risk': 'High (75-100)',
        'hour': 1,
        'ip': '91.240.118.23',
        'device': 'Unknown Headless Machine',
        'os': 'Windows 11',
        'browser': 'Google Chrome',
        'resource': '/database/credentials',
        'sensitivity': 'CRITICAL',
        'failed_count': 0,
        'frequency': 12,
        'duration': 300,
        'status': 'SUCCESS'
    },
    'impossible_travel': {
        'title': '7. Impossible Travel Velocity Attack',
        'desc': 'User authenticated from Delhi, and 12 minutes later attempts login from London (6,700 km, Speed: 33,500 km/h).',
        'expected_risk': 'Critical / High (85-100)',
        'hour': 15,
        'ip': '45.154.255.89',
        'device': 'Unknown Remote Client',
        'os': 'Ubuntu Linux',
        'browser': 'Mozilla Firefox',
        'resource': '/api/v1/internal/admin-dump',
        'sensitivity': 'HIGH',
        'failed_count': 0,
        'frequency': 4,
        'duration': 240,
        'status': 'SUCCESS'
    }
}

@testing_bp.route('/testing')
@login_required
@analyst_required
def testing_dashboard():
    users = User.query.filter_by(is_active=True).all()
    recent_simulations = LoginActivity.query.filter_by(is_simulated=True).order_by(LoginActivity.timestamp.desc()).limit(10).all()
    
    return render_template(
        'testing.html',
        scenarios=SCENARIO_DEFINITIONS,
        users=users,
        recent_simulations=recent_simulations
    )

@testing_bp.route('/api/simulation/run', methods=['POST'])
@login_required
@analyst_required
def run_simulation():
    data = request.get_json() or {}
    scenario_key = data.get('scenario', 'normal')
    username = data.get('username')
    live_mode = bool(data.get('live_mode', False))

    if not username:
        user = User.query.first()
        username = user.username if user else 'test.user'

    # If testing Impossible Travel, seed the anchor location 12 minutes prior in Delhi
    if scenario_key == 'impossible_travel':
        user_target = User.query.filter_by(username=username).first()
        if user_target:
            user_target.last_latitude = 28.6139
            user_target.last_longitude = 77.2090
            user_target.last_city = 'Delhi'
            user_target.last_country = 'India'
            user_target.last_activity_time = datetime.utcnow() - timedelta(minutes=12)
            db.session.commit()

    cfg = SCENARIO_DEFINITIONS.get(scenario_key, SCENARIO_DEFINITIONS['normal'])

    is_sim = not live_mode
    loc_label = f"Live Account Ingress ({cfg['ip']})" if live_mode else f"Simulated Lab Node ({scenario_key.upper()})"

    result = ActivityMonitor.record_and_evaluate(
        username=username,
        login_status=cfg['status'],
        ip_address=cfg['ip'],
        device_info=cfg['device'],
        browser=cfg['browser'],
        operating_system=cfg['os'],
        accessed_resource=cfg['resource'],
        resource_sensitivity=cfg['sensitivity'],
        session_duration=cfg['duration'],
        failed_login_count=cfg['failed_count'],
        access_frequency=cfg['frequency'],
        is_simulated=is_sim,  # False if live_mode is enabled
        location=loc_label,
        custom_hour=cfg['hour']
    )

    result['scenario_title'] = cfg['title']
    result['expected_risk'] = cfg['expected_risk']
    result['live_mode'] = live_mode

    return jsonify(result)
