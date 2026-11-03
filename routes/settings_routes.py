from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from datetime import datetime
from config import Config
from models.database import db, AuditLog, SystemSetting, LoginActivity, SecurityAlert, DetectionResult, BlockedIP
from modules.authentication import admin_required, analyst_required, log_audit_event
from modules.webhook_notifier import WebhookNotifier

settings_bp = Blueprint('settings', __name__)

@settings_bp.route('/settings')
@login_required
@admin_required
def settings_page():
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(30).all()
    blocked_ips = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
    
    settings = {
        'contamination': SystemSetting.get_setting('ML_CONTAMINATION', str(Config.ML_CONTAMINATION)),
        'n_estimators': SystemSetting.get_setting('ML_N_ESTIMATORS', str(Config.ML_N_ESTIMATORS)),
        'risk_low_max': SystemSetting.get_setting('RISK_LOW_MAX', str(Config.RISK_LOW_MAX)),
        'risk_high_min': SystemSetting.get_setting('RISK_HIGH_MIN', str(Config.RISK_HIGH_MIN)),
        'alert_trigger': SystemSetting.get_setting('ALERT_TRIGGER_THRESHOLD', str(Config.ALERT_TRIGGER_THRESHOLD)),
        'webhook_enabled': SystemSetting.get_setting('WEBHOOK_ENABLED', 'false'),
        'webhook_url': SystemSetting.get_setting('WEBHOOK_URL', ''),
        'webhook_min_severity': SystemSetting.get_setting('WEBHOOK_MIN_SEVERITY', 'HIGH'),
    }

    return render_template(
        'settings.html',
        settings=settings,
        audit_logs=audit_logs,
        blocked_ips=blocked_ips
    )

@settings_bp.route('/settings/update', methods=['POST'])
@login_required
@admin_required
def update_settings():
    try:
        contam = request.form.get('contamination')
        n_est = request.form.get('n_estimators')
        low_max = request.form.get('risk_low_max')
        high_min = request.form.get('risk_high_min')
        alert_thresh = request.form.get('alert_trigger')

        # Webhook Parameters
        webhook_enabled = 'true' if request.form.get('webhook_enabled') else 'false'
        webhook_url = request.form.get('webhook_url', '').strip()
        webhook_min_sev = request.form.get('webhook_min_severity', 'HIGH').upper()

        if contam:
            SystemSetting.set_setting('ML_CONTAMINATION', contam, 'Isolation Forest contamination rate')
            Config.ML_CONTAMINATION = float(contam)
        if n_est:
            SystemSetting.set_setting('ML_N_ESTIMATORS', n_est, 'Isolation Forest number of trees')
            Config.ML_N_ESTIMATORS = int(n_est)
        if low_max:
            SystemSetting.set_setting('RISK_LOW_MAX', low_max, 'Maximum boundary for Low Risk tier')
            Config.RISK_LOW_MAX = int(low_max)
        if high_min:
            SystemSetting.set_setting('RISK_HIGH_MIN', high_min, 'Minimum boundary for High Risk tier')
            Config.RISK_HIGH_MIN = int(high_min)
        if alert_thresh:
            SystemSetting.set_setting('ALERT_TRIGGER_THRESHOLD', alert_thresh, 'Risk score threshold triggering security alert')
            Config.ALERT_TRIGGER_THRESHOLD = int(alert_thresh)

        # Save Webhook Configurations
        SystemSetting.set_setting('WEBHOOK_ENABLED', webhook_enabled, 'Enable SOC Real-time Webhook Dispatch')
        SystemSetting.set_setting('WEBHOOK_URL', webhook_url, 'Incoming Webhook Target URL')
        SystemSetting.set_setting('WEBHOOK_MIN_SEVERITY', webhook_min_sev, 'Minimum Severity to Dispatch Webhook')

        log_audit_event('SETTINGS_UPDATED', f"System settings & Webhook configuration updated by {current_user.username}")
        flash('System operational parameters updated successfully. Webhook integration synchronized.', 'success')
    except Exception as e:
        flash(f'Failed to update settings: {e}', 'danger')

    return redirect(url_for('settings.settings_page'))

@settings_bp.route('/settings/test-webhook', methods=['POST'])
@login_required
@admin_required
def test_webhook():
    """Trigger an immediate test ping to the specified or stored webhook URL."""
    data = request.get_json() or {}
    url = data.get('webhook_url', '').strip() or SystemSetting.get_setting('WEBHOOK_URL', '')
    
    if not url:
        return jsonify({
            'success': False,
            'status_code': 400,
            'message': 'No Webhook URL configured. Please enter a valid Discord, Slack, or generic webhook URL.'
        }), 400

    result = WebhookNotifier.send_test_ping(url)
    return jsonify(result)

    return redirect(url_for('settings.settings_page'))

@settings_bp.route('/settings/purge-simulations', methods=['POST'])
@login_required
@admin_required
def purge_simulated_data():
    try:
        # Delete simulated alerts and activities
        sim_alerts = SecurityAlert.query.filter_by(is_simulated=True).all()
        sim_activities = LoginActivity.query.filter_by(is_simulated=True).all()
        
        c_alerts = len(sim_alerts)
        c_acts = len(sim_activities)

        for a in sim_alerts:
            db.session.delete(a)
        for act in sim_activities:
            db.session.delete(act)

        db.session.commit()
        log_audit_event('SIMULATION_PURGE', f"Purged {c_acts} simulated activities and {c_alerts} simulated alerts.")
        flash(f"Successfully purged {c_acts} simulated activities and {c_alerts} simulated alerts from database.", 'info')
    except Exception as e:
        db.session.rollback()
        flash(f"Error purging simulated records: {e}", 'danger')

    return redirect(url_for('settings.settings_page'))

@settings_bp.route('/api/firewall/block-ip', methods=['POST'])
@login_required
@analyst_required
def api_block_ip():
    """SOAR Action: Quarantine an adversarial IP address in the Active Firewall Shield."""
    data = request.get_json() or {}
    ip = data.get('ip_address', '').strip()
    reason = data.get('reason', 'Quarantined by Sentinel SOAR Threat Defense Engine').strip()
    
    if not ip:
        return jsonify({'success': False, 'message': 'Missing IP address parameter.'}), 400

    existing = BlockedIP.query.filter_by(ip_address=ip).first()
    if existing:
        existing.is_active = True
        existing.reason = reason
        existing.blocked_by = current_user.username
        existing.blocked_at = datetime.utcnow()
    else:
        new_block = BlockedIP(
            ip_address=ip,
            reason=reason,
            blocked_by=current_user.username,
            blocked_at=datetime.utcnow(),
            is_active=True
        )
        db.session.add(new_block)

    db.session.commit()
    log_audit_event('IP_QUARANTINED', f"IP {ip} quarantined into firewall shield by {current_user.username}. Reason: {reason}", ip=ip)
    
    return jsonify({
        'success': True,
        'message': f"IP address {ip} successfully quarantined by Sentinel Firewall Shield.",
        'ip_address': ip
    })

@settings_bp.route('/api/firewall/unblock-ip', methods=['POST'])
@login_required
@analyst_required
def api_unblock_ip():
    """SOAR Action: Release an IP address from active firewall quarantine."""
    data = request.get_json() or {}
    ip = data.get('ip_address', '').strip()
    
    if not ip:
        return jsonify({'success': False, 'message': 'Missing IP address parameter.'}), 400

    entry = BlockedIP.query.filter_by(ip_address=ip).first()
    if entry:
        entry.is_active = False
        db.session.commit()
        log_audit_event('IP_RELEASED', f"IP {ip} unblocked and released from firewall quarantine by {current_user.username}", ip=ip)
        return jsonify({'success': True, 'message': f"IP {ip} released from firewall quarantine."})
    
    return jsonify({'success': False, 'message': f"IP {ip} not found in firewall blocklist."}), 404

@settings_bp.route('/api/firewall/blocked-ips')
@login_required
@analyst_required
def api_list_blocked_ips():
    blocks = BlockedIP.query.filter_by(is_active=True).all()
    return jsonify({'blocked_ips': [b.to_dict() for b in blocks]})
