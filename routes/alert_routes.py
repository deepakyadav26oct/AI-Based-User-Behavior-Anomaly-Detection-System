from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from models.database import db, SecurityAlert, LoginActivity
from modules.alert_manager import AlertManager
from modules.authentication import analyst_required

alert_bp = Blueprint('alert', __name__)

@alert_bp.route('/alerts')
@login_required
@analyst_required
def list_alerts():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    status = request.args.get('status', '').strip()
    severity = request.args.get('severity', '').strip()
    user = request.args.get('user', '').strip()
    simulated = request.args.get('simulated', '').strip()

    query = SecurityAlert.query

    if status:
        query = query.filter_by(status=status)
    if severity:
        query = query.filter_by(severity=severity)
    if user:
        query = query.filter(SecurityAlert.username.ilike(f"%{user}%"))
    if simulated == 'real':
        query = query.filter_by(is_simulated=False)
    elif simulated == 'simulated':
        query = query.filter_by(is_simulated=True)

    pagination = query.order_by(SecurityAlert.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    summary = AlertManager.get_summary_statistics()

    return render_template(
        'alerts.html',
        pagination=pagination,
        alerts=pagination.items,
        summary=summary,
        filters={
            'status': status,
            'severity': severity,
            'user': user,
            'simulated': simulated
        }
    )

@alert_bp.route('/alerts/<int:alert_id>/review', methods=['POST'])
@login_required
@analyst_required
def review_alert(alert_id):
    try:
        AlertManager.review_alert(alert_id, current_user.username)
        flash(f'Alert #{alert_id} placed under review.', 'info')
    except Exception as e:
        flash(f'Failed to review alert: {e}', 'danger')
    return redirect(request.referrer or url_for('alert.list_alerts'))

@alert_bp.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
@login_required
@analyst_required
def resolve_alert(alert_id):
    notes = request.form.get('resolution_notes', 'Resolved by SOC Analyst')
    try:
        AlertManager.resolve_alert(alert_id, notes, current_user.username)
        flash(f'Alert #{alert_id} resolved successfully.', 'success')
    except Exception as e:
        flash(f'Failed to resolve alert: {e}', 'danger')
    return redirect(request.referrer or url_for('alert.list_alerts'))

@alert_bp.route('/alerts/<int:alert_id>/dismiss', methods=['POST'])
@login_required
@analyst_required
def dismiss_alert(alert_id):
    reason = request.form.get('dismissal_reason', 'False positive / authorized exception')
    try:
        AlertManager.dismiss_alert(alert_id, reason, current_user.username)
        flash(f'Alert #{alert_id} dismissed.', 'warning')
    except Exception as e:
        flash(f'Failed to dismiss alert: {e}', 'danger')
    return redirect(request.referrer or url_for('alert.list_alerts'))

@alert_bp.route('/api/alerts/<int:alert_id>')
@login_required
@analyst_required
def get_alert_json(alert_id):
    alert = db.session.get(SecurityAlert, alert_id)
    if not alert:
        return {'error': 'Alert not found'}, 404
    return jsonify(alert.to_dict())
