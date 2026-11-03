from datetime import datetime
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required
from models.database import db, LoginActivity, DetectionResult
from modules.authentication import analyst_required
from modules.mitre_attack import MitreAttackMapper

activity_bp = Blueprint('activity', __name__)

@activity_bp.route('/activities')
@login_required
@analyst_required
def list_activities():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 25, type=int)
    
    user_filter = request.args.get('user', '').strip()
    ip_filter = request.args.get('ip', '').strip()
    risk_filter = request.args.get('risk', '').strip()
    sim_filter = request.args.get('simulated', '').strip()
    status_filter = request.args.get('status', '').strip()
    date_filter = request.args.get('date', '').strip()

    query = LoginActivity.query.join(DetectionResult)

    if user_filter:
        query = query.filter(LoginActivity.username.ilike(f"%{user_filter}%"))
    if ip_filter:
        query = query.filter(LoginActivity.ip_address.ilike(f"%{ip_filter}%"))
    if status_filter:
        query = query.filter(LoginActivity.login_status == status_filter)
    if risk_filter:
        query = query.filter(DetectionResult.risk_level == risk_filter)
    if sim_filter == 'real':
        query = query.filter(LoginActivity.is_simulated == False)
    elif sim_filter == 'simulated':
        query = query.filter(LoginActivity.is_simulated == True)
    if date_filter:
        try:
            target_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
            start = datetime.combine(target_date, datetime.min.time())
            end = datetime.combine(target_date, datetime.max.time())
            query = query.filter(LoginActivity.timestamp >= start, LoginActivity.timestamp <= end)
        except ValueError:
            pass

    pagination = query.order_by(LoginActivity.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template(
        'activities.html',
        pagination=pagination,
        activities=pagination.items,
        filters={
            'user': user_filter,
            'ip': ip_filter,
            'risk': risk_filter,
            'simulated': sim_filter,
            'status': status_filter,
            'date': date_filter
        }
    )

@activity_bp.route('/api/activities/<int:activity_id>')
@login_required
@analyst_required
def get_activity_detail(activity_id):
    activity = db.session.get(LoginActivity, activity_id)
    if not activity:
        return {'error': 'Activity not found'}, 404
    det = activity.detection_result
    
    mitre_techs = MitreAttackMapper.map_rule_flags(det.rule_flags) if det else []

    return jsonify({
        'activity': activity.to_dict(),
        'detection': det.to_dict() if det else None,
        'mitre_techniques': mitre_techs
    })
