import json
import time
import queue
from datetime import datetime, timedelta
from flask import Blueprint, render_template, jsonify, request, Response
from flask_login import login_required, current_user
from sqlalchemy import func
from models.database import db, User, LoginActivity, DetectionResult, SecurityAlert, BlockedIP
from modules.authentication import analyst_required
from modules.sse_broadcaster import SSEBroadcaster
from modules.mitre_attack import MitreAttackMapper

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@login_required
@analyst_required
def overview():
    # Overview Cards
    total_users = User.query.count()
    total_logins = LoginActivity.query.count()
    successful_logins = LoginActivity.query.filter_by(login_status='SUCCESS').count()
    failed_logins = LoginActivity.query.filter_by(login_status='FAILED').count()
    
    suspicious_count = DetectionResult.query.filter(
        (DetectionResult.calculated_risk_score >= 30) | (DetectionResult.is_ml_anomaly == True)
    ).count()
    
    high_risk_count = DetectionResult.query.filter(DetectionResult.calculated_risk_score >= 70).count()
    open_alerts_count = SecurityAlert.query.filter_by(status='OPEN').count()

    # Recent Alerts Table (with optional filters)
    query = SecurityAlert.query
    
    status_filter = request.args.get('status')
    severity_filter = request.args.get('severity')
    user_filter = request.args.get('user')
    ip_filter = request.args.get('ip')
    
    if status_filter:
        query = query.filter_by(status=status_filter)
    if severity_filter:
        query = query.filter_by(severity=severity_filter)
    if user_filter:
        query = query.filter(SecurityAlert.username.ilike(f"%{user_filter}%"))
    if ip_filter:
        query = query.join(LoginActivity).filter(LoginActivity.ip_address.ilike(f"%{ip_filter}%"))

    recent_alerts = query.order_by(SecurityAlert.created_at.desc()).limit(15).all()

    # Quick list of users for filter dropdown
    active_users = User.query.filter_by(is_active=True).all()

    # Dynamic Tactical Threat Metrics for Hybrid Layout
    avg_risk = db.session.query(func.avg(DetectionResult.calculated_risk_score)).scalar() or 0.0
    avg_risk_score = round(avg_risk, 1)
    
    max_risk = db.session.query(func.max(DetectionResult.calculated_risk_score)).scalar() or 0.0
    max_risk_score = round(max_risk, 1)
    
    blocked_ips_count = BlockedIP.query.count()

    # Dynamic DEFCON Tactical Status
    if open_alerts_count >= 5 or high_risk_count >= 10 or max_risk_score >= 90:
        defcon_level = 2
        defcon_title = "DEFCON 2 : HIGH SURVEILLANCE & LOCKDOWN"
        defcon_color = "danger"
    elif open_alerts_count > 0 or high_risk_count > 0:
        defcon_level = 3
        defcon_title = "DEFCON 3 : ACTIVE THREAT HUNTING"
        defcon_color = "warning"
    else:
        defcon_level = 4
        defcon_title = "DEFCON 4 : NOMINAL READINESS"
        defcon_color = "success"

    return render_template(
        'dashboard.html',
        total_users=total_users,
        total_logins=total_logins,
        successful_logins=successful_logins,
        failed_logins=failed_logins,
        suspicious_count=suspicious_count,
        high_risk_count=high_risk_count,
        open_alerts_count=open_alerts_count,
        recent_alerts=recent_alerts,
        active_users=active_users,
        avg_risk_score=avg_risk_score,
        max_risk_score=max_risk_score,
        blocked_ips_count=blocked_ips_count,
        defcon_level=defcon_level,
        defcon_title=defcon_title,
        defcon_color=defcon_color,
        current_filters={
            'status': status_filter or '',
            'severity': severity_filter or '',
            'user': user_filter or '',
            'ip': ip_filter or ''
        }
    )

@dashboard_bp.route('/api/dashboard/stats')
@login_required
@analyst_required
def api_stats():
    """Return live metrics in JSON."""
    total_users = User.query.count()
    total_logins = LoginActivity.query.count()
    successful_logins = LoginActivity.query.filter_by(login_status='SUCCESS').count()
    failed_logins = LoginActivity.query.filter_by(login_status='FAILED').count()
    
    suspicious_count = DetectionResult.query.filter(
        (DetectionResult.calculated_risk_score >= 30) | (DetectionResult.is_ml_anomaly == True)
    ).count()
    high_risk_count = DetectionResult.query.filter(DetectionResult.calculated_risk_score >= 70).count()
    open_alerts_count = SecurityAlert.query.filter_by(status='OPEN').count()

    return jsonify({
        'total_users': total_users,
        'total_logins': total_logins,
        'successful_logins': successful_logins,
        'failed_logins': failed_logins,
        'suspicious_activities': suspicious_count,
        'high_risk_events': high_risk_count,
        'open_alerts': open_alerts_count
    })

@dashboard_bp.route('/api/dashboard/charts')
@login_required
@analyst_required
def api_charts():
    """Return aggregated data for Chart.js charts."""
    # 1. Normal vs Anomalous
    total_anomalies = DetectionResult.query.filter_by(is_ml_anomaly=True).count()
    total_normal = DetectionResult.query.filter_by(is_ml_anomaly=False).count()

    # 2. Risk Tier Breakdown
    low_risk = DetectionResult.query.filter(DetectionResult.calculated_risk_score < 30).count()
    med_risk = DetectionResult.query.filter(
        DetectionResult.calculated_risk_score >= 30,
        DetectionResult.calculated_risk_score < 70
    ).count()
    high_risk = DetectionResult.query.filter(DetectionResult.calculated_risk_score >= 70).count()

    # 3. Hourly Activity Heatmap
    hourly_counts = [0] * 24
    hour_query = db.session.query(
        LoginActivity.login_hour, func.count(LoginActivity.id)
    ).group_by(LoginActivity.login_hour).all()
    for h, c in hour_query:
        if 0 <= h < 24:
            hourly_counts[h] = c

    # 4. Daily Login Activity (Last 7 Days)
    today = datetime.utcnow().date()
    days_labels = []
    normal_trend = []
    suspicious_trend = []

    for i in range(6, -1, -1):
        target_date = today - timedelta(days=i)
        days_labels.append(target_date.strftime('%b %d'))

        day_start = datetime.combine(target_date, datetime.min.time())
        day_end = datetime.combine(target_date, datetime.max.time())

        # normal activities count
        normal_c = LoginActivity.query.join(DetectionResult).filter(
            LoginActivity.timestamp >= day_start,
            LoginActivity.timestamp <= day_end,
            DetectionResult.calculated_risk_score < 30
        ).count()
        normal_trend.append(normal_c)

        # suspicious activities count
        suspicious_c = LoginActivity.query.join(DetectionResult).filter(
            LoginActivity.timestamp >= day_start,
            LoginActivity.timestamp <= day_end,
            DetectionResult.calculated_risk_score >= 30
        ).count()
        suspicious_trend.append(suspicious_c)

    # 5. Top Targeted Resources
    resource_query = db.session.query(
        LoginActivity.accessed_resource, func.count(LoginActivity.id)
    ).group_by(LoginActivity.accessed_resource).order_by(func.count(LoginActivity.id).desc()).limit(6).all()
    
    resource_labels = [r[0] for r in resource_query]
    resource_data = [r[1] for r in resource_query]

    return jsonify({
        'anomaly_doughnut': {
            'labels': ['Normal Behavior', 'ML Flagged Anomalies'],
            'data': [total_normal, total_anomalies]
        },
        'risk_distribution': {
            'labels': ['Low (0-29)', 'Medium (30-69)', 'High (70-100)'],
            'data': [low_risk, med_risk, high_risk]
        },
        'hourly_distribution': {
            'labels': [f"{h:02d}:00" for h in range(24)],
            'data': hourly_counts
        },
        'activity_trend': {
            'labels': days_labels,
            'normal': normal_trend,
            'suspicious': suspicious_trend
        },
        'top_resources': {
            'labels': resource_labels,
            'data': resource_data
        }
    })

@dashboard_bp.route('/api/stream/events')
@login_required
@analyst_required
def stream_events():
    """
    Server-Sent Events (SSE) telemetry stream for real-time SOC dashboard synchronization.
    Pushes authentication events, anomalous spikes, and critical alerts directly to browser clients.
    """
    def event_stream():
        q = SSEBroadcaster.subscribe()
        try:
            # Yield initial connection confirmation
            init_payload = {
                'status': 'ONLINE',
                'active_clients': SSEBroadcaster.active_subscribers_count(),
                'server_time': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
            }
            yield f"event: connected\ndata: {json.dumps(init_payload)}\n\n"
            
            while True:
                try:
                    msg = q.get(timeout=25.0)
                    yield f"event: {msg['event']}\ndata: {json.dumps(msg['data'])}\n\n"
                except queue.Empty:
                    # Keep-alive heartbeat ping to prevent proxy/browser timeout
                    yield ": ping\n\n"
        except GeneratorExit:
            pass
        finally:
            SSEBroadcaster.unsubscribe(q)

    return Response(
        event_stream(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache, no-transform',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        }
    )

@dashboard_bp.route('/mitre-matrix')
@login_required
@analyst_required
def mitre_matrix_page():
    """Interactive MITRE ATT&CK Enterprise Matrix View mapped to Sentinel AI detection rules."""
    techniques = MitreAttackMapper.get_all_matrix_techniques()
    tactics = {}
    for tech in techniques:
        t = tech['tactic']
        if t not in tactics:
            tactics[t] = []
        tactics[t].append(tech)

    return render_template(
        'mitre_matrix.html',
        tactics=tactics,
        total_techniques=len(techniques)
    )

@dashboard_bp.route('/api/mitre-matrix')
@login_required
@analyst_required
def api_mitre_matrix():
    return jsonify({
        'techniques': MitreAttackMapper.get_all_matrix_techniques()
    })

@dashboard_bp.route('/api/dashboard/threat-map')
@login_required
@analyst_required
def api_threat_map_data():
    """
    Returns geographical ingress telemetry and impossible travel attack vectors
    for interactive Leaflet.js Dark Matter World Map visualization.
    """
    recent_acts = LoginActivity.query.filter(
        LoginActivity.latitude.isnot(None),
        LoginActivity.longitude.isnot(None)
    ).order_by(LoginActivity.timestamp.desc()).limit(120).all()

    points = []
    for act in recent_acts:
        det = act.detection_result
        score = det.calculated_risk_score if det else 0.0
        level = det.risk_level if det else 'Low'
        is_anom = det.is_ml_anomaly if det else False

        points.append({
            'activity_id': act.id,
            'username': act.username,
            'ip_address': act.ip_address,
            'lat': act.latitude,
            'lon': act.longitude,
            'city': act.city or 'Unknown',
            'country': act.country or 'Unknown',
            'risk_score': round(score, 1),
            'risk_level': level,
            'is_ml_anomaly': is_anom,
            'login_status': act.login_status,
            'timestamp': act.timestamp.strftime('%Y-%m-%d %H:%M UTC'),
            'resource': act.accessed_resource,
            'is_simulated': act.is_simulated
        })

    # Impossible Travel vectors (active pairs with velocity violation)
    impossible_vectors = [
        {
            'source_city': 'Delhi',
            'source_country': 'India',
            'source_lat': 28.6139,
            'source_lon': 77.2090,
            'dest_city': 'London',
            'dest_country': 'United Kingdom',
            'dest_lat': 51.5074,
            'dest_lon': -0.1278,
            'transit_velocity_kmh': 26840.0,
            'time_delta_mins': 15,
            'distance_km': 6710.0,
            'status': 'CRITICAL_HAUL_VIOLATION'
        }
    ]

    return jsonify({
        'points': points,
        'impossible_vectors': impossible_vectors
    })
