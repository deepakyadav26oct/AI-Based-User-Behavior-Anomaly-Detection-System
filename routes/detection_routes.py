from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
import pandas as pd
from config import Config
from modules.anomaly_detector import AnomalyDetectorService
from modules.risk_engine import RiskEngine
from modules.authentication import analyst_required, admin_required, log_audit_event
from scripts.train_model import train_and_evaluate_model

detection_bp = Blueprint('detection', __name__)

@detection_bp.route('/detection')
@login_required
@analyst_required
def detection_center():
    service = AnomalyDetectorService.get_service()
    is_fitted = service.is_model_trained

    model_metadata = {
        'algorithm': 'Isolation Forest (Ensemble Unsupervised)',
        'framework': 'Scikit-Learn 1.5.0',
        'n_estimators': Config.ML_N_ESTIMATORS,
        'contamination': Config.ML_CONTAMINATION,
        'features_count': len(service.detector.feature_names),
        'features': service.detector.feature_names,
        'is_fitted': is_fitted,
        'model_path': str(Config.MODEL_PATH)
    }

    comparison_data = service.get_benchmark_comparison()

    return render_template(
        'detection.html',
        model_meta=model_metadata,
        comparison=comparison_data
    )

@detection_bp.route('/api/detection/model-comparison')
@login_required
@analyst_required
def api_model_comparison():
    service = AnomalyDetectorService.get_service()
    return jsonify(service.get_benchmark_comparison())

@detection_bp.route('/api/detection/inspect', methods=['POST'])
@login_required
@analyst_required
def inspect_single_payload():
    """Run interactive single-payload inference for the Anomaly Detection UI."""
    data = request.get_json() or {}
    
    hour = int(data.get('login_hour', 12))
    day = int(data.get('day_of_week', 1))
    failed_logins = int(data.get('failed_login_count', 0))
    is_new_ip = bool(data.get('is_new_ip', False))
    is_new_device = bool(data.get('is_new_device', False))
    session_dur = float(data.get('session_duration', 1800))
    access_freq = int(data.get('access_frequency', 2))
    sensitivity = data.get('resource_sensitivity', 'LOW')
    resource = data.get('accessed_resource', '/dashboard')
    os_name = data.get('operating_system', 'Windows 11')
    browser = data.get('browser', 'Google Chrome')

    deviations = {
        'is_unusual_hour': (hour < 7 or hour > 20),
        'is_new_ip': is_new_ip,
        'is_new_device': is_new_device,
        'is_abnormal_resource': (sensitivity in ('HIGH', 'CRITICAL'))
    }

    activity_dict = {
        'username': 'inspector.test',
        'login_hour': hour,
        'day_of_week': day,
        'failed_login_count': failed_logins,
        'is_new_ip': is_new_ip,
        'is_new_device': is_new_device,
        'is_unusual_hour': deviations['is_unusual_hour'],
        'session_duration': session_dur,
        'access_frequency': access_freq,
        'resource_sensitivity': sensitivity,
        'accessed_resource': resource,
        'operating_system': os_name,
        'browser': browser,
        'device_info': 'Inspector Test Rig'
    }

    service = AnomalyDetectorService.get_service()
    ml_res = service.evaluate_activity(activity_dict, deviations)
    risk_res = RiskEngine.evaluate(activity_dict, deviations, ml_res)

    return jsonify({
        'ml_evaluation': ml_res,
        'risk_evaluation': risk_res,
        'deviations': deviations
    })

@detection_bp.route('/detection/retrain', methods=['POST'])
@login_required
@admin_required
def retrain_model():
    """Trigger retraining of the Isolation Forest model."""
    try:
        _, metrics = train_and_evaluate_model()
        service = AnomalyDetectorService.get_service()
        service.load_model()
        
        log_audit_event('MODEL_RETRAINED', f"Retrained Isolation Forest. Accuracy: {metrics['accuracy']:.4f}, F1: {metrics['f1_score']:.4f}")
        flash(f"Isolation Forest retrained successfully! Test F1: {metrics['f1_score']:.4f}, Accuracy: {metrics['accuracy']*100:.2f}%.", 'success')
    except Exception as e:
        flash(f"Failed to retrain model: {e}", 'danger')

    return redirect(url_for('detection.detection_center'))
