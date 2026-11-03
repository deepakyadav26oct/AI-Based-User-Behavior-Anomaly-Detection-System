import re
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
from flask import Request
from models.database import db, User, LoginActivity, DetectionResult, SecurityAlert, AuditLog
from modules.behaviour_profiler import BehaviourProfiler
from modules.anomaly_detector import AnomalyDetectorService
from modules.risk_engine import RiskEngine
from modules.alert_manager import AlertManager
from modules.geo_velocity import GeoVelocityEngine
from modules.webhook_notifier import WebhookNotifier
from modules.sse_broadcaster import SSEBroadcaster

class ActivityMonitor:
    """
    Core activity ingestion pipeline: captures events, extracts contextual telemetry,
    orchestrates ML inference and risk scoring, updates baselines, and generates alerts.
    """

    @staticmethod
    def parse_client_telemetry(req: Request) -> Dict[str, str]:
        """Extract IP, User-Agent, OS, Browser, and Device category from HTTP request."""
        # IP detection
        ip = req.headers.get('X-Forwarded-For', req.remote_addr or '127.0.0.1').split(',')[0].strip()
        ua = req.headers.get('User-Agent', '')

        # OS detection
        os_name = 'Unknown OS'
        if 'Windows NT 10.0' in ua:
            os_name = 'Windows 11 / 10'
        elif 'Windows' in ua:
            os_name = 'Windows'
        elif 'Macintosh' in ua or 'Mac OS X' in ua:
            os_name = 'macOS Sonoma'
        elif 'Kali' in ua:
            os_name = 'Kali Linux'
        elif 'Ubuntu' in ua or 'Linux' in ua:
            os_name = 'Ubuntu Linux'
        elif 'Android' in ua:
            os_name = 'Android'
        elif 'iPhone' in ua or 'iPad' in ua:
            os_name = 'iOS'

        # Browser detection
        browser = 'Unknown Browser'
        if 'TorBrowser' in ua or 'Tor' in ua:
            browser = 'Tor Browser'
        elif 'Edg/' in ua:
            browser = 'Microsoft Edge'
        elif 'Chrome/' in ua and 'Edg/' not in ua:
            browser = 'Google Chrome'
        elif 'Firefox/' in ua:
            browser = 'Mozilla Firefox'
        elif 'Safari/' in ua and 'Chrome/' not in ua:
            browser = 'Apple Safari'
        elif 'PostmanRuntime' in ua:
            browser = 'Postman API Client'
        elif 'curl' in ua or 'python' in ua:
            browser = 'Automated CLI / Script'

        # Device classification
        device = 'Desktop Workstation'
        if 'Mobile' in ua or 'Android' in ua or 'iPhone' in ua:
            device = 'Mobile Device'
        elif 'Tablet' in ua or 'iPad' in ua:
            device = 'Tablet Device'

        return {
            'ip_address': ip,
            'device_info': device,
            'browser': browser,
            'operating_system': os_name,
        }

    @classmethod
    def record_and_evaluate(
        cls,
        username: str,
        login_status: str = 'SUCCESS',
        ip_address: str = '127.0.0.1',
        device_info: str = 'Desktop Workstation',
        browser: str = 'Google Chrome',
        operating_system: str = 'Windows 11',
        accessed_resource: str = '/dashboard',
        resource_sensitivity: str = 'LOW',
        session_duration: int = 1800,
        failed_login_count: int = 0,
        access_frequency: int = 1,
        is_simulated: bool = False,
        location: str = 'Corporate HQ / Domestic',
        custom_hour: Optional[int] = None,
        custom_day: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Record a user activity, evaluate behavioral deviations, run ML anomaly detection,
        compute risk score, record database entries, and trigger security alerts.
        """
        now = datetime.utcnow()
        hour = custom_hour if custom_hour is not None else now.hour
        day = custom_day if custom_day is not None else now.weekday()

        user = User.query.filter_by(username=username).first()
        user_id = user.id if user else None

        # Resolve Geolocation coordinates
        geo_info = GeoVelocityEngine.resolve_ip_location(ip_address)
        city = geo_info['city']
        country = geo_info['country']
        lat = geo_info['lat']
        lon = geo_info['lon']
        current_location = location if location != 'Corporate HQ / Domestic' else f"{city}, {country}"

        # Impossible Travel Velocity Evaluation
        travel_eval = GeoVelocityEngine.evaluate_impossible_travel(
            last_lat=user.last_latitude if user else None,
            last_lon=user.last_longitude if user else None,
            last_time=user.last_activity_time if user else None,
            last_city=user.last_city if user else None,
            curr_lat=lat,
            curr_lon=lon,
            curr_time=now,
            curr_city=city
        )

        # 1. Profile baseline inspection
        deviations = {
            'is_unusual_hour': False,
            'is_new_ip': False,
            'is_new_device': False,
            'is_new_browser': False,
            'is_abnormal_resource': False,
            'is_impossible_travel': travel_eval['is_impossible_travel'],
        }

        if user_id:
            profile = BehaviourProfiler.get_or_create_profile(user_id)
            deviations = BehaviourProfiler.inspect_against_baseline(
                profile,
                {
                    'login_hour': hour,
                    'ip_address': ip_address,
                    'device_info': device_info,
                    'browser': browser,
                    'accessed_resource': accessed_resource,
                    'resource_sensitivity': resource_sensitivity
                }
            )
            deviations['is_impossible_travel'] = travel_eval['is_impossible_travel']

        activity_dict = {
            'username': username,
            'user_id': user_id,
            'login_status': login_status,
            'login_hour': hour,
            'day_of_week': day,
            'ip_address': ip_address,
            'device_info': device_info,
            'browser': browser,
            'operating_system': operating_system,
            'accessed_resource': accessed_resource,
            'resource_sensitivity': resource_sensitivity,
            'session_duration': session_duration,
            'failed_login_count': failed_login_count,
            'access_frequency': access_frequency,
            'is_simulated': is_simulated,
            'location': current_location
        }

        # 2. ML Anomaly Detection (Isolation Forest)
        ml_service = AnomalyDetectorService.get_service()
        ml_result = ml_service.evaluate_activity(activity_dict, deviations)

        # 3. Contextual Risk Scoring Engine (with Geo-Velocity evaluation)
        risk_result = RiskEngine.evaluate(activity_dict, deviations, ml_result, travel_data=travel_eval)

        # 4. Save LoginActivity to Database
        activity_record = LoginActivity(
            user_id=user_id,
            username=username,
            timestamp=now,
            ip_address=ip_address,
            device_info=device_info,
            browser=browser,
            operating_system=operating_system,
            login_status=login_status,
            login_hour=hour,
            day_of_week=day,
            accessed_resource=accessed_resource,
            resource_sensitivity=resource_sensitivity,
            session_duration=session_duration,
            failed_login_count=failed_login_count,
            is_simulated=is_simulated,
            location=current_location,
            city=city,
            country=country,
            latitude=lat,
            longitude=lon
        )
        db.session.add(activity_record)
        db.session.flush()  # obtain activity_record.id

        # 5. Save DetectionResult to Database
        detection_record = DetectionResult(
            activity_id=activity_record.id,
            user_id=user_id,
            ml_anomaly_score=ml_result['ml_anomaly_score'],
            is_ml_anomaly=ml_result['is_ml_anomaly'],
            rule_flags=risk_result['rule_flags'],
            calculated_risk_score=risk_result['calculated_risk_score'],
            risk_level=risk_result['risk_level'],
            reasons=risk_result['reasons'],
            evaluated_at=now
        )
        db.session.add(detection_record)
        db.session.flush()

        # 6. Evaluate and dispatch Security Alert if warranted
        alert_record = AlertManager.create_alert_if_warranted(
            activity=activity_record,
            detection=detection_record,
            risk_data=risk_result
        )

        # 7. Automated Active Threat Defense (Account Lockout)
        account_locked = False
        lockout_msg = ""
        if user and not user.is_locked and not is_simulated:
            if (risk_result['calculated_risk_score'] >= 70 or 
                travel_eval.get('is_impossible_travel') or 
                'RULE_BRUTE_FORCE' in risk_result['rule_flags']):
                user.is_locked = True
                user.locked_at = now
                user.lock_reason = f"Automated AI Lockdown: Flagged as {risk_result['risk_level']} Risk ({risk_result['calculated_risk_score']:.1f}/100). Threat Flags: {', '.join(risk_result['rule_flags'])}"
                account_locked = True
                lockout_msg = f"Account automatically locked by Sentinel AI active defense: {user.lock_reason}"
                
                audit_entry = AuditLog(
                    user_id=user.id,
                    username='SENTINEL_ACTIVE_DEFENSE',
                    action='AUTOMATED_ACCOUNT_LOCKDOWN',
                    details=f"Account for {username} automatically locked due to severe risk score ({risk_result['calculated_risk_score']:.1f}). Reason: {user.lock_reason}",
                    ip_address=ip_address
                )
                db.session.add(audit_entry)
        elif user and user.is_locked:
            account_locked = True
            lockout_msg = f"Account is currently under lockdown: {user.lock_reason}"

        # Webhook Notification Dispatch (Discord / Slack / Generic)
        if alert_record or account_locked:
            title = alert_record.alert_title if alert_record else f"Automated Security Lockdown for {username}"
            alert_t = alert_record.alert_type if alert_record else "ACCOUNT_LOCKDOWN"
            sev = alert_record.severity if alert_record else "Critical"
            WebhookNotifier.dispatch_alert_async(
                alert_title=title,
                alert_type=alert_t,
                severity=sev,
                risk_score=risk_result['calculated_risk_score'],
                username=username,
                ip_address=ip_address,
                location=current_location,
                resource=accessed_resource,
                rule_flags=risk_result['rule_flags'],
                reasons=risk_result['reasons'],
                lockout_info=lockout_msg if account_locked else None,
                is_simulated=is_simulated
            )

        # Real-Time SSE Telemetry Stream Dispatch
        try:
            SSEBroadcaster.publish('activity', {
                'activity_id': activity_record.id,
                'username': username,
                'ip_address': ip_address,
                'city': city,
                'country': country,
                'lat': lat,
                'lon': lon,
                'location': current_location,
                'login_status': login_status,
                'risk_score': round(risk_result['calculated_risk_score'], 1),
                'risk_level': risk_result['risk_level'],
                'accessed_resource': accessed_resource,
                'timestamp': now.strftime('%H:%M:%S UTC'),
                'is_simulated': is_simulated,
                'account_locked': account_locked
            })

            if alert_record:
                SSEBroadcaster.publish('alert', {
                    'alert_id': alert_record.id,
                    'activity_id': activity_record.id,
                    'username': username,
                    'title': alert_record.alert_title,
                    'severity': alert_record.severity,
                    'risk_score': round(alert_record.risk_score, 1),
                    'ip_address': ip_address,
                    'city': city,
                    'country': country,
                    'lat': lat,
                    'lon': lon,
                    'timestamp': now.strftime('%Y-%m-%d %H:%M'),
                    'is_simulated': is_simulated
                })
        except Exception:
            pass

        # Update user's last geographic position and activity time
        if user and not is_simulated:
            user.last_latitude = lat
            user.last_longitude = lon
            user.last_city = city
            user.last_country = country
            user.last_activity_time = now

        # 8. Baseline profile update (with strict anti-poisoning safeguards)
        baseline_updated = False
        baseline_msg = ""
        if user_id:
            baseline_updated, baseline_msg = BehaviourProfiler.update_baseline(
                user_id=user_id,
                activity=activity_record,
                risk_score=risk_result['calculated_risk_score']
            )

        db.session.commit()

        return {
            'activity_id': activity_record.id,
            'username': username,
            'timestamp': now.strftime('%Y-%m-%d %H:%M:%S'),
            'ip_address': ip_address,
            'device_info': device_info,
            'operating_system': operating_system,
            'browser': browser,
            'accessed_resource': accessed_resource,
            'resource_sensitivity': resource_sensitivity,
            'login_status': login_status,
            'is_simulated': is_simulated,
            'location': current_location,
            'city': city,
            'country': country,
            'travel_evaluation': travel_eval,
            'account_locked': account_locked,
            'lockout_msg': lockout_msg,
            'ml_anomaly_score': ml_result['ml_anomaly_score'],
            'is_ml_anomaly': ml_result['is_ml_anomaly'],
            'raw_decision_score': ml_result.get('raw_decision_score', 0.0),
            'ml_latency_ms': ml_result.get('latency_ms', 0.0),
            'calculated_risk_score': risk_result['calculated_risk_score'],
            'risk_level': risk_result['risk_level'],
            'rule_flags': risk_result['rule_flags'],
            'reasons': risk_result['reasons'],
            'deviations': deviations,
            'alert_raised': alert_record is not None,
            'alert_id': alert_record.id if alert_record else None,
            'baseline_updated': baseline_updated,
            'baseline_msg': baseline_msg
        }
