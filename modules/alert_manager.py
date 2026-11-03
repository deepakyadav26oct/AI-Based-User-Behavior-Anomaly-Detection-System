from datetime import datetime
from typing import Dict, Any, Optional
from config import Config
from models.database import db, SecurityAlert, LoginActivity, DetectionResult, AuditLog

class AlertManager:
    """
    Automated alert dispatch, triage, resolution lifecycle, and audit trail management.
    """

    @staticmethod
    def create_alert_if_warranted(
        activity: LoginActivity,
        detection: DetectionResult,
        risk_data: Dict[str, Any]
    ) -> Optional[SecurityAlert]:
        """
        Evaluate if a SecurityAlert should be raised based on risk score and security flags.
        """
        risk_score = float(risk_data.get('calculated_risk_score', 0.0))
        rule_flags = risk_data.get('rule_flags', [])
        reasons = risk_data.get('reasons', [])
        
        # Determine trigger condition: Medium/High risk or ML anomaly or specific attack flags
        trigger_threshold = Config.ALERT_TRIGGER_THRESHOLD
        should_alert = (risk_score >= trigger_threshold) or ('RULE_BRUTE_FORCE' in rule_flags) or ('RULE_CRITICAL_RESOURCE' in rule_flags)

        if not should_alert:
            return None

        # Determine Primary Alert Type
        if 'RULE_IMPOSSIBLE_TRAVEL' in rule_flags:
            alert_type = 'IMPOSSIBLE_TRAVEL_ANOMALY'
            title = f"Impossible Geographical Velocity Detected: {activity.username}"
        elif 'RULE_BRUTE_FORCE' in rule_flags:
            alert_type = 'BRUTE_FORCE_ATTACK'
            title = f"Brute Force Authentication Storm Detected on User: {activity.username}"
        elif 'RULE_CRITICAL_RESOURCE' in rule_flags:
            alert_type = 'CRITICAL_ASSET_VIOLATION'
            title = f"Unauthorized Critical Asset Access: {activity.accessed_resource}"
        elif 'RULE_SUSPICIOUS_TOOLING' in rule_flags:
            alert_type = 'PENETRATION_TESTING_TOOL_DETECTED'
            title = f"Adversarial OS / Client Access Attempt by {activity.username}"
        elif 'RULE_UNUSUAL_HOUR' in rule_flags and 'RULE_NEW_IP' in rule_flags:
            alert_type = 'OFF_HOURS_UNKNOWN_LOCATION'
            title = f"Off-Hours Login from Unrecognized IP: {activity.username}"
        elif 'RULE_NEW_IP' in rule_flags:
            alert_type = 'UNRECOGNIZED_IP_ORIGIN'
            title = f"First-Time IP Access: {activity.username} [{activity.ip_address}]"
        elif 'RULE_UNUSUAL_HOUR' in rule_flags:
            alert_type = 'OFF_HOURS_ACCESS'
            title = f"Anomalous Login Schedule: {activity.username} at {activity.login_hour:02d}:00"
        elif 'RULE_ML_ANOMALY' in rule_flags:
            alert_type = 'ML_BEHAVIORAL_ANOMALY'
            title = f"Multi-Vector Behavioral Outlier Flagged by Isolation Forest: {activity.username}"
        else:
            alert_type = 'SUSPICIOUS_USER_ACTIVITY'
            title = f"Elevated Risk Behavior Recorded for {activity.username}"

        # Assign Alert Severity
        if risk_score >= 85:
            severity = 'Critical'
        elif risk_score >= 70:
            severity = 'High'
        elif risk_score >= 40:
            severity = 'Medium'
        else:
            severity = 'Low'

        alert = SecurityAlert(
            activity_id=activity.id,
            detection_result_id=detection.id,
            user_id=activity.user_id,
            username=activity.username,
            alert_title=title,
            alert_type=alert_type,
            severity=severity,
            risk_score=risk_score,
            status='OPEN',
            reasons=reasons,
            is_simulated=activity.is_simulated,
            created_at=datetime.utcnow()
        )
        db.session.add(alert)
        db.session.commit()
        return alert

    @staticmethod
    def review_alert(alert_id: int, reviewer_username: str) -> SecurityAlert:
        """Move alert to IN_REVIEW status."""
        alert = db.session.get(SecurityAlert, alert_id)
        if not alert:
            raise ValueError(f"Alert with ID {alert_id} not found.")

        alert.status = 'IN_REVIEW'
        
        audit = AuditLog(
            user_id=None,
            username=reviewer_username,
            action='ALERT_UNDER_REVIEW',
            details=f"Alert #{alert.id} ({alert.alert_title}) placed in active review by {reviewer_username}."
        )
        db.session.add(audit)
        db.session.commit()
        return alert

    @staticmethod
    def resolve_alert(alert_id: int, resolution_notes: str, resolver_username: str) -> SecurityAlert:
        """Mark alert as RESOLVED with audit record."""
        alert = db.session.get(SecurityAlert, alert_id)
        if not alert:
            raise ValueError(f"Alert with ID {alert_id} not found.")

        alert.status = 'RESOLVED'
        alert.resolved_at = datetime.utcnow()
        alert.resolved_by = resolver_username
        alert.resolution_notes = resolution_notes

        audit = AuditLog(
            user_id=None,
            username=resolver_username,
            action='ALERT_RESOLVED',
            details=f"Alert #{alert.id} ({alert.alert_title}) resolved by {resolver_username}. Notes: {resolution_notes}"
        )
        db.session.add(audit)
        db.session.commit()
        return alert

    @staticmethod
    def dismiss_alert(alert_id: int, dismissal_reason: str, dismisser_username: str) -> SecurityAlert:
        """Dismiss alert as false positive or acceptable risk."""
        alert = db.session.get(SecurityAlert, alert_id)
        if not alert:
            raise ValueError(f"Alert with ID {alert_id} not found.")

        alert.status = 'DISMISSED'
        alert.resolved_at = datetime.utcnow()
        alert.resolved_by = dismisser_username
        alert.resolution_notes = f"Dismissed: {dismissal_reason}"

        audit = AuditLog(
            user_id=None,
            username=dismisser_username,
            action='ALERT_DISMISSED',
            details=f"Alert #{alert.id} dismissed by {dismisser_username}. Reason: {dismissal_reason}"
        )
        db.session.add(audit)
        db.session.commit()
        return alert

    @staticmethod
    def get_summary_statistics() -> Dict[str, Any]:
        """Aggregate alert metrics for dashboard cards and reporting."""
        total = SecurityAlert.query.count()
        open_count = SecurityAlert.query.filter_by(status='OPEN').count()
        in_review = SecurityAlert.query.filter_by(status='IN_REVIEW').count()
        resolved = SecurityAlert.query.filter_by(status='RESOLVED').count()
        dismissed = SecurityAlert.query.filter_by(status='DISMISSED').count()
        critical_high = SecurityAlert.query.filter(SecurityAlert.severity.in_(['High', 'Critical'])).count()

        return {
            'total_alerts': total,
            'open_alerts': open_count,
            'in_review_alerts': in_review,
            'resolved_alerts': resolved,
            'dismissed_alerts': dismissed,
            'critical_high_alerts': critical_high
        }
