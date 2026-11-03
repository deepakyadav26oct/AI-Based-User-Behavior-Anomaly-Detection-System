from typing import Dict, Any, List, Tuple, Optional
from config import Config

class RiskEngine:
    """
    Combines Machine Learning anomaly scores with heuristic contextual security rules
    to generate an explainable composite risk score (0 to 100) and risk category.
    """

    SUSPICIOUS_OS_LIST = ['kali linux', 'parrot os', 'unknown', 'blackarch']
    SUSPICIOUS_BROWSER_LIST = ['tor browser', 'headlesschrome', 'curl', 'python-requests', 'postman']

    @classmethod
    def evaluate(
        cls,
        activity_data: Dict[str, Any],
        profile_deviations: Dict[str, bool],
        ml_result: Dict[str, Any],
        travel_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Evaluate risk score, determine risk category, and document explainable reasons.
        """
        rule_points = 0.0
        rule_flags: List[str] = []
        reasons: List[str] = []

        # 1. Base ML Contribution (up to 35 points)
        ml_score = float(ml_result.get('ml_anomaly_score', 0.0))
        is_ml_anomaly = bool(ml_result.get('is_ml_anomaly', False))
        ml_points = ml_score * 35.0
        rule_points += ml_points

        if is_ml_anomaly:
            rule_flags.append('RULE_ML_ANOMALY')
            reasons.append(
                f"Isolation Forest identified multidimensional behavioral divergence (ML Outlier Score: {ml_score:.2f})."
            )

        # 2. Rule 1: Login during unusual hours
        if profile_deviations.get('is_unusual_hour', False):
            hour = activity_data.get('login_hour', 0)
            rule_points += 22.0
            rule_flags.append('RULE_UNUSUAL_HOUR')
            reasons.append(f"Login attempt at unusual hour ({hour:02d}:00) deviates from established user schedule.")

        # 3. Rule 2: Login from a new IP address
        if profile_deviations.get('is_new_ip', False):
            ip = activity_data.get('ip_address', 'Unknown')
            rule_points += 25.0
            rule_flags.append('RULE_NEW_IP')
            reasons.append(f"Authentication originated from unrecognized IP address: {ip}.")

        # 4. Rule 3: Login from an unknown device or suspicious OS/Browser
        os_name = str(activity_data.get('operating_system', '')).lower()
        browser_name = str(activity_data.get('browser', '')).lower()
        device_name = activity_data.get('device_info', 'Unknown Device')
        
        is_suspicious_environment = any(s in os_name for s in cls.SUSPICIOUS_OS_LIST) or \
                                    any(b in browser_name for b in cls.SUSPICIOUS_BROWSER_LIST)

        if is_suspicious_environment:
            rule_points += 30.0
            rule_flags.append('RULE_SUSPICIOUS_TOOLING')
            reasons.append(f"Connection initiated via penetration testing OS or anonymized client: {os_name} / {browser_name}.")
        elif profile_deviations.get('is_new_device', False):
            rule_points += 20.0
            rule_flags.append('RULE_NEW_DEVICE')
            reasons.append(f"Unfamiliar device hardware signature: {device_name}.")

        # 5. Rule 4: Multiple failed login attempts (Brute Force Detection)
        failed_count = int(activity_data.get('failed_login_count', 0))
        login_status = str(activity_data.get('login_status', 'SUCCESS')).upper()

        if failed_count >= 5:
            rule_points += 45.0
            rule_flags.append('RULE_BRUTE_FORCE')
            reasons.append(f"Critical brute-force attack threshold reached: {failed_count} repeated authentication failures.")
        elif failed_count >= 2:
            rule_points += 20.0
            rule_flags.append('RULE_FAILED_LOGINS')
            reasons.append(f"Elevated credential failure velocity: {failed_count} prior failed attempts.")

        if login_status == 'FAILED' and failed_count < 2:
            rule_points += 10.0
            reasons.append("Single failed login attempt registered.")

        # 6. Rule 5: Unusual access frequency
        frequency = int(activity_data.get('access_frequency', 1))
        if frequency >= 15:
            rule_points += 25.0
            rule_flags.append('RULE_EXCESSIVE_FREQUENCY')
            reasons.append(f"High-frequency request spike: {frequency} access requests within current window.")
        elif frequency >= 8:
            rule_points += 15.0
            rule_flags.append('RULE_ELEVATED_FREQUENCY')
            reasons.append(f"Elevated access frequency detected ({frequency} requests/window).")

        # 7. Rule 6: Abnormal sensitive file or resource access
        sensitivity = str(activity_data.get('resource_sensitivity', 'LOW')).upper()
        resource = activity_data.get('accessed_resource', '/dashboard')

        if sensitivity == 'CRITICAL':
            rule_points += 35.0
            rule_flags.append('RULE_CRITICAL_RESOURCE')
            reasons.append(f"Attempted access to mission-critical asset: {resource}.")
        elif sensitivity == 'HIGH':
            if profile_deviations.get('is_abnormal_resource', False):
                rule_points += 25.0
                rule_flags.append('RULE_ABNORMAL_HIGH_RESOURCE')
                reasons.append(f"Unaccustomed access to high-security resource outside normal workflow: {resource}.")
            else:
                rule_points += 15.0
                reasons.append(f"High-sensitivity resource access recorded: {resource}.")

        # 8. Rule 7: Suspicious changes in user behaviour
        session_dur = float(activity_data.get('session_duration', 1800))
        if session_dur > 28800:  # 8+ hours continuous
            rule_points += 15.0
            rule_flags.append('RULE_SESSION_ANOMALY')
            reasons.append(f"Abnormally extended session duration ({int(session_dur // 3600)} hours).")

        # 9. Rule 8: Impossible Travel / Geographic Velocity Violation
        if travel_data and travel_data.get('is_impossible_travel', False):
            rule_points += 45.0
            rule_flags.append('RULE_IMPOSSIBLE_TRAVEL')
            reasons.append(travel_data.get('reason', 'Impossible human travel velocity detected between successive ingress points.'))

        # Clamp total risk score to [0, 100]
        final_score = min(100.0, max(0.0, rule_points))

        # Assign Risk Category according to specification
        if final_score >= Config.RISK_HIGH_MIN:
            risk_level = 'High'
        elif final_score > Config.RISK_LOW_MAX:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'

        if not reasons:
            reasons.append("User behavior aligns with verified baseline profile and corporate security policies.")

        return {
            'calculated_risk_score': round(final_score, 1),
            'risk_level': risk_level,
            'rule_flags': rule_flags,
            'reasons': reasons,
            'ml_points_contributed': round(ml_points, 1),
            'rule_points_contributed': round(rule_points - ml_points, 1)
        }
