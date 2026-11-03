from datetime import datetime
from typing import Dict, Any, Tuple
from models.database import db, UserBehaviourProfile, LoginActivity

class BehaviourProfiler:
    """
    Maintains and updates behavioral profiles for each user.
    Enforces baseline protection safeguards against profile poisoning.
    """

    DEFAULT_OFFICE_HOURS = [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]

    @staticmethod
    def get_or_create_profile(user_id: int) -> UserBehaviourProfile:
        """Fetch existing profile or create initial profile with corporate defaults."""
        profile = UserBehaviourProfile.query.filter_by(user_id=user_id).first()
        if not profile:
            profile = UserBehaviourProfile(
                user_id=user_id,
                typical_login_hours_raw='[8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]',
                known_ips_raw='[]',
                known_devices_raw='[]',
                known_browsers_raw='[]',
                typical_resources_raw='["/dashboard", "/profile", "/api/v1/auth"]',
                avg_session_duration=1800.0,
                total_logins=0,
                total_failed_logins=0,
                is_baseline_locked=False
            )
            db.session.add(profile)
            db.session.commit()
        return profile

    @staticmethod
    def inspect_against_baseline(profile: UserBehaviourProfile, activity_data: Dict[str, Any]) -> Dict[str, bool]:
        """
        Compare current activity against baseline profile.
        Returns boolean flags for deviations.
        """
        hour = int(activity_data.get('login_hour', 12))
        ip = str(activity_data.get('ip_address', '')).strip()
        device = str(activity_data.get('device_info', '')).strip()
        browser = str(activity_data.get('browser', '')).strip()
        resource = str(activity_data.get('accessed_resource', '')).strip()
        sensitivity = str(activity_data.get('resource_sensitivity', 'LOW')).upper()

        # Check unusual hour
        known_hours = profile.typical_login_hours or BehaviourProfiler.DEFAULT_OFFICE_HOURS
        # Allow +/- 1 hour margin of known hours
        expanded_hours = set()
        for h in known_hours:
            expanded_hours.add(h)
            expanded_hours.add((h - 1) % 24)
            expanded_hours.add((h + 1) % 24)
        is_unusual_hour = (hour not in expanded_hours) or (0 <= hour <= 5)

        # Check new IP
        known_ips = profile.known_ips
        is_new_ip = bool(known_ips and ip not in known_ips)

        # Check new device
        known_devices = profile.known_devices
        is_new_device = bool(known_devices and device not in known_devices)

        # Check new browser
        known_browsers = profile.known_browsers
        is_new_browser = bool(known_browsers and browser not in known_browsers)

        # Check abnormal resource access
        known_resources = profile.typical_resources
        is_abnormal_resource = (sensitivity in ('HIGH', 'CRITICAL')) and (resource not in known_resources)

        return {
            'is_unusual_hour': is_unusual_hour,
            'is_new_ip': is_new_ip,
            'is_new_device': is_new_device,
            'is_new_browser': is_new_browser,
            'is_abnormal_resource': is_abnormal_resource,
        }

    @staticmethod
    def update_baseline(
        user_id: int,
        activity: LoginActivity,
        risk_score: float
    ) -> Tuple[bool, str]:
        """
        Safely update user's behavioral baseline.
        CRITICAL SECURITY SAFEGUARD:
        Baseline is NOT updated if:
        1. Baseline is locked by administrator.
        2. Activity was a failed login.
        3. Risk score is >= 30 (Medium or High risk event).
        4. Activity is marked as simulated test event.
        """
        profile = BehaviourProfiler.get_or_create_profile(user_id)

        if profile.is_baseline_locked:
            return False, "Baseline update skipped: Profile is locked by administrator."

        if activity.is_simulated:
            return False, "Baseline update skipped: Event is simulated testing data."

        if activity.login_status != 'SUCCESS':
            profile.total_failed_logins += 1
            db.session.commit()
            return False, "Baseline update skipped: Login attempt failed."

        if risk_score >= 30:
            return False, f"Baseline update blocked: Risk score {risk_score:.1f} exceeds safety threshold (30)."

        # Legitimate, verified activity - safely update baseline
        # 1. Update hours
        hours = set(profile.typical_login_hours)
        hours.add(activity.login_hour)
        profile.typical_login_hours = list(hours)

        # 2. Update IPs (retain up to 10 most recent)
        ips = profile.known_ips
        if activity.ip_address not in ips:
            ips.append(activity.ip_address)
            if len(ips) > 10:
                ips.pop(0)
            profile.known_ips = ips

        # 3. Update devices (retain up to 5)
        devices = profile.known_devices
        if activity.device_info not in devices:
            devices.append(activity.device_info)
            if len(devices) > 5:
                devices.pop(0)
            profile.known_devices = devices

        # 4. Update browsers
        browsers = profile.known_browsers
        if activity.browser not in browsers:
            browsers.append(activity.browser)
            if len(browsers) > 5:
                browsers.pop(0)
            profile.known_browsers = browsers

        # 5. Update typical resources
        resources = profile.typical_resources
        if activity.accessed_resource not in resources:
            resources.append(activity.accessed_resource)
            if len(resources) > 20:
                resources.pop(0)
            profile.typical_resources = resources

        # 6. Update session duration with Exponential Moving Average
        if activity.session_duration > 0:
            profile.avg_session_duration = (0.85 * profile.avg_session_duration) + (0.15 * float(activity.session_duration))

        profile.total_logins += 1
        profile.last_updated = datetime.utcnow()
        db.session.commit()

        return True, "Baseline profile safely updated."
