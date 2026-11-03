import json
import logging
import threading
import urllib.request
import urllib.error
from datetime import datetime
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)

class WebhookNotifier:
    """
    Real-time SOC alert dispatcher supporting Discord, Slack, and generic JSON webhooks.
    Executes asynchronously in background worker threads to guarantee zero latency penalty
    on the primary authentication/monitoring pipeline.
    """

    @classmethod
    def get_settings(cls) -> Dict[str, str]:
        """Fetch current webhook configurations from SystemSetting database table."""
        from models.database import SystemSetting
        try:
            return {
                'enabled': SystemSetting.get_setting('WEBHOOK_ENABLED', 'false').lower() in ('true', '1', 'yes'),
                'url': SystemSetting.get_setting('WEBHOOK_URL', '').strip(),
                'min_severity': SystemSetting.get_setting('WEBHOOK_MIN_SEVERITY', 'HIGH').upper(),
            }
        except Exception as e:
            logger.warning(f"Failed to read webhook settings: {e}")
            return {'enabled': False, 'url': '', 'min_severity': 'HIGH'}

    @classmethod
    def detect_platform(cls, url: str) -> str:
        """Detect webhook provider type based on URL structure."""
        url_lower = url.lower()
        if 'discord.com' in url_lower or 'discordapp.com' in url_lower:
            return 'discord'
        elif 'slack.com' in url_lower:
            return 'slack'
        return 'generic'

    @classmethod
    def build_discord_payload(
        cls,
        title: str,
        description: str,
        severity: str,
        risk_score: float,
        username: str,
        ip_address: str,
        location: str,
        resource: str,
        rule_flags: list,
        reasons: list,
        lockout_info: Optional[str] = None,
        is_simulated: bool = False
    ) -> Dict[str, Any]:
        """Build Discord Embed structure."""
        sim_prefix = "[SIMULATION LAB] " if is_simulated else ""
        
        # Color mapping: Crimson Red for Critical/High, Amber for Medium, Green for Info
        color = 0xFF0033 if severity in ('Critical', 'High') or risk_score >= 70 else (0xFFA502 if severity == 'Medium' else 0x00F2FE)
        
        fields = [
            {"name": "👤 Target Principal", "value": f"`{username}`", "inline": True},
            {"name": "🛡️ Risk Assessment", "value": f"**{risk_score:.1f} / 100** ({severity})", "inline": True},
            {"name": "🔒 Active Defense", "value": f"**{'[AI LOCKED]' if lockout_info else 'ACTIVE'}**", "inline": True},
            {"name": "🌐 Origin Telemetry", "value": f"`{ip_address}` ({location})", "inline": False},
            {"name": "🎯 Target Resource", "value": f"`{resource}`", "inline": True},
        ]

        if rule_flags:
            flags_str = " ".join([f"`{f}`" for f in rule_flags])
            fields.append({"name": "🚩 Triggered Security Rules", "value": flags_str, "inline": False})

        if reasons:
            top_reasons = "\n".join([f"• {r}" for r in reasons[:3]])
            fields.append({"name": "📋 Explainable AI Root Causes", "value": top_reasons, "inline": False})

        if lockout_info:
            fields.append({"name": "⚠️ Threat Mitigation Action", "value": f"```{lockout_info}```", "inline": False})

        return {
            "username": "CyberGuard Sentinel SOC",
            "avatar_url": "https://img.icons8.com/fluency/96/shield.png",
            "embeds": [
                {
                    "title": f"🚨 {sim_prefix}CYBERGUARD SOC THREAT ALERT",
                    "description": f"**{title}**\n{description}",
                    "color": color,
                    "fields": fields,
                    "footer": {
                        "text": "CyberGuard Sentinel AI • User Behavior Anomaly Detection Engine",
                        "icon_url": "https://img.icons8.com/fluency/48/lock-shield.png"
                    },
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
            ]
        }

    @classmethod
    def build_slack_payload(
        cls,
        title: str,
        description: str,
        severity: str,
        risk_score: float,
        username: str,
        ip_address: str,
        location: str,
        resource: str,
        rule_flags: list,
        reasons: list,
        lockout_info: Optional[str] = None,
        is_simulated: bool = False
    ) -> Dict[str, Any]:
        """Build Slack Incoming Webhook structure."""
        sim_prefix = "[SIMULATION LAB] " if is_simulated else ""
        color = "#ff0033" if severity in ('Critical', 'High') else "#ffa502"

        fields_text = (
            f"*Principal:* `{username}` | *Risk Score:* *{risk_score:.1f}/100* ({severity})\n"
            f"*Origin IP:* `{ip_address}` ({location}) | *Resource:* `{resource}`\n"
        )
        if lockout_info:
            fields_text += f"*Active Defense:* :lock: `{lockout_info}`\n"
        if rule_flags:
            fields_text += f"*Rule Flags:* {', '.join(rule_flags)}\n"

        return {
            "text": f"🚨 {sim_prefix}*CyberGuard Sentinel Alert:* {title}",
            "attachments": [
                {
                    "color": color,
                    "title": f"{sim_prefix}{title}",
                    "text": f"{description}\n\n{fields_text}",
                    "footer": "CyberGuard Sentinel AI SOC",
                    "ts": int(datetime.utcnow().timestamp())
                }
            ]
        }

    @classmethod
    def build_generic_payload(
        cls,
        title: str,
        description: str,
        severity: str,
        risk_score: float,
        username: str,
        ip_address: str,
        location: str,
        resource: str,
        rule_flags: list,
        reasons: list,
        lockout_info: Optional[str] = None,
        is_simulated: bool = False
    ) -> Dict[str, Any]:
        """Build standard JSON webhook structure."""
        return {
            "event_type": "SECURITY_THREAT_ALERT",
            "is_simulated": is_simulated,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "alert": {
                "title": title,
                "description": description,
                "severity": severity,
                "risk_score": risk_score
            },
            "principal": {
                "username": username,
                "ip_address": ip_address,
                "location": location
            },
            "telemetry": {
                "accessed_resource": resource,
                "rule_flags": rule_flags,
                "reasons": reasons,
                "account_locked": bool(lockout_info),
                "lockout_details": lockout_info
            }
        }

    @classmethod
    def send_http_post(cls, url: str, payload: Dict[str, Any], timeout: float = 4.0) -> Tuple[bool, int, str]:
        """Execute HTTP POST request with standard library urllib."""
        try:
            req_data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                url,
                data=req_data,
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'CyberGuard-Sentinel-SOC/2.4'
                },
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                status_code = response.getcode()
                return (200 <= status_code < 300, status_code, "Webhook delivered successfully.")
        except urllib.error.HTTPError as e:
            return (False, e.code, f"HTTP Error {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            return (False, 0, f"Network Connection Error: {e.reason}")
        except Exception as e:
            return (False, 0, f"Webhook Dispatch Failure: {str(e)}")

    @classmethod
    def dispatch_alert_async(
        cls,
        alert_title: str,
        alert_type: str,
        severity: str,
        risk_score: float,
        username: str,
        ip_address: str,
        location: str,
        resource: str,
        rule_flags: list,
        reasons: list,
        lockout_info: Optional[str] = None,
        is_simulated: bool = False
    ) -> None:
        """
        Dispatches webhook alert asynchronously in a background daemon thread.
        Never blocks or delays request handling.
        """
        try:
            cfg = cls.get_settings()
        except Exception:
            return

        if not cfg.get('enabled') or not cfg.get('url'):
            return

        min_sev = cfg.get('min_severity', 'HIGH')
        if min_sev == 'HIGH' and severity not in ('High', 'Critical') and not lockout_info:
            return

        target_url = cfg['url']
        platform = cls.detect_platform(target_url)

        if platform == 'discord':
            payload = cls.build_discord_payload(
                title=alert_title,
                description=f"Incident Classification: `{alert_type}`",
                severity=severity,
                risk_score=risk_score,
                username=username,
                ip_address=ip_address,
                location=location,
                resource=resource,
                rule_flags=rule_flags,
                reasons=reasons,
                lockout_info=lockout_info,
                is_simulated=is_simulated
            )
        elif platform == 'slack':
            payload = cls.build_slack_payload(
                title=alert_title,
                description=f"Incident Classification: `{alert_type}`",
                severity=severity,
                risk_score=risk_score,
                username=username,
                ip_address=ip_address,
                location=location,
                resource=resource,
                rule_flags=rule_flags,
                reasons=reasons,
                lockout_info=lockout_info,
                is_simulated=is_simulated
            )
        else:
            payload = cls.build_generic_payload(
                title=alert_title,
                description=f"Incident Classification: `{alert_type}`",
                severity=severity,
                risk_score=risk_score,
                username=username,
                ip_address=ip_address,
                location=location,
                resource=resource,
                rule_flags=rule_flags,
                reasons=reasons,
                lockout_info=lockout_info,
                is_simulated=is_simulated
            )

        def _worker():
            try:
                success, code, msg = cls.send_http_post(target_url, payload)
                if not success:
                    logger.warning(f"Background webhook dispatch failed (code {code}): {msg}")
            except Exception as e:
                logger.error(f"Error in background webhook worker: {e}")

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()

    @classmethod
    def send_test_ping(cls, webhook_url: str) -> Dict[str, Any]:
        """
        Sends an immediate synchronous test ping to verify webhook URL connectivity.
        """
        if not webhook_url or not webhook_url.startswith(('http://', 'https://')):
            return {
                'success': False,
                'status_code': 400,
                'message': 'Invalid Webhook URL. Must begin with http:// or https://'
            }

        platform = cls.detect_platform(webhook_url)
        now_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

        if platform == 'discord':
            payload = {
                "username": "CyberGuard Sentinel SOC",
                "avatar_url": "https://img.icons8.com/fluency/96/shield.png",
                "embeds": [
                    {
                        "title": "✅ [TEST PING] CyberGuard SOC Webhook Channel Verified",
                        "description": "Integration channel connectivity test from CyberGuard Sentinel AI Anomaly Detection System.",
                        "color": 0x00F2FE,
                        "fields": [
                            {"name": "Channel Status", "value": "🟢 `ONLINE & OPERATIONAL`", "inline": True},
                            {"name": "Security Mode", "value": "`ACTIVE SENTINEL AI`", "inline": True},
                            {"name": "Timestamp", "value": f"`{now_str}`", "inline": False},
                            {"name": "Alert Policy", "value": "Real-time High/Critical anomalies and automated account lockouts will be dispatched here.", "inline": False}
                        ],
                        "footer": {
                            "text": "CyberGuard Sentinel Test Probe",
                            "icon_url": "https://img.icons8.com/fluency/48/lock-shield.png"
                        }
                    }
                ]
            }
        elif platform == 'slack':
            payload = {
                "text": "✅ *[TEST PING]* CyberGuard SOC Webhook Channel Verified successfully at " + now_str
            }
        else:
            payload = {
                "event_type": "TEST_CONNECTIVITY_PING",
                "status": "ONLINE",
                "message": "CyberGuard Sentinel Webhook integration test passed.",
                "timestamp": now_str
            }

        success, code, msg = cls.send_http_post(webhook_url, payload, timeout=5.0)
        return {
            'success': success,
            'status_code': code,
            'platform': platform.upper(),
            'message': msg
        }
