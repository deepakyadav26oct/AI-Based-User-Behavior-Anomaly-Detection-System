import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config import Config
from models.ml_model import BehaviorAnomalyDetector
from modules.risk_engine import RiskEngine

def run_sample_tests():
    print("[Test Detection] Loading trained Isolation Forest model...")
    model_path = str(Config.MODEL_PATH)
    try:
        detector = BehaviorAnomalyDetector.load(model_path)
    except FileNotFoundError:
        print("[Test Detection] Model not found. Please run scripts/train_model.py first.")
        return

    test_scenarios = [
        {
            'name': 'Standard Daytime Office Login (Normal)',
            'data': {
                'login_hour': 10,
                'day_of_week': 1,
                'failed_login_count': 0,
                'session_duration': 2400,
                'access_frequency': 2,
                'resource_sensitivity': 'LOW',
                'accessed_resource': '/dashboard',
                'operating_system': 'Windows 11',
                'browser': 'Google Chrome',
                'device_info': 'Desktop Workstation'
            },
            'deviations': {
                'is_new_ip': False,
                'is_new_device': False,
                'is_unusual_hour': False,
                'is_abnormal_resource': False
            }
        },
        {
            'name': 'Midnight Login from New Device (Medium/High Anomaly)',
            'data': {
                'login_hour': 3,
                'day_of_week': 5,
                'failed_login_count': 1,
                'session_duration': 600,
                'access_frequency': 4,
                'resource_sensitivity': 'MEDIUM',
                'accessed_resource': '/documents/shared',
                'operating_system': 'Android',
                'browser': 'Chrome Mobile',
                'device_info': 'Mobile Device'
            },
            'deviations': {
                'is_new_ip': True,
                'is_new_device': True,
                'is_unusual_hour': True,
                'is_abnormal_resource': False
            }
        },
        {
            'name': 'Brute Force Attack + Kali Linux (Critical Threat)',
            'data': {
                'login_hour': 2,
                'day_of_week': 2,
                'failed_login_count': 8,
                'session_duration': 45,
                'access_frequency': 30,
                'resource_sensitivity': 'CRITICAL',
                'accessed_resource': '/database/credentials',
                'operating_system': 'Kali Linux',
                'browser': 'Tor Browser',
                'device_info': 'Unknown Penetration Testing Rig'
            },
            'deviations': {
                'is_new_ip': True,
                'is_new_device': True,
                'is_unusual_hour': True,
                'is_abnormal_resource': True
            }
        }
    ]

    for tc in test_scenarios:
        print("\n" + "-" * 60)
        print(f"Scenario: {tc['name']}")
        print("-" * 60)
        
        merged_for_ml = dict(tc['data'])
        merged_for_ml['is_new_ip'] = tc['deviations']['is_new_ip']
        merged_for_ml['is_new_device'] = tc['deviations']['is_new_device']
        merged_for_ml['is_unusual_hour'] = tc['deviations']['is_unusual_hour']

        ml_res = detector.predict_single(merged_for_ml)
        risk_res = RiskEngine.evaluate(tc['data'], tc['deviations'], ml_res)

        print(f"  ML Decision Function : {ml_res['raw_decision_score']:.4f}")
        print(f"  ML Anomaly Flag      : {ml_res['is_ml_anomaly']} (Score: {ml_res['ml_anomaly_score']:.4f})")
        print(f"  Inference Latency    : {ml_res['latency_ms']:.3f} ms")
        print(f"  Calculated Risk Score: {risk_res['calculated_risk_score']:.1f} / 100")
        print(f"  Assigned Risk Tier   : [{risk_res['risk_level'].upper()}]")
        print(f"  Rule Flags Triggered : {risk_res['rule_flags']}")
        print("  Documented Reasons   :")
        for r in risk_res['reasons']:
            print(f"    * {r}")

if __name__ == '__main__':
    run_sample_tests()
