import os
import random
import numpy as np
import pandas as pd
from faker import Faker
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = BASE_DIR / 'dataset' / 'raw'
PROCESSED_DIR = BASE_DIR / 'dataset' / 'processed'

fake = Faker()
Faker.seed(42)
np.random.seed(42)
random.seed(42)

USERS = [
    {'username': 'alice.chen', 'dept': 'Engineering', 'role': 'user'},
    {'username': 'bob.martinez', 'dept': 'Finance', 'role': 'user'},
    {'username': 'carol.smith', 'dept': 'Human Resources', 'role': 'user'},
    {'username': 'david.kim', 'dept': 'DevOps', 'role': 'analyst'},
    {'username': 'eva.rossi', 'dept': 'Executive', 'role': 'user'},
    {'username': 'frank.wright', 'dept': 'Security Operations', 'role': 'analyst'},
    {'username': 'grace.hopper', 'dept': 'Engineering', 'role': 'user'},
    {'username': 'hector.salamanca', 'dept': 'Procurement', 'role': 'user'},
    {'username': 'irene.adler', 'dept': 'Legal', 'role': 'user'},
    {'username': 'jack.reacher', 'dept': 'Facilities', 'role': 'user'},
]

INTERNAL_IPS = [
    '10.0.12.14', '10.0.12.25', '10.0.12.88', '10.0.14.102',
    '192.168.1.45', '192.168.1.110', '192.168.2.15', '172.16.4.12'
]

EXTERNAL_SUSPICIOUS_IPS = [
    '185.220.101.5', '194.26.29.112', '45.154.255.89', '91.240.118.23',
    '103.152.220.10', '198.51.100.44', '203.0.113.77'
]

STANDARD_DEVICES = [
    'Desktop Workstation (Corporate Dell)',
    'Laptop (ThinkPad X1)',
    'MacBook Pro Corporate',
]

STANDARD_BROWSERS = ['Google Chrome', 'Mozilla Firefox', 'Microsoft Edge', 'Apple Safari']
STANDARD_OS = ['Windows 11', 'macOS Sonoma', 'Ubuntu Linux']

NORMAL_RESOURCES = [
    ('/dashboard', 'LOW'),
    ('/profile', 'LOW'),
    ('/api/v1/auth', 'LOW'),
    ('/projects/tickets', 'LOW'),
    ('/documents/shared', 'MEDIUM'),
    ('/reports/weekly', 'MEDIUM'),
]

SENSITIVE_RESOURCES = [
    ('/admin/system-logs', 'HIGH'),
    ('/financial/payroll', 'HIGH'),
    ('/database/credentials', 'CRITICAL'),
    ('/security/keys/export', 'CRITICAL'),
    ('/api/v1/internal/admin-dump', 'CRITICAL'),
]

SENSITIVITY_NUMERIC = {
    'LOW': 1,
    'MEDIUM': 2,
    'HIGH': 3,
    'CRITICAL': 4
}

def generate_synthetic_data(n_normal=2250, n_anomalous=250):
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    records = []

    # 1. Normal Activity Records
    for i in range(n_normal):
        user_info = random.choice(USERS)
        hour = int(np.clip(np.random.normal(13, 2.8), 7, 20))
        day = random.choices([0, 1, 2, 3, 4, 5, 6], weights=[0.2, 0.2, 0.2, 0.2, 0.15, 0.03, 0.02])[0]
        ip = random.choice(INTERNAL_IPS)
        device = random.choice(STANDARD_DEVICES)
        browser = random.choice(STANDARD_BROWSERS)
        os_name = random.choice(STANDARD_OS)
        res_name, res_sens = random.choice(NORMAL_RESOURCES)
        
        failed_count = random.choices([0, 1, 2], weights=[0.94, 0.05, 0.01])[0]
        login_status = 'SUCCESS' if failed_count < 2 else random.choice(['SUCCESS', 'FAILED'])
        session_duration = int(np.clip(np.random.normal(2400, 800), 120, 10800))
        access_freq = random.choices([1, 2, 3, 4, 5], weights=[0.5, 0.25, 0.15, 0.07, 0.03])[0]

        is_new_ip = 1 if random.random() < 0.04 else 0
        is_new_device = 1 if random.random() < 0.02 else 0
        is_unusual_hour = 1 if (hour < 7 or hour > 21) else 0

        records.append({
            'username': user_info['username'],
            'department': user_info['dept'],
            'ip_address': ip,
            'device_info': device,
            'browser': browser,
            'operating_system': os_name,
            'accessed_resource': res_name,
            'resource_sensitivity': res_sens,
            'resource_sensitivity_numeric': SENSITIVITY_NUMERIC[res_sens],
            'login_status': login_status,
            'login_hour': hour,
            'day_of_week': day,
            'failed_login_count': failed_count,
            'session_duration': session_duration,
            'access_frequency': access_freq,
            'is_new_ip': is_new_ip,
            'is_new_device': is_new_device,
            'is_unusual_hour': is_unusual_hour,
            'is_anomaly': 0,
            'scenario': 'NORMAL_BASELINE_BEHAVIOR'
        })

    # 2. Anomalous Activity Records (Contaminants / Attack Simulations)
    scenarios = [
        'MIDNIGHT_LOGIN',
        'EXTERNAL_NEW_IP',
        'SUSPICIOUS_DEVICE_OS',
        'BRUTE_FORCE_ATTACK',
        'CRITICAL_RESOURCE_EXFILTRATION',
        'FREQUENCY_BURST_DOS',
    ]

    for i in range(n_anomalous):
        user_info = random.choice(USERS)
        scenario = random.choice(scenarios)

        if scenario == 'MIDNIGHT_LOGIN':
            hour = random.choice([1, 2, 3, 4])
            day = random.choice([5, 6, 0])
            ip = random.choice(INTERNAL_IPS)
            device = random.choice(STANDARD_DEVICES)
            browser = random.choice(STANDARD_BROWSERS)
            os_name = random.choice(STANDARD_OS)
            res_name, res_sens = random.choice(NORMAL_RESOURCES)
            failed_count = random.choice([0, 1])
            login_status = 'SUCCESS'
            session_duration = random.randint(60, 600)
            access_freq = random.randint(1, 3)
            is_new_ip = 0
            is_new_device = 0
            is_unusual_hour = 1

        elif scenario == 'EXTERNAL_NEW_IP':
            hour = random.randint(8, 22)
            day = random.randint(0, 6)
            ip = random.choice(EXTERNAL_SUSPICIOUS_IPS)
            device = random.choice(STANDARD_DEVICES)
            browser = random.choice(STANDARD_BROWSERS)
            os_name = random.choice(STANDARD_OS)
            res_name, res_sens = random.choice(NORMAL_RESOURCES)
            failed_count = random.choice([0, 1, 2])
            login_status = 'SUCCESS'
            session_duration = random.randint(300, 3600)
            access_freq = random.randint(1, 6)
            is_new_ip = 1
            is_new_device = 0
            is_unusual_hour = 0

        elif scenario == 'SUSPICIOUS_DEVICE_OS':
            hour = random.randint(9, 21)
            day = random.randint(0, 4)
            ip = random.choice(EXTERNAL_SUSPICIOUS_IPS)
            device = 'Unknown Linux Virtual Machine'
            browser = 'Tor Browser'
            os_name = 'Kali Linux'
            res_name, res_sens = random.choice(SENSITIVE_RESOURCES)
            failed_count = random.choice([1, 2])
            login_status = 'SUCCESS'
            session_duration = random.randint(600, 7200)
            access_freq = random.randint(3, 8)
            is_new_ip = 1
            is_new_device = 1
            is_unusual_hour = 0

        elif scenario == 'BRUTE_FORCE_ATTACK':
            hour = random.randint(0, 23)
            day = random.randint(0, 6)
            ip = random.choice(EXTERNAL_SUSPICIOUS_IPS)
            device = 'Automated Attack Rig'
            browser = 'Automated CLI / Script'
            os_name = 'Ubuntu Linux'
            res_name = '/api/v1/auth/login'
            res_sens = 'MEDIUM'
            failed_count = random.randint(5, 16)
            login_status = 'FAILED'
            session_duration = random.randint(5, 60)
            access_freq = random.randint(15, 45)
            is_new_ip = 1
            is_new_device = 1
            is_unusual_hour = 1 if hour in [0, 1, 2, 3, 4, 5] else 0

        elif scenario == 'CRITICAL_RESOURCE_EXFILTRATION':
            hour = random.choice([22, 23, 0, 1, 2])
            day = random.randint(0, 6)
            ip = random.choice(EXTERNAL_SUSPICIOUS_IPS)
            device = 'Unknown Headless Machine'
            browser = 'Mozilla Firefox'
            os_name = 'macOS Sonoma'
            res_name, res_sens = random.choice(SENSITIVE_RESOURCES[2:])  # CRITICAL
            failed_count = random.choice([0, 1])
            login_status = 'SUCCESS'
            session_duration = random.randint(120, 1800)
            access_freq = random.randint(8, 20)
            is_new_ip = 1
            is_new_device = 1
            is_unusual_hour = 1

        else:  # FREQUENCY_BURST_DOS
            hour = random.randint(8, 18)
            day = random.randint(0, 4)
            ip = random.choice(INTERNAL_IPS)
            device = random.choice(STANDARD_DEVICES)
            browser = random.choice(STANDARD_BROWSERS)
            os_name = random.choice(STANDARD_OS)
            res_name, res_sens = random.choice(NORMAL_RESOURCES)
            failed_count = random.choice([0, 1])
            login_status = 'SUCCESS'
            session_duration = random.randint(3600, 14400)
            access_freq = random.randint(20, 50)
            is_new_ip = 0
            is_new_device = 0
            is_unusual_hour = 0

        records.append({
            'username': user_info['username'],
            'department': user_info['dept'],
            'ip_address': ip,
            'device_info': device,
            'browser': browser,
            'operating_system': os_name,
            'accessed_resource': res_name,
            'resource_sensitivity': res_sens,
            'resource_sensitivity_numeric': SENSITIVITY_NUMERIC[res_sens],
            'login_status': login_status,
            'login_hour': hour,
            'day_of_week': day,
            'failed_login_count': failed_count,
            'session_duration': session_duration,
            'access_frequency': access_freq,
            'is_new_ip': is_new_ip,
            'is_new_device': is_new_device,
            'is_unusual_hour': is_unusual_hour,
            'is_anomaly': 1,
            'scenario': scenario
        })

    # Shuffle dataset
    random.shuffle(records)
    df = pd.DataFrame(records)

    raw_path = RAW_DIR / 'synthetic_user_activity.csv'
    df.to_csv(raw_path, index=False)
    print(f"[Dataset Generator] Successfully wrote {len(df)} records to {raw_path}")

    # Prepare features dataset for model training
    feature_cols = [
        'login_hour', 'day_of_week', 'failed_login_count',
        'is_new_ip', 'is_new_device', 'session_duration',
        'access_frequency', 'resource_sensitivity', 'is_unusual_hour',
        'is_anomaly'
    ]
    df_features = df[feature_cols].copy()
    # Map sensitivity string to numeric
    df_features['resource_sensitivity'] = df['resource_sensitivity'].map(SENSITIVITY_NUMERIC)

    processed_path = PROCESSED_DIR / 'features.csv'
    df_features.to_csv(processed_path, index=False)
    print(f"[Dataset Generator] Successfully wrote processed features to {processed_path}")

    return df

if __name__ == '__main__':
    generate_synthetic_data()
