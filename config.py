import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Application configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cyber-guard-ai-sentinel-key-2026-x99f')
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL', f"sqlite:///{BASE_DIR / 'instance' / 'cyber_anomaly_detection.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Paths
    BASE_DIR = BASE_DIR
    MODEL_DIR = BASE_DIR / 'ml_models'
    MODEL_PATH = MODEL_DIR / 'isolation_forest.joblib'
    DATASET_DIR = BASE_DIR / 'dataset'
    RAW_DATASET_PATH = DATASET_DIR / 'raw' / 'synthetic_user_activity.csv'
    PROCESSED_DATASET_PATH = DATASET_DIR / 'processed' / 'features.csv'
    REPORTS_DIR = BASE_DIR / 'reports'
    
    # ML & Risk Thresholds
    ML_CONTAMINATION = float(os.environ.get('ML_CONTAMINATION', 0.08))
    ML_N_ESTIMATORS = int(os.environ.get('ML_N_ESTIMATORS', 150))
    ML_RANDOM_STATE = 42
    
    # Risk Score Categories (0-100)
    RISK_LOW_MAX = 29
    RISK_MEDIUM_MAX = 69
    RISK_HIGH_MIN = 70
    
    # Alert Generation Threshold (Default: 30 generates Medium or High alerts)
    ALERT_TRIGGER_THRESHOLD = 30
    
    # Session Configuration
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour
    
    # Admin Seed Credentials
    DEFAULT_ADMIN_USERNAME = os.environ.get('ADMIN_USER', 'admin')
    DEFAULT_ADMIN_PASSWORD = os.environ.get('ADMIN_PASS', 'Admin@CyberGuard2026!')
    DEFAULT_ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@sentinel.cyberguard.internal')
