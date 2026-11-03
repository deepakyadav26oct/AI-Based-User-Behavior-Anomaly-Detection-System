import pytest
import numpy as np
import pandas as pd
from models.ml_model import BehaviorAnomalyDetector, FEATURE_COLUMNS
from modules.anomaly_detector import AnomalyDetectorService

@pytest.fixture
def trained_detector():
    # Train a fast detector on synthetic mock data
    np.random.seed(42)
    n_samples = 200
    
    normal_data = {
        'login_hour': np.random.randint(9, 18, n_samples),
        'day_of_week': np.random.randint(0, 5, n_samples),
        'failed_login_count': np.zeros(n_samples),
        'is_new_ip': np.zeros(n_samples),
        'is_new_device': np.zeros(n_samples),
        'session_duration': np.random.normal(1800, 300, n_samples),
        'access_frequency': np.random.randint(1, 4, n_samples),
        'resource_sensitivity': np.ones(n_samples),
        'is_unusual_hour': np.zeros(n_samples),
    }
    df = pd.DataFrame(normal_data)
    detector = BehaviorAnomalyDetector(contamination=0.08, n_estimators=50, random_state=42)
    detector.train(df)
    return detector

def test_feature_extraction():
    raw = {
        'login_hour': 14,
        'day_of_week': 2,
        'failed_login_count': 1,
        'is_new_ip': True,
        'is_new_device': False,
        'session_duration': 1200,
        'access_frequency': 3,
        'resource_sensitivity': 'HIGH',
        'is_unusual_hour': False
    }
    df = BehaviorAnomalyDetector.extract_features_from_dict(raw)
    assert list(df.columns) == FEATURE_COLUMNS
    assert df.iloc[0]['resource_sensitivity'] == 3  # HIGH maps to 3
    assert df.iloc[0]['is_new_ip'] == 1
    assert df.iloc[0]['is_new_device'] == 0

def test_detector_inference(trained_detector):
    # Test normal inlier
    normal_case = {
        'login_hour': 11,
        'day_of_week': 1,
        'failed_login_count': 0,
        'is_new_ip': False,
        'is_new_device': False,
        'session_duration': 1800,
        'access_frequency': 2,
        'resource_sensitivity': 1,
        'is_unusual_hour': False
    }
    res_normal = trained_detector.predict_single(normal_case)
    assert res_normal['is_ml_anomaly'] is False
    assert res_normal['ml_anomaly_score'] < 0.5
    assert res_normal['latency_ms'] >= 0.0

    # Test extreme outlier
    extreme_case = {
        'login_hour': 3,
        'day_of_week': 6,
        'failed_login_count': 10,
        'is_new_ip': True,
        'is_new_device': True,
        'session_duration': 20,
        'access_frequency': 40,
        'resource_sensitivity': 4,
        'is_unusual_hour': True
    }
    res_extreme = trained_detector.predict_single(extreme_case)
    assert res_extreme['is_ml_anomaly'] is True
    assert res_extreme['ml_anomaly_score'] > 0.6
    assert res_extreme['raw_decision_score'] < 0.0

def test_evaluation_metrics_calculation(trained_detector):
    # Create test set
    X_test = pd.DataFrame({
        'login_hour': [10, 11, 2],
        'day_of_week': [1, 2, 6],
        'failed_login_count': [0, 0, 8],
        'is_new_ip': [0, 0, 1],
        'is_new_device': [0, 0, 1],
        'session_duration': [1800, 2000, 30],
        'access_frequency': [2, 1, 35],
        'resource_sensitivity': [1, 1, 4],
        'is_unusual_hour': [0, 0, 1]
    })
    y_test = np.array([0, 0, 1])  # two normal, one anomalous

    metrics = trained_detector.evaluate(X_test, y_test)
    assert 'accuracy' in metrics
    assert 'precision' in metrics
    assert 'recall' in metrics
    assert 'f1_score' in metrics
    assert 'false_positive_rate' in metrics
    assert 'average_latency_ms' in metrics
    assert metrics['total_tested'] == 3

def test_one_class_svm_and_benchmark():
    from models.ml_model import OneClassSVMDetector, MultiModelBenchmark
    np.random.seed(42)
    n = 100
    df_train = pd.DataFrame({
        'login_hour': np.random.randint(9, 18, n),
        'day_of_week': np.random.randint(0, 5, n),
        'failed_login_count': np.zeros(n),
        'is_new_ip': np.zeros(n),
        'is_new_device': np.zeros(n),
        'session_duration': np.random.normal(1800, 300, n),
        'access_frequency': np.random.randint(1, 4, n),
        'resource_sensitivity': np.ones(n),
        'is_unusual_hour': np.zeros(n),
    })
    svm = OneClassSVMDetector(nu=0.1)
    train_res = svm.train(df_train)
    assert svm.is_fitted is True
    assert train_res['total_samples'] == n

    # Predict single
    sample = {
        'login_hour': 12, 'day_of_week': 1, 'failed_login_count': 0,
        'is_new_ip': False, 'is_new_device': False, 'session_duration': 1800,
        'access_frequency': 2, 'resource_sensitivity': 1, 'is_unusual_hour': False
    }
    pred = svm.predict_single(sample)
    assert 'is_ml_anomaly' in pred
    assert 'ml_anomaly_score' in pred
    assert 'latency_ms' in pred

    # Benchmark test
    df_test = df_train.iloc[:20].copy()
    y_test = np.zeros(20)
    bench = MultiModelBenchmark.run_benchmark(df_train, np.zeros(n), df_test, y_test)
    assert 'isolation_forest' in bench
    assert 'one_class_svm' in bench
    assert 'agreement_rate' in bench
    assert bench['agreement_rate'] >= 0.0
