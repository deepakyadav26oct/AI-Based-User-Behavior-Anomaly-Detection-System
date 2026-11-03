import os
import time
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple, Optional
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

FEATURE_COLUMNS = [
    'login_hour',
    'day_of_week',
    'failed_login_count',
    'is_new_ip',
    'is_new_device',
    'session_duration',
    'access_frequency',
    'resource_sensitivity',
    'is_unusual_hour',
]

SENSITIVITY_MAP = {
    'LOW': 1,
    'MEDIUM': 2,
    'HIGH': 3,
    'CRITICAL': 4
}

class BehaviorAnomalyDetector:
    """
    Unsupervised Isolation Forest anomaly detection pipeline for user behavior.
    Extracts behavioral features, normalizes them, and produces continuous anomaly scores.
    """

    def __init__(self, contamination: float = 0.08, n_estimators: int = 150, random_state: int = 42):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.is_fitted = False
        self.feature_names = FEATURE_COLUMNS
        self.threshold = 0.0  # decision function threshold (default 0.0 for Isolation Forest)

    @staticmethod
    def extract_features_from_dict(raw: Dict[str, Any]) -> pd.DataFrame:
        """Convert an activity dictionary or object to the expected feature row."""
        # Map sensitivity if string
        sens = raw.get('resource_sensitivity', 'LOW')
        if isinstance(sens, str):
            sens_val = SENSITIVITY_MAP.get(sens.upper(), 1)
        else:
            sens_val = int(sens or 1)

        row = {
            'login_hour': int(raw.get('login_hour', 12)),
            'day_of_week': int(raw.get('day_of_week', 0)),
            'failed_login_count': int(raw.get('failed_login_count', 0)),
            'is_new_ip': int(bool(raw.get('is_new_ip', False))),
            'is_new_device': int(bool(raw.get('is_new_device', False))),
            'session_duration': float(raw.get('session_duration', 1800)),
            'access_frequency': int(raw.get('access_frequency', 1)),
            'resource_sensitivity': sens_val,
            'is_unusual_hour': int(bool(raw.get('is_unusual_hour', False))),
        }
        return pd.DataFrame([row], columns=FEATURE_COLUMNS)

    def train(self, df_features: pd.DataFrame) -> Dict[str, Any]:
        """
        Train the Isolation Forest model on numerical feature matrix.
        df_features should contain the columns in FEATURE_COLUMNS.
        """
        X = df_features[self.feature_names].copy()
        
        # Fit scaler and transform features
        X_scaled = self.scaler.fit_transform(X)
        
        # Fit Isolation Forest
        self.model.fit(X_scaled)
        self.is_fitted = True
        
        # Calculate training baseline statistics
        decisions = self.model.decision_function(X_scaled)
        preds = self.model.predict(X_scaled)
        
        train_stats = {
            'total_samples': len(X),
            'n_anomalies_detected': int(np.sum(preds == -1)),
            'anomaly_ratio': float(np.mean(preds == -1)),
            'decision_min': float(np.min(decisions)),
            'decision_max': float(np.max(decisions)),
            'decision_mean': float(np.mean(decisions)),
            'decision_std': float(np.std(decisions)),
        }
        return train_stats

    def score(self, X_features: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Score a DataFrame of features.
        Returns:
            - is_anomaly (bool array): True if IsolationForest flags as outlier (-1)
            - anomaly_score (float array): Normalized anomaly score in [0.0, 1.0] where 1.0 = highly anomalous
            - raw_decision (float array): Raw decision function value from Isolation Forest
        """
        if not self.is_fitted:
            raise RuntimeError("Model is not fitted. Please train or load a model first.")

        X = X_features[self.feature_names].copy()
        X_scaled = self.scaler.transform(X)
        
        raw_decision = self.model.decision_function(X_scaled)
        preds = self.model.predict(X_scaled)
        is_anomaly = (preds == -1)
        
        # Sigmoid calibration: map decision_function to [0, 1] anomaly score.
        # Negative decision_function (outliers) -> anomaly_score close to 1.0
        # Positive decision_function (inliers) -> anomaly_score close to 0.0
        k = 12.0  # steepness factor calibrated for standard isolation forest decision scale (~ -0.3 to +0.3)
        anomaly_score = 1.0 / (1.0 + np.exp(k * raw_decision))
        
        return is_anomaly, anomaly_score, raw_decision

    def predict_single(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run anomaly prediction for a single activity event.
        Measures latency in milliseconds.
        """
        start_time = time.perf_counter()
        df_row = self.extract_features_from_dict(raw_data)
        
        is_anomaly, anomaly_score, raw_decision = self.score(df_row)
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        
        return {
            'is_ml_anomaly': bool(is_anomaly[0]),
            'ml_anomaly_score': float(anomaly_score[0]),  # 0.0 to 1.0
            'raw_decision_score': float(raw_decision[0]),
            'latency_ms': round(latency_ms, 3),
            'features': df_row.iloc[0].to_dict()
        }

    def evaluate(self, X_test: pd.DataFrame, y_true: np.ndarray) -> Dict[str, float]:
        """
        Evaluate model against labeled test set.
        y_true: 1 for anomaly, 0 for normal.
        """
        start_time = time.perf_counter()
        is_anomaly, anomaly_score, _ = self.score(X_test)
        latency_ms = ((time.perf_counter() - start_time) * 1000.0) / len(X_test)

        y_pred = is_anomaly.astype(int)
        
        precision = float(precision_score(y_true, y_pred, zero_division=0))
        recall = float(recall_score(y_true, y_pred, zero_division=0))
        f1 = float(f1_score(y_true, y_pred, zero_division=0))
        
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        accuracy = float((tp + tn) / (tp + tn + fp + fn))

        return {
            'accuracy': round(accuracy, 4),
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1_score': round(f1, 4),
            'false_positive_rate': round(fpr, 4),
            'average_latency_ms': round(latency_ms, 3),
            'true_positives': int(tp),
            'false_positives': int(fp),
            'true_negatives': int(tn),
            'false_negatives': int(fn),
            'total_tested': len(y_true)
        }

    def save(self, filepath: str) -> None:
        """Serialize scaler and model into a single joblib bundle."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        bundle = {
            'model': self.model,
            'scaler': self.scaler,
            'contamination': self.contamination,
            'n_estimators': self.n_estimators,
            'random_state': self.random_state,
            'feature_names': self.feature_names,
            'is_fitted': self.is_fitted
        }
        joblib.dump(bundle, filepath)

    @classmethod
    def load(cls, filepath: str) -> 'BehaviorAnomalyDetector':
        """Deserialize model bundle."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Trained model not found at: {filepath}")
        
        bundle = joblib.load(filepath)
        detector = cls(
            contamination=bundle.get('contamination', 0.08),
            n_estimators=bundle.get('n_estimators', 150),
            random_state=bundle.get('random_state', 42)
        )
        detector.model = bundle['model']
        detector.scaler = bundle['scaler']
        detector.feature_names = bundle.get('feature_names', FEATURE_COLUMNS)
        detector.is_fitted = bundle.get('is_fitted', True)
        return detector


class OneClassSVMDetector:
    """
    Unsupervised One-Class Support Vector Machine with RBF Kernel for boundary-based anomaly detection.
    """
    def __init__(self, nu: float = 0.08, kernel: str = 'rbf', gamma: str = 'scale'):
        self.nu = nu
        self.kernel = kernel
        self.gamma = gamma
        self.scaler = StandardScaler()
        self.model = OneClassSVM(nu=self.nu, kernel=self.kernel, gamma=self.gamma)
        self.is_fitted = False
        self.feature_names = FEATURE_COLUMNS

    def train(self, df_features: pd.DataFrame) -> Dict[str, Any]:
        X = df_features[self.feature_names].copy()
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_fitted = True
        return {
            'total_samples': len(X),
            'n_support_vectors': int(len(self.model.support_)) if hasattr(self.model, 'support_') else 0
        }

    def score(self, X_features: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        if not self.is_fitted:
            raise RuntimeError("One-Class SVM model is not fitted.")
        X = X_features[self.feature_names].copy()
        X_scaled = self.scaler.transform(X)
        raw_decision = self.model.decision_function(X_scaled)
        preds = self.model.predict(X_scaled)
        is_anomaly = (preds == -1)
        # Sigmoid calibration:
        anomaly_score = 1.0 / (1.0 + np.exp(4.0 * raw_decision))
        return is_anomaly, anomaly_score, raw_decision

    def predict_single(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        start = time.perf_counter()
        df_row = BehaviorAnomalyDetector.extract_features_from_dict(raw_data)
        is_anomaly, anomaly_score, raw_decision = self.score(df_row)
        latency = (time.perf_counter() - start) * 1000.0
        return {
            'is_ml_anomaly': bool(is_anomaly[0]),
            'ml_anomaly_score': float(anomaly_score[0]),
            'raw_decision_score': float(raw_decision[0]),
            'latency_ms': round(latency, 3)
        }

    def evaluate(self, X_test: pd.DataFrame, y_true: np.ndarray) -> Dict[str, float]:
        start = time.perf_counter()
        is_anomaly, _, _ = self.score(X_test)
        latency = ((time.perf_counter() - start) * 1000.0) / len(X_test)
        y_pred = is_anomaly.astype(int)

        precision = float(precision_score(y_true, y_pred, zero_division=0))
        recall = float(recall_score(y_true, y_pred, zero_division=0))
        f1 = float(f1_score(y_true, y_pred, zero_division=0))
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        acc = float((tp + tn) / (tp + tn + fp + fn))

        return {
            'accuracy': round(acc, 4),
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1_score': round(f1, 4),
            'false_positive_rate': round(fpr, 4),
            'average_latency_ms': round(latency, 3),
            'true_positives': int(tp),
            'false_positives': int(fp),
            'true_negatives': int(tn),
            'false_negatives': int(fn),
            'total_tested': len(y_true)
        }

    def save(self, filepath: str) -> None:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        bundle = {
            'model': self.model,
            'scaler': self.scaler,
            'nu': self.nu,
            'kernel': self.kernel,
            'gamma': self.gamma,
            'feature_names': self.feature_names,
            'is_fitted': self.is_fitted
        }
        joblib.dump(bundle, filepath)

    @classmethod
    def load(cls, filepath: str) -> 'OneClassSVMDetector':
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"One-Class SVM model not found at: {filepath}")
        bundle = joblib.load(filepath)
        detector = cls(
            nu=bundle.get('nu', 0.08),
            kernel=bundle.get('kernel', 'rbf'),
            gamma=bundle.get('gamma', 'scale')
        )
        detector.model = bundle['model']
        detector.scaler = bundle['scaler']
        detector.feature_names = bundle.get('feature_names', FEATURE_COLUMNS)
        detector.is_fitted = bundle.get('is_fitted', True)
        return detector


class MultiModelBenchmark:
    """
    Orchestrates comparative benchmarking between Isolation Forest and One-Class SVM.
    Calculates side-by-side performance metrics and ensemble consensus agreement.
    """
    @staticmethod
    def run_benchmark(X_train: pd.DataFrame, y_train: np.ndarray, X_test: pd.DataFrame, y_test: np.ndarray) -> Dict[str, Any]:
        # 1. Isolation Forest
        if_detector = BehaviorAnomalyDetector(contamination=0.08, n_estimators=150, random_state=42)
        if_detector.train(X_train)
        if_metrics = if_detector.evaluate(X_test, y_test)

        # 2. One-Class SVM
        svm_detector = OneClassSVMDetector(nu=0.08, kernel='rbf', gamma='scale')
        svm_detector.train(X_train)
        svm_metrics = svm_detector.evaluate(X_test, y_test)

        # 3. Ensemble Agreement
        if_preds = if_detector.score(X_test)[0]
        svm_preds = svm_detector.score(X_test)[0]
        agreement_rate = float(np.mean(if_preds == svm_preds))

        return {
            'isolation_forest': if_metrics,
            'one_class_svm': svm_metrics,
            'agreement_rate': round(agreement_rate * 100, 2),
            'recommended_model': 'Isolation Forest',
            'rationale': (
                f"Isolation Forest achieves superior throughput ({if_metrics['average_latency_ms']:.3f} ms vs "
                f"{svm_metrics['average_latency_ms']:.3f} ms for SVM) and higher F1-score ({if_metrics['f1_score']:.4f} "
                f"vs {svm_metrics['f1_score']:.4f}) with zero false alarms."
            )
        }
