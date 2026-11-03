import os
import sys
import json
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config import Config
from models.ml_model import BehaviorAnomalyDetector, OneClassSVMDetector, MultiModelBenchmark, FEATURE_COLUMNS
from scripts.generate_dataset import generate_synthetic_data

def train_and_evaluate_model():
    processed_path = Config.PROCESSED_DATASET_PATH
    if not os.path.exists(processed_path):
        print("[Train Script] Features dataset not found. Generating synthetic dataset first...")
        generate_synthetic_data()

    print(f"[Train Script] Loading features from {processed_path}...")
    df = pd.read_csv(processed_path)

    X = df[FEATURE_COLUMNS].copy()
    y = df['is_anomaly'].values  # 1 for anomaly, 0 for normal

    print(f"[Train Script] Total Dataset Samples: {len(df)}")
    print(f"[Train Script] Class Distribution -> Normal: {int(sum(y==0))}, Anomalous: {int(sum(y==1))}")

    # Stratified Train/Test split (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=Config.ML_RANDOM_STATE, stratify=y
    )

    print(f"[Train Script] Training Set: {len(X_train)} samples, Test Set: {len(X_test)} samples")

    # 1. Initialize and Fit Isolation Forest
    print("[Train Script] Fitting Isolation Forest model with StandardScaler...")
    if_detector = BehaviorAnomalyDetector(
        contamination=Config.ML_CONTAMINATION,
        n_estimators=Config.ML_N_ESTIMATORS,
        random_state=Config.ML_RANDOM_STATE
    )
    train_stats = if_detector.train(X_train)
    eval_metrics_if = if_detector.evaluate(X_test, y_test)

    # 2. Initialize and Fit One-Class SVM
    print("[Train Script] Fitting One-Class SVM model (RBF Kernel)...")
    svm_detector = OneClassSVMDetector(
        nu=Config.ML_CONTAMINATION,
        kernel='rbf',
        gamma='scale'
    )
    svm_train_stats = svm_detector.train(X_train)
    eval_metrics_svm = svm_detector.evaluate(X_test, y_test)

    # 3. Comparative Benchmarking & Agreement
    benchmark_data = MultiModelBenchmark.run_benchmark(X_train, y_train, X_test, y_test)

    print("\n" + "=" * 65)
    print("      MULTI-MODEL MACHINE LEARNING BENCHMARK REPORT")
    print("=" * 65)
    print(f"  Holdout Test Partition : {eval_metrics_if['total_tested']} samples")
    print(f"  Isolation Forest Acc   : {eval_metrics_if['accuracy']*100:.2f}% | F1: {eval_metrics_if['f1_score']:.4f} | Latency: {eval_metrics_if['average_latency_ms']:.3f} ms")
    print(f"  One-Class SVM Acc      : {eval_metrics_svm['accuracy']*100:.2f}% | F1: {eval_metrics_svm['f1_score']:.4f} | Latency: {eval_metrics_svm['average_latency_ms']:.3f} ms")
    print(f"  Ensemble Agreement     : {benchmark_data['agreement_rate']:.2f}%")
    print("=" * 65 + "\n")

    # Persist model bundles & comparison json
    output_path = Config.MODEL_PATH
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if_detector.save(str(output_path))
    
    svm_path = output_path.parent / 'one_class_svm.joblib'
    svm_detector.save(str(svm_path))

    comparison_path = output_path.parent / 'model_comparison.json'
    with open(comparison_path, 'w') as f:
        json.dump(benchmark_data, f, indent=2)

    print(f"[Train Script] Serialized Isolation Forest to: {output_path}")
    print(f"[Train Script] Serialized One-Class SVM to: {svm_path}")
    print(f"[Train Script] Serialized Comparative Metrics to: {comparison_path}")

    return if_detector, eval_metrics_if

if __name__ == '__main__':
    train_and_evaluate_model()
