"""
Model Training & Evaluation Pipeline
Trains Random Forest and Support Vector Machine (SVM) on network intrusion dataset.
Evaluates and benchmarks both models, persisting weights and performance metrics.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

from preprocessing import prepare_data, ALL_FEATURE_ORDER, LABEL_TO_INT, INT_TO_LABEL

def train_and_evaluate():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_path = os.path.join(base_dir, 'data', 'cyber_attacks_dataset.csv')
    models_dir = os.path.join(base_dir, 'models')
    os.makedirs(models_dir, exist_ok=True)

    print(f"Loading dataset from: {data_path}")
    df = pd.read_csv(data_path)

    # Preprocessing
    X, y, scaler = prepare_data(df, fit_scaler=True)
    
    # Train / Test Split (80 / 20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"Training set: {X_train.shape[0]} samples | Testing set: {X_test.shape[0]} samples")

    # 1. Random Forest Classifier
    print("\n--- Training Random Forest Classifier ---")
    rf = RandomForestClassifier(n_estimators=120, max_depth=16, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    rf_pred = rf.predict(X_test)
    
    rf_acc = accuracy_score(y_test, rf_pred)
    rf_prec = precision_score(y_test, rf_pred, average='weighted', zero_division=0)
    rf_rec = recall_score(y_test, rf_pred, average='weighted', zero_division=0)
    rf_f1 = f1_score(y_test, rf_pred, average='weighted', zero_division=0)
    rf_cm = confusion_matrix(y_test, rf_pred).tolist()
    
    # Feature importances from Random Forest
    importances = rf.feature_importances_
    feat_imp = [
        {"feature": feat, "importance": round(float(imp), 4)}
        for feat, imp in sorted(zip(ALL_FEATURE_ORDER, importances), key=lambda x: x[1], reverse=True)
    ]

    print(f"Random Forest Accuracy: {rf_acc:.4f} | F1-Score: {rf_f1:.4f}")

    # 2. Support Vector Machine (SVM)
    print("\n--- Training Support Vector Machine (SVM) ---")
    svm = SVC(kernel='rbf', C=2.0, probability=True, random_state=42)
    svm.fit(X_train, y_train)
    svm_pred = svm.predict(X_test)
    
    svm_acc = accuracy_score(y_test, svm_pred)
    svm_prec = precision_score(y_test, svm_pred, average='weighted', zero_division=0)
    svm_rec = recall_score(y_test, svm_pred, average='weighted', zero_division=0)
    svm_f1 = f1_score(y_test, svm_pred, average='weighted', zero_division=0)
    svm_cm = confusion_matrix(y_test, svm_pred).tolist()
    print(f"SVM Accuracy: {svm_acc:.4f} | F1-Score: {svm_f1:.4f}")

    # Save artifacts
    print("\nSaving trained models and metrics...")
    joblib.dump(rf, os.path.join(models_dir, 'random_forest_model.pkl'))
    joblib.dump(svm, os.path.join(models_dir, 'svm_model.pkl'))
    joblib.dump(scaler, os.path.join(models_dir, 'scaler.pkl'))
    
    metrics = {
        "classes": [INT_TO_LABEL[i] for i in range(len(INT_TO_LABEL))],
        "features": ALL_FEATURE_ORDER,
        "feature_importances": feat_imp,
        "random_forest": {
            "name": "Random Forest",
            "accuracy": round(float(rf_acc), 4),
            "precision": round(float(rf_prec), 4),
            "recall": round(float(rf_rec), 4),
            "f1_score": round(float(rf_f1), 4),
            "confusion_matrix": rf_cm
        },
        "svm": {
            "name": "Support Vector Machine (SVM)",
            "accuracy": round(float(svm_acc), 4),
            "precision": round(float(svm_prec), 4),
            "recall": round(float(svm_rec), 4),
            "f1_score": round(float(svm_f1), 4),
            "confusion_matrix": svm_cm
        }
    }
    
    with open(os.path.join(models_dir, 'metrics.json'), 'w') as f:
        json.dump(metrics, f, indent=2)

    print(f"Models successfully saved to {models_dir}")
    return metrics

if __name__ == '__main__':
    train_and_evaluate()
