"""
Inference & Prediction Service
Loads persisted models and runs single or batch predictions with risk scoring
and incident response mitigation recommendations.
"""

import os
import json
import joblib
import pandas as pd
import numpy as np

from preprocessing import prepare_data, encode_features, INT_TO_LABEL
from mitigations import get_mitigation_plan

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, 'models')

class CyberThreatPredictor:
    def __init__(self):
        self.rf_model = None
        self.svm_model = None
        self.scaler = None
        self.metrics = None
        self._load_artifacts()

    def _load_artifacts(self):
        rf_path = os.path.join(MODELS_DIR, 'random_forest_model.pkl')
        svm_path = os.path.join(MODELS_DIR, 'svm_model.pkl')
        scaler_path = os.path.join(MODELS_DIR, 'scaler.pkl')
        metrics_path = os.path.join(MODELS_DIR, 'metrics.json')

        if os.path.exists(rf_path):
            self.rf_model = joblib.load(rf_path)
        if os.path.exists(svm_path):
            self.svm_model = joblib.load(svm_path)
        if os.path.exists(scaler_path):
            self.scaler = joblib.load(scaler_path)
        if os.path.exists(metrics_path):
            with open(metrics_path, 'r') as f:
                self.metrics = json.load(f)

    def predict_single(self, packet_data: dict, model_type: str = 'random_forest') -> dict:
        """
        Runs prediction for a single network packet / event dictionary.
        Returns prediction details, risk score, probability breakdown, and mitigation advisory.
        """
        df = pd.DataFrame([packet_data])
        X_scaled, _, _ = prepare_data(df, scaler=self.scaler, fit_scaler=False)

        model = self.svm_model if model_type == 'svm' else self.rf_model
        if model is None:
            raise ValueError(f"Model {model_type} is not loaded.")

        pred_idx = model.predict(X_scaled)[0]
        predicted_label = INT_TO_LABEL.get(pred_idx, 'Normal')

        # Probabilities
        if hasattr(model, 'predict_proba'):
            probs = model.predict_proba(X_scaled)[0]
            confidence = float(np.max(probs))
            prob_breakdown = {
                INT_TO_LABEL.get(i, str(i)): round(float(p), 4)
                for i, p in enumerate(probs)
            }
        else:
            confidence = 0.95
            prob_breakdown = {predicted_label: 0.95}

        mitigation = get_mitigation_plan(predicted_label, confidence)

        return {
            'predicted_class': predicted_label,
            'confidence': confidence,
            'probability_breakdown': prob_breakdown,
            'mitigation': mitigation,
            'model_used': 'Support Vector Machine' if model_type == 'svm' else 'Random Forest'
        }

    def predict_batch(self, df: pd.DataFrame, model_type: str = 'random_forest') -> pd.DataFrame:
        """
        Runs batch prediction on a DataFrame of network connection logs.
        Appends 'predicted_attack', 'confidence', 'risk_severity', and 'risk_score'.
        """
        model = self.svm_model if model_type == 'svm' else self.rf_model
        if model is None:
            raise ValueError(f"Model {model_type} is not loaded.")

        X_scaled, _, _ = prepare_data(df, scaler=self.scaler, fit_scaler=False)
        preds = model.predict(X_scaled)
        
        result_df = df.copy()
        result_df['predicted_attack'] = [INT_TO_LABEL.get(p, 'Normal') for p in preds]

        if hasattr(model, 'predict_proba'):
            probs = model.predict_proba(X_scaled)
            result_df['confidence'] = np.max(probs, axis=1).round(3)
        else:
            result_df['confidence'] = 0.95

        # Add mitigation / severity metadata
        severities = []
        risk_scores = []
        for _, row in result_df.iterrows():
            plan = get_mitigation_plan(row['predicted_attack'], row['confidence'])
            severities.append(plan['severity'])
            risk_scores.append(plan['risk_score'])

        result_df['severity'] = severities
        result_df['risk_score'] = risk_scores
        return result_df
