"""
Preprocessing and Feature Engineering Pipeline
Handles categorical mapping, normalization, and feature consistency for the
Cyber Attack Prediction System.
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

CATEGORICAL_COLUMNS = ['protocol_type', 'service', 'flag']

# Canonical mappings to prevent out-of-vocabulary issues during inference
PROTOCOL_MAP = {'tcp': 0, 'udp': 1, 'icmp': 2}
SERVICE_MAP = {
    'http': 0, 'smtp': 1, 'ftp': 2, 'dns': 3, 'ssh': 4,
    'telnet': 5, 'finger': 6, 'private': 7, 'ecr_i': 8, 'other': 9
}
FLAG_MAP = {'SF': 0, 'S0': 1, 'REJ': 2, 'RSTO': 3}

NUMERIC_COLUMNS = [
    'duration', 'src_bytes', 'dst_bytes', 'wrong_fragment', 'urgent',
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'count', 'srv_count', 'serror_rate',
    'same_srv_rate', 'diff_srv_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_serror_rate'
]

ALL_FEATURE_ORDER = [
    'protocol_type', 'service', 'flag', 'duration', 'src_bytes', 'dst_bytes',
    'wrong_fragment', 'urgent', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'count',
    'srv_count', 'serror_rate', 'same_srv_rate', 'diff_srv_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_serror_rate'
]

LABEL_TO_INT = {'Normal': 0, 'DoS': 1, 'Probe': 2, 'R2L': 3, 'U2R': 4}
INT_TO_LABEL = {v: k for k, v in LABEL_TO_INT.items()}

def encode_features(df: pd.DataFrame) -> pd.DataFrame:
    """Encodes categorical fields into numeric values."""
    processed = df.copy()
    
    if 'protocol_type' in processed.columns:
        processed['protocol_type'] = processed['protocol_type'].map(
            lambda x: PROTOCOL_MAP.get(str(x).lower(), PROTOCOL_MAP['tcp'])
        )
    if 'service' in processed.columns:
        processed['service'] = processed['service'].map(
            lambda x: SERVICE_MAP.get(str(x).lower(), SERVICE_MAP['other'])
        )
    if 'flag' in processed.columns:
        processed['flag'] = processed['flag'].map(
            lambda x: FLAG_MAP.get(str(x).upper(), FLAG_MAP['SF'])
        )
    
    # Ensure all required features are present
    for col in ALL_FEATURE_ORDER:
        if col not in processed.columns:
            processed[col] = 0
            
    return processed[ALL_FEATURE_ORDER]

def prepare_data(df: pd.DataFrame, scaler: StandardScaler = None, fit_scaler: bool = False):
    """
    Prepares input DataFrame for model consumption.
    Returns: X_scaled (np.ndarray), y (optional np.ndarray), scaler (StandardScaler)
    """
    X_encoded = encode_features(df)
    
    if fit_scaler or scaler is None:
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_encoded)
    else:
        X_scaled = scaler.transform(X_encoded)
        
    y = None
    if 'label' in df.columns:
        y = df['label'].map(LABEL_TO_INT).values
        
    return X_scaled, y, scaler
