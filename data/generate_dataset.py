"""
Dataset Generator for Cyber Attack Prediction System
Generates benchmark network traffic data adhering to NSL-KDD and CICIDS2017 distribution patterns.
Includes Normal traffic and 4 major attack classes: DoS, Probe, R2L, and U2R.
"""

import numpy as np
import pandas as pd
import os

np.random.seed(42)

def generate_network_traffic_dataset(n_samples=6000):
    records = []
    
    # Class distribution: ~50% Normal, ~25% DoS, ~15% Probe, ~8% R2L, ~2% U2R
    classes = ['Normal'] * int(n_samples * 0.48) + \
              ['DoS'] * int(n_samples * 0.26) + \
              ['Probe'] * int(n_samples * 0.16) + \
              ['R2L'] * int(n_samples * 0.08) + \
              ['U2R'] * int(n_samples * 0.02)
    
    protocols = ['tcp', 'udp', 'icmp']
    services_normal = ['http', 'smtp', 'ftp', 'dns', 'other']
    services_dos = ['http', 'other', 'private', 'ecr_i']
    services_probe = ['http', 'private', 'other', 'smtp', 'finger']
    services_r2l = ['ftp', 'telnet', 'smtp', 'ssh']
    services_u2r = ['telnet', 'ftp', 'other']

    for label in classes:
        if label == 'Normal':
            proto = np.random.choice(protocols, p=[0.75, 0.20, 0.05])
            serv = np.random.choice(services_normal, p=[0.60, 0.15, 0.10, 0.10, 0.05])
            flag = np.random.choice(['SF', 'REJ', 'RSTO'], p=[0.95, 0.03, 0.02])
            duration = int(np.random.exponential(scale=3))
            src_bytes = int(np.random.normal(loc=450, scale=180))
            src_bytes = max(20, src_bytes)
            dst_bytes = int(np.random.normal(loc=3200, scale=1200))
            dst_bytes = max(50, dst_bytes)
            wrong_fragment = 0
            urgent = 0
            num_failed_logins = 0
            logged_in = 1 if serv in ['http', 'smtp', 'ftp', 'ssh'] else 0
            num_compromised = 0
            root_shell = 0
            su_attempted = 0
            num_root = 0
            count = np.random.randint(1, 20)
            srv_count = np.random.randint(1, 15)
            serror_rate = round(np.random.uniform(0.0, 0.05), 3)
            same_srv_rate = round(np.random.uniform(0.85, 1.0), 3)
            diff_srv_rate = round(np.random.uniform(0.0, 0.15), 3)
            dst_host_count = np.random.randint(10, 255)
            dst_host_srv_count = np.random.randint(15, 255)
            dst_host_same_srv_rate = round(np.random.uniform(0.80, 1.0), 3)
            dst_host_diff_srv_rate = round(np.random.uniform(0.0, 0.10), 3)
            dst_host_serror_rate = round(np.random.uniform(0.0, 0.05), 3)

        elif label == 'DoS':
            # SYN flood, Smurf, Neptune attacks: high packet count, high serror_rate, zero dst_bytes
            proto = np.random.choice(['tcp', 'icmp'], p=[0.85, 0.15])
            serv = np.random.choice(services_dos)
            flag = np.random.choice(['S0', 'REJ', 'SF'], p=[0.80, 0.15, 0.05])
            duration = 0
            src_bytes = int(np.random.exponential(scale=20))
            dst_bytes = 0
            wrong_fragment = np.random.choice([0, 1, 3], p=[0.90, 0.07, 0.03])
            urgent = 0
            num_failed_logins = 0
            logged_in = 0
            num_compromised = 0
            root_shell = 0
            su_attempted = 0
            num_root = 0
            count = np.random.randint(200, 512)
            srv_count = np.random.randint(100, 512)
            serror_rate = round(np.random.uniform(0.80, 1.0), 3)
            same_srv_rate = round(np.random.uniform(0.90, 1.0), 3)
            diff_srv_rate = round(np.random.uniform(0.0, 0.10), 3)
            dst_host_count = 255
            dst_host_srv_count = np.random.randint(1, 50)
            dst_host_same_srv_rate = round(np.random.uniform(0.01, 0.20), 3)
            dst_host_diff_srv_rate = round(np.random.uniform(0.50, 0.90), 3)
            dst_host_serror_rate = round(np.random.uniform(0.85, 1.0), 3)

        elif label == 'Probe':
            # Port scanning, ping sweep: many different services or hosts, low duration
            proto = np.random.choice(['tcp', 'icmp', 'udp'], p=[0.60, 0.30, 0.10])
            serv = np.random.choice(services_probe)
            flag = np.random.choice(['REJ', 'RSTO', 'SF', 'S0'], p=[0.50, 0.30, 0.10, 0.10])
            duration = np.random.randint(0, 4)
            src_bytes = int(np.random.uniform(0, 150))
            dst_bytes = 0
            wrong_fragment = 0
            urgent = 0
            num_failed_logins = 0
            logged_in = 0
            num_compromised = 0
            root_shell = 0
            su_attempted = 0
            num_root = 0
            count = np.random.randint(50, 300)
            srv_count = np.random.randint(1, 10)
            serror_rate = round(np.random.uniform(0.10, 0.40), 3)
            same_srv_rate = round(np.random.uniform(0.05, 0.30), 3)
            diff_srv_rate = round(np.random.uniform(0.60, 1.0), 3)
            dst_host_count = 255
            dst_host_srv_count = np.random.randint(1, 20)
            dst_host_same_srv_rate = round(np.random.uniform(0.01, 0.15), 3)
            dst_host_diff_srv_rate = round(np.random.uniform(0.70, 0.98), 3)
            dst_host_serror_rate = round(np.random.uniform(0.20, 0.60), 3)

        elif label == 'R2L':
            # Remote to Local (e.g. brute-force passwords, guessing credentials)
            proto = 'tcp'
            serv = np.random.choice(services_r2l)
            flag = np.random.choice(['SF', 'REJ'], p=[0.80, 0.20])
            duration = int(np.random.normal(loc=15, scale=8))
            duration = max(1, duration)
            src_bytes = int(np.random.uniform(150, 900))
            dst_bytes = int(np.random.uniform(200, 2500))
            wrong_fragment = 0
            urgent = 0
            num_failed_logins = np.random.choice([1, 2, 3, 4, 5], p=[0.30, 0.25, 0.20, 0.15, 0.10])
            logged_in = np.random.choice([0, 1], p=[0.75, 0.25])
            num_compromised = np.random.choice([0, 1], p=[0.85, 0.15])
            root_shell = 0
            su_attempted = 0
            num_root = 0
            count = np.random.randint(1, 15)
            srv_count = np.random.randint(1, 10)
            serror_rate = 0.0
            same_srv_rate = round(np.random.uniform(0.70, 1.0), 3)
            diff_srv_rate = round(np.random.uniform(0.0, 0.15), 3)
            dst_host_count = np.random.randint(5, 100)
            dst_host_srv_count = np.random.randint(5, 80)
            dst_host_same_srv_rate = round(np.random.uniform(0.60, 0.95), 3)
            dst_host_diff_srv_rate = round(np.random.uniform(0.0, 0.20), 3)
            dst_host_serror_rate = 0.0

        elif label == 'U2R':
            # User to Root (buffer overflow, privilege escalation)
            proto = 'tcp'
            serv = np.random.choice(services_u2r)
            flag = 'SF'
            duration = int(np.random.normal(loc=40, scale=20))
            duration = max(5, duration)
            src_bytes = int(np.random.uniform(400, 3000))
            dst_bytes = int(np.random.uniform(1000, 6000))
            wrong_fragment = 0
            urgent = np.random.choice([0, 1], p=[0.80, 0.20])
            num_failed_logins = 0
            logged_in = 1
            num_compromised = np.random.choice([1, 2, 3, 5], p=[0.4, 0.3, 0.2, 0.1])
            root_shell = 1
            su_attempted = np.random.choice([1, 2], p=[0.7, 0.3])
            num_root = np.random.randint(1, 6)
            count = np.random.randint(1, 5)
            srv_count = np.random.randint(1, 5)
            serror_rate = 0.0
            same_srv_rate = 1.0
            diff_srv_rate = 0.0
            dst_host_count = np.random.randint(1, 30)
            dst_host_srv_count = np.random.randint(1, 30)
            dst_host_same_srv_rate = 1.0
            dst_host_diff_srv_rate = 0.0
            dst_host_serror_rate = 0.0

        records.append({
            'duration': duration,
            'protocol_type': proto,
            'service': serv,
            'flag': flag,
            'src_bytes': src_bytes,
            'dst_bytes': dst_bytes,
            'wrong_fragment': wrong_fragment,
            'urgent': urgent,
            'num_failed_logins': num_failed_logins,
            'logged_in': logged_in,
            'num_compromised': num_compromised,
            'root_shell': root_shell,
            'su_attempted': su_attempted,
            'num_root': num_root,
            'count': count,
            'srv_count': srv_count,
            'serror_rate': serror_rate,
            'same_srv_rate': same_srv_rate,
            'diff_srv_rate': diff_srv_rate,
            'dst_host_count': dst_host_count,
            'dst_host_srv_count': dst_host_srv_count,
            'dst_host_same_srv_rate': dst_host_same_srv_rate,
            'dst_host_diff_srv_rate': dst_host_diff_srv_rate,
            'dst_host_serror_rate': dst_host_serror_rate,
            'label': label
        })
    
    df = pd.DataFrame(records)
    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df

if __name__ == '__main__':
    data_dir = os.path.dirname(os.path.abspath(__file__))
    df = generate_network_traffic_dataset(n_samples=7500)
    
    full_path = os.path.join(data_dir, 'cyber_attacks_dataset.csv')
    df.to_csv(full_path, index=False)
    print(f"Generated complete dataset at: {full_path} ({len(df)} rows)")
    print("Class Distribution:")
    print(df['label'].value_counts())
    
    # Also save a sample CSV for batch uploading in the UI
    sample_path = os.path.join(data_dir, 'sample_network_traffic.csv')
    sample_df = df.sample(n=100, random_state=101).reset_index(drop=True)
    sample_df.to_csv(sample_path, index=False)
    print(f"Generated sample batch test CSV at: {sample_path} (100 rows)")
