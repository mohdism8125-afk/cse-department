"""
Training script for A14 - Cyber Attack Detection System
Generates model.pkl and all encoder .pkl files using synthetic data
matching the Kaggle "Cyber Security Attacks" dataset schema.
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pickle
import os

np.random.seed(42)
N = 5000  # synthetic samples

# Define categorical feature values
packet_types = ['Control', 'Data', 'Management']
traffic_types = ['HTTP', 'DNS', 'FTP', 'SSH', 'ICMP']
malware_indicators = ['IoC Detected', 'No Indicator', 'Suspicious Activity']
actions_taken = ['Blocked', 'Allowed', 'Logged', 'Dropped']
severity_levels = ['Low', 'Medium', 'High', 'Critical']
network_segments = ['Internal', 'External', 'DMZ', 'Guest']
firewall_logs = ['Allowed', 'Denied', 'Dropped', 'Reset']
ids_ips_alerts = ['Alert Triggered', 'No Alert', 'False Positive']
protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS']
attack_types = ['DDoS', 'Intrusion', 'Malware', 'Normal', 'Phishing', 'Ransomware']

# Generate synthetic data
data = {
    'Source_Port': np.random.randint(1024, 65535, N),
    'Destination_Port': np.random.choice([80, 443, 22, 53, 21, 8080, 3389, 25, 110, 143], N),
    'Packet_Length': np.random.randint(40, 1500, N).astype(float),
    'Anomaly_Scores': np.random.uniform(0, 1, N),
    'Packet_Type': np.random.choice(packet_types, N),
    'Traffic_Type': np.random.choice(traffic_types, N),
    'Malware_Indicators': np.random.choice(malware_indicators, N),
    'Action_Taken': np.random.choice(actions_taken, N),
    'Severity_Level': np.random.choice(severity_levels, N),
    'Network_Segment': np.random.choice(network_segments, N),
    'Firewall_Logs': np.random.choice(firewall_logs, N),
    'IDS_or_IPS_Alerts': np.random.choice(ids_ips_alerts, N),
    'Protocol': np.random.choice(protocols, N),
    'Year': np.random.choice([2023, 2024, 2025], N),
    'Month': np.random.randint(1, 13, N),
    'Day': np.random.randint(1, 29, N),
    'Hour': np.random.randint(0, 24, N),
    'DayOfWeek': np.random.randint(0, 7, N),
    'Attack_Type': np.random.choice(attack_types, N, p=[0.15, 0.15, 0.15, 0.30, 0.10, 0.15]),
}

# Make attack patterns more realistic
df = pd.DataFrame(data)
# DDoS: high anomaly, high packet count
mask_ddos = df['Attack_Type'] == 'DDoS'
df.loc[mask_ddos, 'Anomaly_Scores'] = np.random.uniform(0.6, 1.0, mask_ddos.sum())
df.loc[mask_ddos, 'Severity_Level'] = np.random.choice(['High', 'Critical'], mask_ddos.sum())
df.loc[mask_ddos, 'IDS_or_IPS_Alerts'] = 'Alert Triggered'

# Malware: IoC detected
mask_malware = df['Attack_Type'] == 'Malware'
df.loc[mask_malware, 'Malware_Indicators'] = 'IoC Detected'
df.loc[mask_malware, 'Anomaly_Scores'] = np.random.uniform(0.5, 0.9, mask_malware.sum())

# Normal: low anomaly
mask_normal = df['Attack_Type'] == 'Normal'
df.loc[mask_normal, 'Anomaly_Scores'] = np.random.uniform(0.0, 0.3, mask_normal.sum())
df.loc[mask_normal, 'Malware_Indicators'] = 'No Indicator'
df.loc[mask_normal, 'IDS_or_IPS_Alerts'] = 'No Alert'
df.loc[mask_normal, 'Severity_Level'] = 'Low'

# Intrusion: SSH/FTP, high severity
mask_intrusion = df['Attack_Type'] == 'Intrusion'
df.loc[mask_intrusion, 'Traffic_Type'] = np.random.choice(['SSH', 'FTP'], mask_intrusion.sum())
df.loc[mask_intrusion, 'Anomaly_Scores'] = np.random.uniform(0.4, 0.8, mask_intrusion.sum())

print(f"Dataset shape: {df.shape}")
print(f"Attack distribution:\n{df['Attack_Type'].value_counts()}\n")

# Create and fit encoders
encoders = {
    'Packet_Type': LabelEncoder(),
    'Traffic_Type': LabelEncoder(),
    'Malware_Indicators': LabelEncoder(),
    'Action_Taken': LabelEncoder(),
    'Severity_Level': LabelEncoder(),
    'Network_Segment': LabelEncoder(),
    'Firewall_Logs': LabelEncoder(),
    'IDS_or_IPS_Alerts': LabelEncoder(),
    'Protocol': LabelEncoder(),
    'Attack_Type': LabelEncoder(),
}

categorical_cols = list(encoders.keys())
for col in categorical_cols:
    df[col + '_encoded'] = encoders[col].fit_transform(df[col])

# Save encoders
encoder_filenames = {
    'Packet_Type': 'Packet_Type_encoder.pkl',
    'Traffic_Type': 'Traffic_Type_encoder.pkl',
    'Malware_Indicators': 'Malware_Indicators_encoder.pkl',
    'Action_Taken': 'Action_Taken_encoder.pkl',
    'Severity_Level': 'Severity_Level_encoder.pkl',
    'Network_Segment': 'Network_Segment_encoder.pkl',
    'Firewall_Logs': 'Firewall_Logs_encoder.pkl',
    'IDS_or_IPS_Alerts': 'IDS_or_IPS_Alerts_encoder.pkl',
    'Protocol': 'Protocol_encoder.pkl',
    'Attack_Type': 'Attack_Type_encoder.pkl',
}

for col, fname in encoder_filenames.items():
    with open(fname, 'wb') as f:
        pickle.dump(encoders[col], f)
    print(f"Saved {fname} - classes: {list(encoders[col].classes_)}")

# Prepare features (must match order in app.py)
feature_cols = [
    'Source_Port', 'Destination_Port', 'Protocol_encoded', 'Packet_Length',
    'Packet_Type_encoded', 'Traffic_Type_encoded', 'Malware_Indicators_encoded',
    'Anomaly_Scores', 'Action_Taken_encoded', 'Severity_Level_encoded',
    'Network_Segment_encoded', 'Firewall_Logs_encoded', 'IDS_or_IPS_Alerts_encoded',
    'Year', 'Month', 'Day', 'Hour', 'DayOfWeek'
]

X = df[feature_cols]
y = df['Attack_Type_encoded']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train Random Forest
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print(f"\n{classification_report(y_test, y_pred, target_names=encoders['Attack_Type'].classes_)}")

# Save model
with open('model.pkl', 'wb') as f:
    pickle.dump(model, f)
print("Saved model.pkl")
print("\nAll files generated successfully!")
