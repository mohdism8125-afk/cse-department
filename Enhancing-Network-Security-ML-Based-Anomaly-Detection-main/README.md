# Enhancing Network Security: ML-Based Anomaly Detection

A Flask web application that uses a Random Forest machine learning model to detect cyber attacks from network traffic parameters. Analyzes 18 features including packet characteristics, anomaly scores, protocol types, and security indicators to classify traffic into 6 categories.

## Features

- **ML-Based Detection** — Random Forest classifier trained on network traffic data
- **6 Attack Types** — Detects DDoS, Intrusion, Malware, Phishing, Ransomware, and Normal traffic
- **18 Network Features** — Source/destination ports, protocol, packet type, anomaly score, severity, and more
- **Security Dashboard** — Overview with stats, attack distribution, and recent detections
- **Interactive Analytics** — Chart.js visualizations (doughnut charts, anomaly score trends)
- **Detection History** — Full log of all past predictions with filters
- **Mitigation Strategies** — Detailed countermeasures for each attack type
- **User Authentication** — Login/register with password hashing

## Attack Types

| Attack | Key Indicators |
|--------|---------------|
| **DDoS** | Anomaly > 0.7, Severity = Critical/High, IDS = Alert Triggered |
| **Intrusion** | Traffic = SSH/FTP, Anomaly > 0.4, Severity = High |
| **Malware** | Malware = IoC Detected, Anomaly > 0.5 |
| **Phishing** | Suspicious activity patterns, varied anomaly scores |
| **Ransomware** | High anomaly, suspicious indicators, elevated severity |
| **Normal** | Anomaly < 0.3, Severity = Low, No alerts, No IoC |

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

## Installation (Windows)

1. **Clone the repository:**
```bash
git clone <repository-url>
cd code
```

2. **Create a virtual environment (recommended):**
```bash
python -m venv venv
venv\Scripts\activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **(Optional) Retrain the model:**
```bash
python train_model.py
```
This generates `model.pkl` and all `*_encoder.pkl` files from scratch using synthetic data.

5. **Run the application:**
```bash
python app.py
```
Open http://localhost:5017 in your browser.

6. **Login:**
- Username: `admin`
- Password: `admin123`

## Docker Deployment

```bash
docker build -t network-security .
docker run -p 5017:5017 network-security
```

## Project Structure

```
code/
├── app.py                          # Flask app with all routes
├── train_model.py                  # Model training script (generates model + encoders)
├── model.pkl                       # Trained Random Forest classifier
├── *_encoder.pkl                   # 10 LabelEncoder files for categorical features
├── templates/
│   ├── base.html                   # Bootstrap 5 dark theme (cyber cyan #00d4ff)
│   ├── login.html                  # Login page
│   ├── register.html               # Registration page
│   ├── home.html                   # Security dashboard with stats
│   ├── predict.html                # Network traffic analysis form
│   ├── history.html                # Detection history log
│   ├── analytics.html              # Chart.js visualizations
│   ├── suggestions.html            # Attack mitigation strategies
│   └── about.html                  # Project information
├── Dockerfile
├── requirements.txt
├── .gitignore / .dockerignore
├── README.md
└── PROJECT_EXPLANATION.md
```

## Test Cases

1. Login as admin/admin123 → dashboard with stat cards
2. Click "New Detection" → prediction form with 18 fields
3. Enter DDoS indicators (Anomaly=0.85, Severity=Critical, IDS=Alert Triggered) → "DDoS" detected
4. Enter Normal indicators (Anomaly=0.1, Severity=Low, No Alert, No Indicator) → "Normal" detected
5. Enter Malware indicators (Malware=IoC Detected, Anomaly=0.75) → "Malware" detected
6. Enter Intrusion indicators (Traffic=SSH, Anomaly=0.65, Severity=High) → "Intrusion" detected
7. After 4 detections, check History → all 4 entries with timestamps and severity badges
8. Check Analytics → doughnut charts (attack distribution, severity) and anomaly score line chart
9. Check Mitigations → 5 attack types with detailed countermeasures
10. Register new user → redirect to login with success
11. Duplicate username → error message
12. Access /predict without login → redirect to login
13. Dashboard shows correct attack/normal counts
14. About page shows attack types table, tech stack, feature list

## Technology Stack

- **Backend:** Python, Flask
- **ML Model:** Random Forest (scikit-learn)
- **Frontend:** Bootstrap 5, Bootstrap Icons, Chart.js
- **Database:** SQLite
- **Security:** Werkzeug password hashing
- **Encoding:** LabelEncoder (10 categorical features)
