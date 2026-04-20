from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import pickle
import numpy as np
import sqlite3
import datetime
import os

app = Flask(__name__)
app.secret_key = 'network-security-anomaly-detection-2025'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'database.db')

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            source_port INTEGER,
            dest_port INTEGER,
            protocol TEXT,
            packet_length REAL,
            packet_type TEXT,
            traffic_type TEXT,
            malware_indicators TEXT,
            anomaly_score REAL,
            action_taken TEXT,
            severity_level TEXT,
            network_segment TEXT,
            firewall_logs TEXT,
            ids_ips_alerts TEXT,
            attack_type TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ''')
    # Seed admin user
    existing = conn.execute('SELECT id FROM users WHERE username = ?', ('admin',)).fetchone()
    if not existing:
        conn.execute('INSERT INTO users (username, password, name) VALUES (?, ?, ?)',
                     ('admin', generate_password_hash('admin123'), 'Administrator'))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Auth decorator
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Load ML model and encoders
# ---------------------------------------------------------------------------

model = pickle.load(open(os.path.join(BASE_DIR, 'model.pkl'), 'rb'))

encoder_names = [
    'Packet_Type', 'Traffic_Type', 'Malware_Indicators', 'Action_Taken',
    'Severity_Level', 'Network_Segment', 'Firewall_Logs', 'IDS_or_IPS_Alerts',
    'Protocol', 'Attack_Type'
]

encoders = {}
for name in encoder_names:
    encoders[name] = pickle.load(open(os.path.join(BASE_DIR, f'{name}_encoder.pkl'), 'rb'))

# Reverse map for prediction labels
attack_map = {v: k for k, v in enumerate(encoders['Attack_Type'].classes_)}
reverse_map = {v: k for k, v in attack_map.items()}


# ---------------------------------------------------------------------------
# Routes — Auth
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        name = request.form.get('name', username).strip()
        if not username or not password:
            flash('Username and password are required.', 'danger')
        else:
            conn = get_db()
            try:
                conn.execute('INSERT INTO users (username, password, name) VALUES (?, ?, ?)',
                             (username, generate_password_hash(password), name))
                conn.commit()
                flash('Registration successful! Please login.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username already exists.', 'danger')
            finally:
                conn.close()
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ---------------------------------------------------------------------------
# Routes — Dashboard
# ---------------------------------------------------------------------------

@app.route('/home')
@login_required
def home():
    conn = get_db()
    total = conn.execute('SELECT COUNT(*) FROM predictions WHERE user_id = ?',
                         (session['user_id'],)).fetchone()[0]
    attacks = conn.execute(
        "SELECT COUNT(*) FROM predictions WHERE user_id = ? AND attack_type != 'Normal'",
        (session['user_id'],)).fetchone()[0]
    normal = total - attacks
    recent = conn.execute(
        'SELECT * FROM predictions WHERE user_id = ? ORDER BY created_at DESC LIMIT 5',
        (session['user_id'],)).fetchall()

    # Attack type distribution
    dist = conn.execute(
        'SELECT attack_type, COUNT(*) as cnt FROM predictions WHERE user_id = ? GROUP BY attack_type',
        (session['user_id'],)).fetchall()
    conn.close()

    return render_template('home.html', total=total, attacks=attacks, normal=normal,
                           recent=recent, distribution=dist)


# ---------------------------------------------------------------------------
# Routes — Prediction
# ---------------------------------------------------------------------------

@app.route('/predict', methods=['GET', 'POST'])
@login_required
def predict():
    prediction_text = None

    if request.method == 'POST':
        try:
            # Encode categorical inputs
            packet_type = encoders['Packet_Type'].transform([request.form['Packet_Type']])[0]
            traffic_type = encoders['Traffic_Type'].transform([request.form['Traffic_Type']])[0]
            malware = encoders['Malware_Indicators'].transform([request.form['Malware_Indicators']])[0]
            action = encoders['Action_Taken'].transform([request.form['Action_Taken']])[0]
            severity = encoders['Severity_Level'].transform([request.form['Severity_Level']])[0]
            segment = encoders['Network_Segment'].transform([request.form['Network_Segment']])[0]
            firewall = encoders['Firewall_Logs'].transform([request.form['Firewall_Logs']])[0]
            ids_ips = encoders['IDS_or_IPS_Alerts'].transform([request.form['IDS_IPS_Alerts']])[0]
            protocol = encoders['Protocol'].transform([request.form['Protocol']])[0]

            # Numeric inputs
            source_port = int(request.form['Source_Port'])
            dest_port = int(request.form['Destination_Port'])
            packet_length = float(request.form['Packet_Length'])
            anomaly = float(request.form['Anomaly_Scores'])
            year = int(request.form['Year'])
            month = int(request.form['Month'])
            day = int(request.form['Day'])
            hour = int(request.form['Hour'])
            dow = int(request.form['DayOfWeek'])

            input_data = np.array([[source_port, dest_port, protocol, packet_length,
                                    packet_type, traffic_type, malware, anomaly,
                                    action, severity, segment, firewall, ids_ips,
                                    year, month, day, hour, dow]])

            prediction = model.predict(input_data)[0]
            result = reverse_map.get(prediction, 'Normal')

            # Save to database
            conn = get_db()
            conn.execute('''INSERT INTO predictions
                (user_id, source_port, dest_port, protocol, packet_length,
                 packet_type, traffic_type, malware_indicators, anomaly_score,
                 action_taken, severity_level, network_segment, firewall_logs,
                 ids_ips_alerts, attack_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (session['user_id'], source_port, dest_port,
                 request.form['Protocol'], packet_length,
                 request.form['Packet_Type'], request.form['Traffic_Type'],
                 request.form['Malware_Indicators'], anomaly,
                 request.form['Action_Taken'], request.form['Severity_Level'],
                 request.form['Network_Segment'], request.form['Firewall_Logs'],
                 request.form['IDS_IPS_Alerts'], result))
            conn.commit()
            conn.close()

            prediction_text = f'Predicted Attack Type: {result}'

        except Exception as e:
            prediction_text = f'Error: {str(e)}'

    return render_template('predict.html',
                           prediction_text=prediction_text,
                           packet_types=encoders['Packet_Type'].classes_,
                           traffic_types=encoders['Traffic_Type'].classes_,
                           malware_indicators=encoders['Malware_Indicators'].classes_,
                           actions=encoders['Action_Taken'].classes_,
                           severity_levels=encoders['Severity_Level'].classes_,
                           network_segments=encoders['Network_Segment'].classes_,
                           firewall_logs=encoders['Firewall_Logs'].classes_,
                           ids_ips_alerts=encoders['IDS_or_IPS_Alerts'].classes_,
                           protocols=encoders['Protocol'].classes_)


# ---------------------------------------------------------------------------
# Routes — History
# ---------------------------------------------------------------------------

@app.route('/history')
@login_required
def history():
    conn = get_db()
    predictions = conn.execute(
        'SELECT * FROM predictions WHERE user_id = ? ORDER BY created_at DESC',
        (session['user_id'],)).fetchall()
    conn.close()
    return render_template('history.html', predictions=predictions)


# ---------------------------------------------------------------------------
# Routes — Attack Suggestions
# ---------------------------------------------------------------------------

ATTACK_SUGGESTIONS = [
    {
        'attack': 'DDoS (Distributed Denial of Service)',
        'icon': 'globe2',
        'color': '#ef4444',
        'suggestions': [
            'Deploy a Web Application Firewall (WAF) to filter malicious traffic',
            'Use rate limiting and traffic throttling on API endpoints',
            'Enable DDoS protection services (e.g., Cloudflare, AWS Shield)',
            'Implement IP blacklisting for known malicious sources',
            'Set up traffic anomaly detection with automated alerts',
        ]
    },
    {
        'attack': 'Intrusion',
        'icon': 'door-open',
        'color': '#f97316',
        'suggestions': [
            'Enforce strong password policies and multi-factor authentication',
            'Regularly update and patch SSH, FTP, and other services',
            'Monitor login attempts and block after repeated failures (fail2ban)',
            'Segment internal networks to limit lateral movement',
            'Deploy Intrusion Detection/Prevention Systems (IDS/IPS)',
        ]
    },
    {
        'attack': 'Malware',
        'icon': 'bug',
        'color': '#a855f7',
        'suggestions': [
            'Keep antivirus and anti-malware software up to date',
            'Conduct regular full-system scans on all endpoints',
            'Block known malicious IPs and domains at the firewall level',
            'Implement application whitelisting to prevent unauthorized executables',
            'Train employees to recognize phishing emails and suspicious downloads',
        ]
    },
    {
        'attack': 'Phishing',
        'icon': 'envelope-exclamation',
        'color': '#eab308',
        'suggestions': [
            'Conduct regular security awareness training for all staff',
            'Enable multi-factor authentication (MFA) on all accounts',
            'Deploy email filtering with anti-phishing capabilities',
            'Verify sender identity before clicking links or downloading attachments',
            'Report suspicious emails to the security team immediately',
        ]
    },
    {
        'attack': 'Ransomware',
        'icon': 'lock',
        'color': '#dc2626',
        'suggestions': [
            'Maintain regular offline backups of critical data',
            'Disable unnecessary remote access services (RDP, SMB)',
            'Keep operating systems and software patched and up to date',
            'Implement network segmentation to contain the spread',
            'Never pay the ransom — contact law enforcement immediately',
        ]
    },
]


@app.route('/suggestions')
@login_required
def attack_suggestions():
    return render_template('suggestions.html', suggestions=ATTACK_SUGGESTIONS)


# ---------------------------------------------------------------------------
# Routes — Graph / Analytics
# ---------------------------------------------------------------------------

@app.route('/analytics')
@login_required
def analytics():
    conn = get_db()
    # Attack type distribution
    dist = conn.execute(
        'SELECT attack_type, COUNT(*) as cnt FROM predictions WHERE user_id = ? GROUP BY attack_type',
        (session['user_id'],)).fetchall()
    # Severity distribution
    severity = conn.execute(
        'SELECT severity_level, COUNT(*) as cnt FROM predictions WHERE user_id = ? GROUP BY severity_level',
        (session['user_id'],)).fetchall()
    # Recent trend (last 10)
    recent = conn.execute(
        'SELECT attack_type, anomaly_score, created_at FROM predictions WHERE user_id = ? ORDER BY created_at DESC LIMIT 10',
        (session['user_id'],)).fetchall()
    total = conn.execute('SELECT COUNT(*) FROM predictions WHERE user_id = ?',
                         (session['user_id'],)).fetchone()[0]
    conn.close()

    return render_template('analytics.html', distribution=dist, severity=severity,
                           recent=recent, total=total)


# ---------------------------------------------------------------------------
# Routes — About
# ---------------------------------------------------------------------------

@app.route('/about')
@login_required
def about():
    return render_template('about.html')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    init_db()
    print('=' * 60)
    print('  Network Security Anomaly Detection System')
    print('  http://localhost:5017')
    print('  Login: admin / admin123')
    print('=' * 60)
    app.run(debug=True, port=5017)
