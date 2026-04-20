# Enhancing Network Security: ML-Based Anomaly Detection — Project Explanation

## What Does This Project Do?

Imagine you're a security guard watching the entrance to a building. You need to decide: is this person a regular visitor, or are they trying to break in? Now imagine doing that for **thousands of network packets** every second.

This project is like a smart security guard for computer networks. It looks at network traffic (data flowing through the internet) and decides whether it's **normal** (safe) or a **cyber attack** (dangerous). It can detect 6 different types of threats — DDoS attacks, intrusions, malware, phishing, ransomware, and normal traffic.

## How Does It Work? (Step by Step)

### Step 1: Understanding Network Traffic

When computers talk to each other over the internet, they send small chunks of data called **packets**. Each packet has information like:
- **Where it came from** (source port — like a return address)
- **Where it's going** (destination port — like a house address)
- **What protocol it uses** (TCP, UDP, HTTP — like the language it speaks)
- **How big it is** (packet length)
- **What type it is** (data, control, management)

Think of it like letters in the mail — each has a sender, a receiver, a size, and contents.

### Step 2: Collecting Data

The system also records **security indicators** for each packet:
- **Anomaly Score:** A number from 0 to 1 that shows how "suspicious" the traffic looks. Normal traffic is close to 0, attacks are close to 1.
- **Severity Level:** Low, Medium, High, or Critical — how dangerous it could be
- **Malware Indicators:** Whether known virus signatures (called "Indicators of Compromise" or IoC) were found
- **IDS/IPS Alerts:** Whether the Intrusion Detection System raised an alarm
- **Firewall Logs:** Whether the firewall blocked, allowed, or dropped the traffic

In total, the system looks at **18 different features** to make its decision.

### Step 3: Training the AI (Machine Learning)

The `train_model.py` script creates the "brain" of the system:

1. **Generate training data** — It creates 5,000 sample network packets, each labeled with the correct attack type. The data is made realistic:
   - DDoS packets get high anomaly scores and critical severity
   - Malware packets have IoC detected
   - Normal packets have low anomaly and no alerts
   - Intrusion packets come from SSH/FTP services

2. **Encode the data** — Computers don't understand words like "TCP" or "High". So we use **LabelEncoder** to convert words into numbers. For example: TCP → 0, UDP → 1, ICMP → 2. We save 10 separate encoders (one for each categorical feature) as `.pkl` files.

3. **Train the model** — We use a **Random Forest Classifier**. This is like asking 100 different "decision trees" (simple yes/no question chains) to vote on what type of attack each packet is. The majority vote wins.

4. **Save the model** — The trained model is saved as `model.pkl` so the web app can load it instantly without retraining.

### Step 4: Making Predictions

When you fill in the form on the website:

1. Your inputs (packet type, anomaly score, etc.) are sent to the Flask server
2. The server encodes your text inputs into numbers using the saved encoders
3. It arranges the 18 numbers into the correct order
4. The Random Forest model looks at these 18 numbers and predicts which attack type it is
5. The result (like "DDoS" or "Normal") is shown on the page and saved to the database

### Step 5: Understanding the Results

The app shows your results in several ways:
- **Dashboard** — Quick overview with total scans, attacks detected, and normal traffic counts
- **History** — Table of every prediction with timestamp, protocol, anomaly score, severity, and result
- **Analytics** — Visual charts:
  - Doughnut chart showing attack type distribution
  - Doughnut chart showing severity distribution
  - Line chart showing anomaly scores over time
- **Mitigations** — For each attack type, what you can do to protect yourself

## What Does Each File Do?

| File | Purpose |
|------|---------|
| `app.py` | The main website — handles all routes, user login, predictions, dashboard |
| `train_model.py` | Creates the ML model and encoders from synthetic training data |
| `model.pkl` | The trained Random Forest model (the "brain") |
| `*_encoder.pkl` | 10 files that convert text categories to numbers and back |
| `templates/base.html` | Page layout with cyber-themed dark design |
| `templates/login.html` | Login page |
| `templates/register.html` | Registration page |
| `templates/home.html` | Security dashboard with stats and recent detections |
| `templates/predict.html` | The main detection form with 18 input fields |
| `templates/history.html` | Past detection results table |
| `templates/analytics.html` | Chart.js visualizations |
| `templates/suggestions.html` | Attack mitigation strategies |
| `templates/about.html` | Project information and tech stack |

## What Is a Random Forest?

Imagine you're trying to decide if a mushroom is poisonous. You could ask one expert, but what if they're wrong? A better approach: ask 100 experts and go with the majority answer.

A **Random Forest** does exactly this with "decision trees." Each tree is a series of yes/no questions:
- Is the anomaly score > 0.5? → Yes
- Is the severity Critical? → Yes
- Is there an IDS alert? → Yes
- → Predict: DDoS

Each of the 100 trees asks slightly different questions in a different order. They all vote, and the most popular answer wins. This makes Random Forest very accurate and resistant to errors.

In our model: `RandomForestClassifier(n_estimators=100)` means 100 trees voting together.

## What Is LabelEncoder?

Computers work with numbers, not words. LabelEncoder converts categories to numbers:

| Category | Encoded Value |
|----------|--------------|
| TCP | 0 |
| UDP | 1 |
| ICMP | 2 |
| HTTP | 3 |
| DNS | 4 |

We need 10 encoders because we have 10 text-based features (Protocol, Packet Type, Traffic Type, etc.). Each encoder "remembers" its mapping and can convert both ways — text to number (for prediction) and number to text (for display).

## What Are the 6 Attack Types?

| Attack | What It Does | Real-World Example |
|--------|-------------|-------------------|
| **DDoS** | Floods a server with so much traffic it can't respond | Millions of fake requests crash a website |
| **Intrusion** | Unauthorized access to a system | Someone guesses your SSH password |
| **Malware** | Malicious software infects a system | A virus that steals your files |
| **Phishing** | Tricks people into giving up information | Fake bank email asking for your password |
| **Ransomware** | Encrypts your files and demands payment | "Pay $500 to unlock your files" |
| **Normal** | Regular, harmless network traffic | You browsing a website normally |

## How to Run It Yourself

1. Install Python 3.8+
2. Run `pip install -r requirements.txt`
3. Run `python app.py` (starts the website)
4. Open http://localhost:5017 in your browser
5. Login with username: `admin`, password: `admin123`
6. Fill in network parameters and click "Detect Attack Type"

## Why Does This Matter?

- **Cyber attacks are growing:** Millions of attacks happen every day on the internet
- **Manual detection is impossible:** Humans can't check every network packet
- **ML is fast:** The model can classify thousands of packets per second
- **Prevention is better than cure:** Detecting attacks early prevents data breaches
- **Real-world use:** Companies like Cloudflare, CrowdStrike, and Palo Alto use similar ML models to protect networks
- **Education:** This project teaches how ML can be applied to cybersecurity — a field with massive job demand
