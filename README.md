# Unified Privacy & Security Assistant (UPSA)

A comprehensive, production-ready platform designed to harmonize strict digital security with premium user experience using **usable security** and **behavioral economics** principles.

---

## 🎯 Strategic Value: Company Interests & User Experience

Historically, cybersecurity has been a trade-off: increasing security meant increasing user friction. Rigid Multi-Factor Authentication (MFA), aggressive session timeouts, and confusing browser warning messages often lead to user frustration, high customer support ticket volumes, cart abandonment, and employees seeking insecure workarounds.

**UPSA** resolves this trade-off. It provides businesses with a smart, adaptive framework that actively reduces user friction while proactively blocking threats and keeping systems compliant.

### 1. The Corporate Interest
*   **Preventing Customer Churn:** Traditional websites require constant MFA challenges. If a user exhibits high friction (e.g., typing delays, multiple attempts, abandonment of MFA screens), UPSA's **User Frustration Analyzer** detects it. The system can dynamically extend the trusted session window or adjust the step-up verification frequency for recognized, low-risk devices. This keeps users happy, reducing authentication drop-offs.
*   **Adaptive Account Takeover (ATO) Prevention:** Instead of using fixed login rules that attackers can study and bypass, UPSA uses an **Adaptive Risk Engine**. Every login is scored dynamically using indicators like impossible travel speed, device mismatch, IP reputation, and time-of-day. This protects sensitive data without blocking legitimate users.
*   **Interactive Compliance & Data Protection (GDPR / CCPA / CPRA):** Businesses can use UPSA to audit website permissions (camera, location, microphone, notifications) and flag inappropriate third-party tracking scripts. This keeps companies compliant with modern data protection regulations and avoids costly regulatory fines.
*   **Actionable Employee Training:** Instead of boring annual compliance videos, the **Security Awareness Survey** assesses each employee's actual security habits. It generates personalized learning cards that explain security in plain language, creating a proactive security culture.
*   **Automated Third-Party Risk Assessment:** Integrating the **Privacy Policy Analyzer** allows procurement, compliance, and legal teams to upload vendor privacy policies. The tool uses rule-based NLP to summarize what data is collected, shared, and retained, saving hours of manual review.

### 2. The User Experience (UX)
*   **Plain Language Explanations:** UPSA translates technical security jargon into simple analogies. For example, instead of explaining "MFA cryptographic challenge-response," UPSA explains: *"Think of MFA like a deadbolt on your door. Even if someone has your key (password), they still can't get in without the second lock."*
*   **Gamified Privacy Score:** The **0-100 Privacy Health Score** gives users clear, visual feedback on their security posture. It highlights exactly what they need to fix (like updating an old password or disabling location access on a shopping site) and rewards improvement.
*   **Friction Reduction:** When the system detects a user struggling with logins or password resets, it dynamically offers helpful recommendations (like using a password manager) or safely relaxes MFA checks on trusted devices.

---

## 📚 Academic Research & Paper

This project is backed by the research paper: **"UPSA: A Human-Centric Unified Privacy & Security Assistant with Adaptive Machine Learning"** (published in *NCSA National Cyber Security Academy, Air University*, 2026, Vol. 1).

### Key Contributions & Research Gap Solved:
*   **Static vs. Adaptive Authentication:** Introduces an Adaptive Risk Engine mapping contextual risk factors to custom login workflows.
*   **Explainable Security Interface:** Formulates layman-friendly security recommendations and a single, unified Privacy Health Score.
*   **Friction-Reduction Pipeline:** Measures UX friction via a Frustration Analyzer to programmatically adjust security controls.
*   **Proactive Threat Defense:** Employs an ML classifier ensemble to predict phishing susceptibility and account takeover probabilities before exploitation.
*   **Usability Validation:** Tested using the standardized **System Usability Scale (SUS)**, achieving ratings in the **"Good" to "Excellent"** range ($> 80$).

For detailed research methodology, empirical data, and references, please refer directly to the [UPSA Research Paper.pdf](UPSA%20Research%20Paper.pdf) in the root directory.

---

## 🔧 Enterprise Integration Playbook

Companies can easily integrate UPSA's key modules into their existing web systems. Below are the architectural patterns for integration:

### 1. Risk-Based Authentication Integration (Risk Engine API)
To implement adaptive, zero-trust login challenges:
*   **Middleware Hook:** Intercept login requests before they complete. Send the user's IP, User-Agent, device info, browser info, location (from GeoIP databases), and user history to UPSA's risk engine.
*   **Scoring Flow:**
    *   If the score is **Low Risk** ($\le 30$), log the user in immediately.
    *   If the score is **Medium Risk** ($31 - 60$), trigger a step-up MFA prompt (email OTP, SMS, or Authenticator app).
    *   If the score is **High Risk** ($> 60$), block the login attempt and alert the security team.
*   **API Response Contract Example:**
    ```json
    {
      "total_score": 45,
      "risk_category": "medium",
      "result": "mfa_required",
      "explanation": "We noticed you are logging in from a new location. Please enter the verification code sent to your email.",
      "factors": [
        {"name": "new_device", "triggered": true, "points": 25},
        {"name": "new_location", "triggered": true, "points": 20}
      ]
    }
    ```

### 2. User Frustration Mitigation (Telemetry & Adaptive UX)
To track and adapt to user friction:
*   **Client-Side Telemetry:** Record user actions like time spent typing, login error messages shown, visits to password reset pages, and MFA cancelations.
*   **Telemetry Processing:** Send these friction indicators to the frustration service at `/api/telemetry/friction`. The service calculates the user's frustration level ('low', 'medium', 'high').
*   **Adaptive UI Action:**
    *   If frustration is **High**, extend the user's trusted session length from the standard 7 days to 30 days (if the browser signature matches).
    *   Display helper cards pointing to support resources, single sign-on (SSO), or password managers to simplify the user's experience.

### 3. Third-Party Script & Browser Permission Auditing
To audit permissions granted to external scripts:
*   **Browser Queries:** Use the standard HTML5 Permissions API on the frontend to check active permissions:
    ```javascript
    navigator.permissions.query({name: 'geolocation'}).then(function(result) {
      // Sync result.state ('granted', 'denied') to the UPSA database
    });
    ```
*   **Categorization and Auditing:** Store the permission mappings in the backend (`WebsitePermission` model). The system flags permissions that don't match the site's function (e.g., location access on a gaming or shopping site). The user is then prompted to revoke inappropriate permissions, reducing the risk of data collection by third-party tracking scripts.

### 4. Privacy Policy NLP Analyzer
To analyze legal policies for compliance or transparency:
*   **Ingestion Endpoint:** Create a portal where users or employees can paste terms of service text or upload policy files (PDF/DOCX/TXT).
*   **NLP Extraction Pipeline:** Extract text using PyPDF2 or python-docx. Scan the text against structured dictionaries to count risk-related keywords.
*   **Summary Output:** Convert numerical scores for data collection, sharing, tracking, and retention into plain-language summaries (HTML/JSON cards) for review.

---

## ⚙️ How the System Works (Under the Hood)

UPSA is built with a modular, service-oriented architecture using Flask. Below is a detailed view of its technical components.

```
                  ┌──────────────────────────────────────────────┐
                  │                 Web Browser                  │
                  │   (Bootstrap 5 Theme, AJAX, Telemetry UX)    │
                  └──────────────┬──────────────────────▲────────┘
                                 │                      │
                                 │ HTTP Requests        │ Rendered Templates /
                                 │ & JSON Payloads      │ JSON API Responses
                                 ▼                      │
                  ┌─────────────────────────────────────┴────────┐
                  │             Flask App Controllers            │
                  │   (Auth, Settings, Survey, Analytics, etc.)  │
                  └──────────────┬──────────────────────▲────────┘
                                 │                      │
                                 │ Service Calls        │ Returns Models
                                 ▼                      │ & Scores
                  ┌─────────────────────────────────────┴────────┐
                  │               Business Services              │
                  │   (Risk Engine, Frustration, ML Classifier)  │
                  └──────────────┬──────────────────────▲────────┘
                                 │                      │
                                 │ Read / Write         │ Maps Tables to
                                 ▼                      │ Python Objects
                  ┌─────────────────────────────────────┴────────┐
                  │                Database Layer                │
                  │       (SQLite + SQLAlchemy ORM Models)       │
                  └──────────────────────────────────────────────┘
```

### 1. Data Models & Database Schema
The database uses **SQLite 3** managed via **SQLAlchemy ORM**. The relationships are mapped as follows:
*   **`User` ([user.py](file:///e:/UPSA/app/models/user.py)):** Stores credentials (bcrypt hashes), account verification status, password age, password strength, and failed login counts.
*   **`PrivacyScore` ([privacy_score.py](file:///e:/UPSA/app/models/privacy_score.py)):** Stores the periodic overall privacy score (out of 100) and scores for each component (MFA, password age, browser permissions, and surveys).
*   **`RiskEvent` ([risk_event.py](file:///e:/UPSA/app/models/risk_event.py)):** Logs login attempts, IP address, user-agent, geo-location, total calculated risk points, risk level ('low', 'medium', 'high'), decision ('allowed', 'mfa_required', 'blocked'), and plain-language explanation.
*   **`FrustrationMetric` ([frustration_metric.py](file:///e:/UPSA/app/models/frustration_metric.py)):** Aggregates login failures, password resets, MFA abandonments, help page visits, and login durations over a rolling 7-day period to compute frustration levels.
*   **`WebsitePermission` ([website_permission.py](file:///e:/UPSA/app/models/website_permission.py)):** Audits browser permissions granted to external sites, classifying them as contextually appropriate or inappropriate.
*   **`Recommendation` ([recommendation.py](file:///e:/UPSA/app/models/recommendation.py)):** Actionable recommendations (high, medium, low priority) generated automatically based on weaknesses identified in the privacy score.
*   **`PolicyReport` ([policy_report.py](file:///e:/UPSA/app/models/policy_report.py)):** Stores compliance reports generated from uploaded privacy policies.
*   **`MLPrediction` ([ml_prediction.py](file:///e:/UPSA/app/models/ml_prediction.py)):** Logs predictions made by machine learning models.

### 2. Core Service Components & Algorithms

#### A. Risk Assessment Engine ([risk_engine.py](file:///e:/UPSA/app/services/risk_engine.py))
Every login attempt is evaluated using these risk factors:

| Risk Factor | Points | Evaluation Trigger |
| :--- | :--- | :--- |
| **Impossible Travel** | 40 | Login location physically impossible compared to the time of the last login. |
| **New Location** | 30 | Login from an unrecognized location or IP range. |
| **Failed Attempts** | 25 | $\ge 3$ consecutive password failures within the last hour. |
| **New Device** | 25 | First time logging in from a particular device signature. |
| **New Browser** | 20 | Unrecognized browser client on a trusted device. |
| **Unusual Time** | 15 | Login occurs outside the user's normal active hours (6:00 AM - 11:00 PM). |

*   **Low Risk ($\le 30$):** Allowed immediately.
*   **Medium Risk ($31 - 60$):** Triggers MFA step-up.
*   **High Risk ($> 60$):** Account locked; requires administrative review.

#### B. Frustration Index Calculation ([frustration_metric.py](file:///e:/UPSA/app/models/frustration_metric.py))
The frustration level is a weighted index calculated from the user's login and session interactions over a rolling 7-day period.

##### Scoring Metrics:
*   **Failed Logins:** +5 points per failure (capped at 25 points)
*   **Password Resets:** +10 points per reset request (capped at 20 points)
*   **MFA Abandonments:** +8 points per abandoned flow (capped at 24 points)
*   **Help Page Visits:** +3 points per visit to the support page (capped at 15 points)

##### Friction Score Formula:
```text
Friction Score = Min(Failed_Logins * 5, 25) 
                 + Min(Password_Resets * 10, 20) 
                 + Min(MFA_Abandonments * 8, 24) 
                 + Min(Help_Visits * 3, 15)
```

##### Categorization & System Response:
*   **Low Frustration (Score $\le$ 20):** *Smooth Experience*. Default security checks apply.
*   **Medium Frustration (Score 21 - 45):** *Some Friction*. System suggests helpful configuration tips (e.g., saving browser as trusted, utilizing a password manager).
*   **High Frustration (Score $>$ 45):** *High Friction*. System initiates adaptive UX adjustments (e.g., safely extending the trusted device session duration to reduce verification prompts).

#### C. Machine Learning Analytics Pipeline ([ml_service.py](file:///e:/UPSA/app/services/ml_service.py))
UPSA uses ML models to predict:
1.  **Phishing Susceptibility:** Classifies users into Low, Medium, or High risk of falling for phishing.
2.  **Account Compromise Risk:** Predicts the probability (0.0 to 1.0) of an account compromise in the next 90 days.

*   **Feature Vector Configuration:** The model accepts a 14-dimensional input vector:
    *   Features $0-9$: Scaled answers from the Security Awareness Survey ($0.0$ represents high risk/poor habits, $1.0$ represents low risk/strong habits).
    *   Feature $10$: MFA Enabled status ($0.0$ or $1.0$).
    *   Feature $11$: Password Age (normalized: days elapsed / 365, capped at $1.0$).
    *   Feature $12$: Login Failures count (normalized: count / 10, capped at $1.0$).
    *   Feature $13$: Overall Privacy Health Score (normalized: score / 100).
*   **Model Architectures:**
    *   **Random Forest Classifier (`phishing_rf.joblib`, `account_rf.joblib`):** An ensemble of decision trees used for robust, non-linear classification.
    *   **Logistic Regression (`phishing_lr.joblib`):** Provides probability distributions for risk levels.
    *   **Decision Tree Classifier (`phishing_dt.joblib`):** Offers a clear decision-tree explanation of how security factors impact risk.
*   The system uses an **ensemble approach** for phishing prediction, averaging the probabilities from both Random Forest and Logistic Regression.

#### D. Privacy Policy Ingestion Engine ([policy_analyzer.py](file:///e:/UPSA/app/services/policy_analyzer.py))
Uses rule-based NLP to process policy text:
1.  **Text Extraction:** Extracts raw text from uploaded `.pdf`, `.docx`, or `.txt` files.
2.  **Sentence Extraction:** Normalizes characters and splits text into individual sentences.
3.  **Keyword Matching:** Scores text across categories using dictionary matching:
    *   *Data Collection:* Evaluates collection of sensitive info (GPS location, biometrics, financial info, government IDs).
    *   *Data Sharing:* Evaluates terms like "sell data", "brokers", "third-party advertisers".
    *   *Tracking:* Matches tracking methods (pixels, cross-site cookies, beacons, fingerprinting).
    *   *Retention:* Evaluates retention periods ("indefinitely", "permanently").
    *   *User Rights:* Evaluates user options ("right to deletion", "opt out", "request copy", "arbitration").
4.  **Reporting:** Generates score cards, lists negative/positive findings, and outputs a plain-language HTML summary.

---

## 🚀 Getting Started & Local Setup

Follow these steps to run UPSA on your local machine:

### 1. Clone & Set Up Virtual Environment
Clone the repository and navigate to the project directory:
```bash
# Clone the repository
git clone https://github.com/bali-36/UPSA.git
cd UPSA

# Set up a virtual environment
python -m venv .venv

# Activate the virtual environment
# On Windows (PowerShell/CMD):
.venv\Scripts\activate

# On macOS/Linux:
source .venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Seed the Database
Seed the database with default rules, website permissions, mock users, and 180 days of historical activity data:
```bash
python scripts/seed_data.py
```

### 4. Run the Application
Launch the Flask development server:
```bash
python run.py
```
Open your web browser and go to: `http://127.0.0.1:5000`

### 🔒 Demo Credentials
You can log in using these pre-seeded accounts:

| Email | Password | Role | Description |
| :--- | :--- | :--- | :--- |
| **admin@upsa.local** | `AdminPass123!` | Administrator | Full access to settings, user management, and audit logs. |
| **alice@example.com** | `DemoPass123!` | Default User | Standard dashboard, privacy scoring, and recommendation features. |
| **bob@example.com** | `DemoPass123!` | Default User | Standard dashboard with pre-seeded analytics history. |

---

## 🧪 Testing Guide

UPSA has automated tests to verify the authentication flows, risk engine rules, NLP policy parser, and AJAX endpoints.

### Run the Complete Test Suite
Run tests using Pytest with the virtual environment activated:
```bash
.venv\Scripts\python -m pytest
```

### Advanced Testing Commands
*   **Run with verbose logging:**
    ```bash
    .venv\Scripts\python -m pytest -v
    ```
*   **Run a specific test module:**
    ```bash
    .venv\Scripts\python -m pytest tests/test_risk_engine.py -v
    ```
*   **Run code coverage analysis:**
    ```bash
    .venv\Scripts\python -m pytest --cov=app tests/
    ```

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Muhammad Bilal Badar. All rights reserved.
