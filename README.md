# SOC-AI — Active Directory Threat Detection & Prioritization

A modular cybersecurity project that enriches Windows Active Directory events collected by **Wazuh**, analyzes them with **UEBA features** and an **Isolation Forest** model, then publishes prioritized alerts to **OpenSearch**.

> This public repository is a sanitized demonstration version. It contains no production logs, certificates, real credentials, or internal infrastructure details.

## What it does

- Extracts relevant Windows / Active Directory security events from Wazuh Indexer.
- Normalizes authentication, account-management and privilege-related events.
- Builds UEBA features: login hour, failures in five minutes, unique IPs, unique hosts and successful login after failures.
- Applies rule-based detections for brute-force activity and IOC matches.
- Uses Isolation Forest for unsupervised anomaly detection.
- Adds contextual scoring and MITRE ATT&CK mappings.
- Stores enriched alerts in a dedicated OpenSearch index.

## Architecture

```mermaid
flowchart LR
    AD[Windows Server / Active Directory] --> WA[Wazuh Agent]
    WA --> WM[Wazuh Manager]
    WM --> OS[OpenSearch / Wazuh Indexer]
    OS --> C[Python Collector]
    C --> UEBA[UEBA Feature Engineering]
    UEBA --> D[Detection Engine]
    D --> ML[Isolation Forest]
    D --> R[Rules, IOC & Context]
    ML --> S[SOC Risk Scoring]
    R --> S
    S --> AI[soc-ai-alerts index]
    AI --> DB[OpenSearch Dashboards]
```

## Detection coverage

| Scenario | Relevant events / approach | MITRE ATT&CK |
|---|---|---|
| Brute-force authentication | 4625, 4771, 4776 + rolling five-minute failure window | T1110 |
| Suspicious successful login | 4624 after high failure volume | T1078 |
| Account creation / deletion | 4720, 4726 | T1136 |
| Privilege-related activity | 4672, privileged-group events | T1078 |
| Password reset | 4724 | T1098 |
| Security-log clearing | 1102 | T1070.001 |
| IOC match | IP, account, host, workstation or group comparison | Context-dependent |

## Repository layout

```text
collectors/   Wazuh/OpenSearch extraction and event normalization
core/         Detection-module loading, execution and shared context
detections/   Brute-force, IOC and ML/contextual detections
features/     UEBA feature engineering
responders/   Enriched alert publishing to OpenSearch
config/       Safe example configuration and IOC templates
docs/         Architecture and publication notes
main.py       Application entry point
```

## Quick start

### 1. Clone and create an environment

```bash
git clone https://github.com/Oussama-Ouenniche/soc-ai-active-directory.git
cd soc-ai-active-directory

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Create local configuration

```bash
cp config/settings.example.py config/settings.py
cp config/iocs.example.json config/iocs.json
```

Edit `config/settings.py` or provide the `SOC_AI_*` environment variables for your lab. `settings.py`, IOC data, certificates, logs and trained models are deliberately ignored by Git.

### 3. Run

```bash
python main.py
```

## Key technical choices

- **Isolation Forest** is used because security events are commonly unlabeled; it can flag unusual patterns without requiring a labeled attack dataset.
- The application uses a **hybrid approach**: deterministic rules, IOC matching, behavioral context and ML scores contribute to priority.
- Generated alerts receive a stable identifier so repeat processing updates the same logical alert rather than creating unnecessary duplicates.

## Tech stack

Python · Wazuh · OpenSearch · Pandas · NumPy · scikit-learn · Isolation Forest · Windows Active Directory · Linux

## Security and responsible publication

Before publishing or sharing your own deployment, do **not** include:

- real passwords, API keys or tokens;
- certificates and private keys;
- internal IP addresses, host names or domain names;
- production logs or personally identifiable information;
- virtual machine images and trained artifacts built from sensitive data.

## Author

**Oussama Ouenniche**  
Cybersecurity | Cloud | AI for Cybersecurity | Networking | Python & Linux

