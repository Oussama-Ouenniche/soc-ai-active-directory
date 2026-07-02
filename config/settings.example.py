"""Example local configuration for SOC-AI.

Copy this file to ``config/settings.py`` and replace the placeholder values.
The real settings file is intentionally excluded from Git.
"""

from pathlib import Path
import os

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


class SOCConfig:
    # OpenSearch / Wazuh Indexer
    WAZUH_HOST = os.getenv("SOC_AI_WAZUH_HOST", "127.0.0.1")
    WAZUH_PORT = int(os.getenv("SOC_AI_WAZUH_PORT", "9200"))
    USERNAME = os.getenv("SOC_AI_USERNAME", "admin")
    PASSWORD = os.getenv("SOC_AI_PASSWORD", "CHANGE_ME")

    # TLS: set SOC_AI_VERIFY_CERTS=true in environments with a valid CA certificate.
    CA_CERT = os.getenv(
        "SOC_AI_CA_CERT",
        str(PROJECT_ROOT / "certs" / "root-ca.pem"),
    )
    VERIFY_CERTS = _as_bool(os.getenv("SOC_AI_VERIFY_CERTS", "false"))

    # OpenSearch indices
    INDEX = os.getenv("SOC_AI_SOURCE_INDEX", "wazuh-alerts-*")
    ALERT_INDEX = os.getenv("SOC_AI_ALERT_INDEX", "soc-ai-alerts")

    # Collection and alerting windows
    LOOKBACK_MINUTES = int(os.getenv("SOC_AI_LOOKBACK_MINUTES", "1440"))
    ALERT_WINDOW_MINUTES = int(os.getenv("SOC_AI_ALERT_WINDOW_MINUTES", "5"))

    # UEBA / ML
    ML_MODEL_PATH = os.getenv(
        "SOC_AI_MODEL_PATH",
        str(PROJECT_ROOT / "models" / "isolation_forest_ad.pkl"),
    )
    ML_ANOMALY_THRESHOLD = float(
        os.getenv("SOC_AI_ML_ANOMALY_THRESHOLD", "0.60")
    )

    # Local artifacts
    IOC_FILE = os.getenv(
        "SOC_AI_IOC_FILE",
        str(PROJECT_ROOT / "config" / "iocs.json"),
    )
    LOG_FILE = os.getenv(
        "SOC_AI_LOG_FILE",
        str(PROJECT_ROOT / "logs" / "soc-ai.log"),
    )
