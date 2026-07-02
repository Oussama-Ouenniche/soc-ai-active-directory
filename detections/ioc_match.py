# detections/ioc_match.py

from datetime import datetime, timezone
import os
import json
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
IOC_FILE_DEFAULT = str(PROJECT_ROOT / "config" / "iocs.json")

SEVERITY_TO_LEVEL = {
    "LOW": 7,
    "MEDIUM": 10,
    "HIGH": 13,
    "CRITICAL": 15,
}

SEVERITY_TO_SCORE = {
    "LOW": 40.0,
    "MEDIUM": 65.0,
    "HIGH": 85.0,
    "CRITICAL": 100.0,
}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _clean(v):
    if v is None:
        return None
    try:
        if pd.isna(v):
            return None
    except Exception:
        pass
    s = str(v).strip()
    return s if s else None


def _load_iocs(context):
    """
    Charge les IOC depuis un fichier JSON.
    Sans modifier settings.py : fallback sur IOC_FILE_DEFAULT.
    Format attendu :
    {
      "ip": ["203.0.113.10", "198.51.100.25"],
      "user": ["evil.user", "svc-backdoor"],
      "host": ["LAB-DC01", "LAB-WKS01"],
      "workstation": ["LAB-WKS01", "LAB-WKS02"],
      "group_name": ["Domain Admins"],
      "target_user": ["administrator"],
      "subject_user": ["unknown-admin"]
    }
    """
    cfg = getattr(context, "config", None)
    ioc_file = getattr(cfg, "IOC_FILE", IOC_FILE_DEFAULT) if cfg else IOC_FILE_DEFAULT

    if not os.path.exists(ioc_file):
        return {}

    try:
        with open(ioc_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {k: set(str(x).strip().lower() for x in v if str(x).strip()) for k, v in data.items()}
    except Exception:
        return {}

    return {}


def _infer_severity(field):
    if field in {"ip", "host", "workstation"}:
        return "HIGH"
    if field in {"user", "target_user", "subject_user", "member_user"}:
        return "HIGH"
    if field == "group_name":
        return "CRITICAL"
    return "MEDIUM"


def run(context):
    df = context.df
    if df is None or df.empty:
        return []

    iocs = _load_iocs(context)
    if not iocs:
        return []

    alerts = []
    now = _now()

    supported_fields = [
        "ip",
        "user",
        "host",
        "workstation",
        "group_name",
        "member_user",
        "target_user",
        "subject_user",
    ]

    for _, row in df.iterrows():
        for field in supported_fields:
            if field not in iocs or not iocs[field]:
                continue

            value = _clean(row.get(field))
            if not value:
                continue

            value_norm = value.lower()
            if value_norm not in iocs[field]:
                continue

            severity = _infer_severity(field)
            level = SEVERITY_TO_LEVEL[severity]
            soc_score = SEVERITY_TO_SCORE[severity]

            ml_risk = row.get("ml_risk")
            ml_label = row.get("ml_label")
            ml_raw = row.get("ml_raw_score")
            ml_anom = bool(row.get("ml_anomaly")) if row.get("ml_anomaly") is not None else False

            if ml_risk is not None:
                try:
                    soc_score = min(100.0, soc_score + float(ml_risk) * 0.15)
                except Exception:
                    pass

            if ml_anom:
                soc_score = min(100.0, soc_score + 5.0)

            alerts.append({
                "@timestamp": now,
                "source": "soc-ai",
                "alert_type": "ioc_match",

                "title": f"[IOC] Correspondance détectée sur {field}: {value}",
                "description": f"Une valeur observée correspond à un IOC connu. Champ={field}, valeur={value}.",

                "severity": severity,
                "soc_score": round(soc_score, 2),

                "event_id": str(row.get("event_id") or "IOC"),
                "user": _clean(row.get("user")),
                "target_user": _clean(row.get("target_user")),
                "subject_user": _clean(row.get("subject_user")),

                "ip": _clean(row.get("ip")) or "0.0.0.0",
                "host": _clean(row.get("host")) or "unknown",
                "workstation": _clean(row.get("workstation")),

                "group_name": _clean(row.get("group_name")),
                "member_user": _clean(row.get("member_user")),

                "ioc_field": field,
                "ioc_value": value,
                "ctx_suspicious": True,

                "ml_label": ml_label,
                "ml_risk": ml_risk,
                "ml_raw_score": ml_raw,
                "ml_anomaly": ml_anom,

                "rule": {
                    "level": level,
                    "groups": ["soc-ai", "ioc", "threat-intel"]
                }
            })

    return alerts