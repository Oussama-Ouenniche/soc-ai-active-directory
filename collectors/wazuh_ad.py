import pandas as pd
import logging
from datetime import datetime, timedelta, timezone
from opensearchpy import OpenSearch
from config.settings import SOCConfig

logger = logging.getLogger(__name__)

# Event IDs AD / Windows Security utiles pour SOC
EVENT_IDS = [
    # Auth
    "4624", "4625", "4672",
    "4768", "4769", "4771", "4776",

    # Comptes / mots de passe
    "4720", "4722", "4723", "4724", "4725", "4726",

    # Groupes (Admin / privilèges)
    "4728", "4729", "4732", "4733",

    # Effacement des logs
    "1102",
]


def get_client(config: SOCConfig) -> OpenSearch:
    """
    Client OpenSearch (Wazuh Indexer).

    - DEV/PFE: VERIFY_CERTS=False
    - PROD:    VERIFY_CERTS=True + CA_CERT
    """
    verify = bool(getattr(config, "VERIFY_CERTS", False))
    ca_path = getattr(config, "CA_CERT", None)

    return OpenSearch(
        hosts=[{"host": config.WAZUH_HOST, "port": config.WAZUH_PORT}],
        http_auth=(config.USERNAME, config.PASSWORD),
        use_ssl=True,
        verify_certs=verify,
        ca_certs=ca_path if verify else None,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
        timeout=30,
    )


def _safe_str(x) -> str:
    if x is None:
        return ""
    return str(x)


def _first(*vals, default=""):
    """Return first non-empty value."""
    for v in vals:
        if v is None:
            continue
        if isinstance(v, str) and v.strip() == "":
            continue
        return v
    return default


def extract_ad_events(client: OpenSearch, config: SOCConfig) -> pd.DataFrame:
    """
    Extraction des événements AD depuis Wazuh (index config.INDEX).
    Retourne un DataFrame normalisé pour les étapes features + detections.

    La fenêtre de collecte est définie par config.LOOKBACK_MINUTES.
    """
    now_utc = datetime.now(timezone.utc)
    start_time = (now_utc - timedelta(minutes=config.LOOKBACK_MINUTES)).isoformat()

    query = {
        "size": 10000,
        "_source": True,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"terms": {"data.win.system.eventID": EVENT_IDS}},
                    {"range": {"@timestamp": {"gte": start_time}}}
                ]
            }
        }
    }

    try:
        res = client.search(index=config.INDEX, body=query)
        hits = res.get("hits", {}).get("hits", [])
    except Exception as e:
        logger.error(f"Wazuh query error: {e}")
        return pd.DataFrame()

    if not hits:
        return pd.DataFrame()

    rows = []
    for h in hits:
        s = h.get("_source", {}) or {}
        source_event_id = h.get("_id")

        win = (s.get("data", {}) or {}).get("win", {}) or {}
        ev = win.get("eventdata", {}) or {}
        sys = win.get("system", {}) or {}

        event_id = _safe_str(sys.get("eventID")).strip()
        ts = s.get("@timestamp")

        if not event_id or not ts:
            continue

        target_user = _first(
            ev.get("TargetUserName"),
            ev.get("targetUserName"),
            ev.get("AccountName"),
            default=""
        )

        subject_user = _first(
            ev.get("SubjectUserName"),
            ev.get("subjectUserName"),
            ev.get("CallerUserName"),
            default=""
        )

        user = target_user or subject_user or "unknown"

        ip = _first(
            ev.get("IpAddress"),
            ev.get("ipAddress"),
            ev.get("ClientAddress"),
            ev.get("SourceNetworkAddress"),
            ev.get("SourceIp"),
            default="0.0.0.0"
        )

        workstation = _first(
            ev.get("WorkstationName"),
            ev.get("workstationName"),
            ev.get("Workstation"),
            ev.get("ComputerName"),
            default=""
        )

        host = (s.get("agent", {}) or {}).get("name", "unknown")

        logon_type = _first(ev.get("LogonType"), ev.get("logonType"), default="")
        status = _first(ev.get("Status"), ev.get("status"), default="")
        sub_status = _first(ev.get("SubStatus"), ev.get("subStatus"), default="")

        member_user = _first(
            ev.get("MemberName"),
            ev.get("TargetUserName"),
            ev.get("targetUserName"),
            default=""
        )

        group_name = _first(
            ev.get("GroupName"),
            ev.get("groupName"),
            ev.get("TargetSid"),
            ev.get("targetSid"),
            default=""
        )

        auth_failed = 1 if event_id in {"4625", "4771", "4776"} else 0
        auth_success = 1 if event_id == "4624" else 0

        rows.append({
            "timestamp": ts,
            "event_id": event_id,
            "source_event_id": source_event_id,

            "user": _safe_str(user) or "unknown",
            "target_user": _safe_str(target_user) or None,
            "subject_user": _safe_str(subject_user) or None,

            "ip": _safe_str(ip) or "0.0.0.0",
            "workstation": _safe_str(workstation) or None,
            "host": _safe_str(host) or "unknown",

            "auth_failed": auth_failed,
            "auth_success": auth_success,

            "logon_type": _safe_str(logon_type) or None,
            "status": _safe_str(status) or None,
            "sub_status": _safe_str(sub_status) or None,

            "group_name": _safe_str(group_name) or None,
            "member_user": _safe_str(member_user) or None,
        })

    df = pd.DataFrame(rows)
    if df.empty or "user" not in df.columns:
        return pd.DataFrame()

    noise = {
        "SYSTEM",
        "ANONYMOUS LOGON",
        "unknown",
        "AUTORITE NT\\SYSTEM",
        "AUTORITE NT\\SERVICE RÉSEAU",
        "AUTORITE NT\\SERVICE LOCAL",
    }

    df = df[~df["user"].isin(noise)].reset_index(drop=True)
    return df