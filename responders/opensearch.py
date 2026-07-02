# responders/opensearch.py

import logging
import hashlib
import json


def _norm(v):
    if v is None:
        return ""
    if isinstance(v, list):
        return sorted(str(x).strip() for x in v)
    if isinstance(v, dict):
        return {k: _norm(v[k]) for k in sorted(v.keys())}
    return str(v).strip()


def _stable_alert_id(alert: dict) -> str:
    """
    ID stable basé sur l'identité logique de l'alerte,
    sans dépendre du timestamp de génération.
    """
    key_fields = {
        "alert_type": _norm(alert.get("alert_type")),
        "event_id": _norm(alert.get("event_id")),
        "event_ids": _norm(alert.get("event_ids")),
        "user": _norm(alert.get("user")),
        "target_user": _norm(alert.get("target_user")),
        "subject_user": _norm(alert.get("subject_user")),
        "ip": _norm(alert.get("ip")),
        "host": _norm(alert.get("host")),
        "workstation": _norm(alert.get("workstation")),
        "group_name": _norm(alert.get("group_name")),
        "member_user": _norm(alert.get("member_user")),
        "ioc_field": _norm(alert.get("ioc_field")),
        "ioc_value": _norm(alert.get("ioc_value")),
        "mitre": _norm(alert.get("mitre")),
        "title": _norm(alert.get("title")),
        "description": _norm(alert.get("description")),
    }

    raw = json.dumps(key_fields, sort_keys=True, ensure_ascii=False)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def push_alerts(context):
    client = context.client
    index = context.config.ALERT_INDEX
    alerts = context.alerts

    if not alerts:
        logging.info("No alerts to push")
        return

    for alert in alerts:
        try:
            alert_id = alert.get("alert_id") or _stable_alert_id(alert)
            alert["alert_id"] = alert_id

            client.index(
                index=index,
                id=alert_id,
                body=alert,
                
                
            )
        except Exception as e:
            logging.error(f"Failed to push alert to OpenSearch: {e}")
