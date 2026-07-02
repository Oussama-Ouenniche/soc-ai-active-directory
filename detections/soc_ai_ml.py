from datetime import datetime, timezone, timedelta
import math
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


# ========= Events =========
CRITICAL_EVENT_IDS = {"1102", "4726", "4724"}
WATCH_EVENT_IDS = {"4625", "4771", "4776"}
CREATE_EVENT = "4720"
DELETE_EVENT = "4726"
PASSWORD_RESET_EVENT = "4724"
SUCCESS_LOGON_EVENT = "4624"
GROUP_ADD_EVENTS = {"4728", "4732", "4756"}
PRIV_EVENT = "4672"

ADMIN_GROUP_KEYWORDS = [
    "admin",
    "administrateur",
    "administrateurs",
    "admins du domaine",
    "domain admins",
    "administrateurs de l’entreprise",
    "administrateurs des entreprise",
    "enterprise admins",
    "administrateurs du schéma",
    "schema admins",
    "administrateurs clés",
    "key admins",
    "administrators",
    "account operators",
    "backup operators",
    "server operators",
]

TRUSTED_SUBJECTS = {
    "Administrateur",
    "Administrator",
    "svc_provisioning",
    "svc_ad_sync",
    "svc_iam",
}

TRUSTED_HOSTS = {
    "IAM-SERVER",
    "DC-LAB",
    "IDM-SERVER",
}

TEST_USER_PREFIXES = ("test_", "tmp_", "lab_", "demo_", "qa_")
SERVICE_USER_PREFIXES = ("svc_", "sa_")

EVENT_DESC = {
    "4756": "Ajout d’un membre à un groupe universel",
    "4624": "Connexion réussie (logon success)",
    "4625": "Échec de connexion (logon failure)",
    "4672": "Connexion avec privilèges élevés (Special privileges)",
    "4720": "Création d’un compte utilisateur",
    "4722": "Compte utilisateur activé",
    "4723": "Tentative de changement de mot de passe",
    "4724": "Réinitialisation du mot de passe (password reset)",
    "4725": "Compte utilisateur désactivé",
    "4726": "Suppression d’un compte utilisateur",
    "4728": "Ajout d’un membre à un groupe global",
    "4729": "Suppression d’un membre à un groupe global",
    "4732": "Ajout d’un membre à un groupe local",
    "4733": "Suppression d’un membre à un groupe local",
    "4768": "Demande TGT Kerberos (AS-REQ)",
    "4769": "Demande TGS Kerberos (TGS-REQ)",
    "4771": "Échec Kerberos pre-auth",
    "4776": "Échec d’authentification NTLM",
    "1102": "Effacement des journaux de sécurité (Security log cleared)",
}


# ========= Helpers =========
def _now():
    return datetime.now(timezone.utc)


def _clean(v):
    if v is None:
        return None
    try:
        if pd.isna(v):
            return None
    except Exception:
        pass
    if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
        return None
    s = str(v).strip()
    return s if s else None


def _safe_float(v, default=None):
    try:
        if v is None:
            return default
        return float(v)
    except Exception:
        return default


def _safe_int(v, default=None):
    try:
        if v is None:
            return default
        return int(v)
    except Exception:
        return default


def _event_desc(event_id: str) -> str:
    return EVENT_DESC.get(str(event_id), f"Événement Windows Security {event_id}")


def _mitre_for_event(event_id: str):
    mapping = {
        "1102": {
            "tactic": ["Defense Evasion"],
            "technique": ["T1070", "T1070.001"],
            "technique_name": [
                "Indicator Removal on Host",
                "Indicator Removal on Host: Clear Windows Event Logs"
            ],
        },
        "4720": {
            "tactic": ["Persistence", "Privilege Escalation"],
            "technique": ["T1136", "T1136.002"],
            "technique_name": [
                "Create Account",
                "Create Account: Domain Account"
            ],
        },
        "4724": {
            "tactic": ["Persistence", "Privilege Escalation"],
            "technique": ["T1098"],
            "technique_name": ["Account Manipulation"],
        },
        "4672": {
            "tactic": ["Privilege Escalation"],
            "technique": ["T1078"],
            "technique_name": ["Valid Accounts"],
        },
        "4625": {
            "tactic": ["Credential Access"],
            "technique": ["T1110"],
            "technique_name": ["Brute Force"],
        },
        "4771": {
            "tactic": ["Credential Access"],
            "technique": ["T1110"],
            "technique_name": ["Brute Force"],
        },
        "4776": {
            "tactic": ["Credential Access"],
            "technique": ["T1110"],
            "technique_name": ["Brute Force"],
        },
        "4728": {
            "tactic": ["Privilege Escalation", "Persistence"],
            "technique": ["T1098"],
            "technique_name": ["Account Manipulation"],
        },
        "4732": {
            "tactic": ["Privilege Escalation", "Persistence"],
            "technique": ["T1098"],
            "technique_name": ["Account Manipulation"],
        },
        "4756": {
            "tactic": ["Privilege Escalation", "Persistence"],
            "technique": ["T1098"],
            "technique_name": ["Account Manipulation"],
        },
    }
    return mapping.get(str(event_id))


def _mitre_for_correlation(name: str):
    mapping = {
        "create_delete": {
            "tactic": ["Persistence", "Privilege Escalation"],
            "technique": ["T1136", "T1136.002"],
            "technique_name": [
                "Create Account",
                "Create Account: Domain Account"
            ],
        },
        "reset_then_logon": {
            "tactic": ["Persistence", "Privilege Escalation"],
            "technique": ["T1098"],
            "technique_name": ["Account Manipulation"],
        },
        "create_admin_group": {
            "tactic": ["Privilege Escalation", "Persistence"],
            "technique": ["T1136", "T1098"],
            "technique_name": ["Create Account", "Account Manipulation"],
        },
    }
    return mapping.get(name)


def _is_machine_account(user: str) -> bool:
    return user.endswith("$") if user else False


def _is_bad_member_candidate(user: str) -> bool:
    if not user:
        return True

    u = str(user).strip().lower()

    bad_values = {
        "system",
        "système",
        "anonymous logon",
        "unknown",
        "unknown_member",
        "administrateur",
        "administrator",
        "administrateur@pfe.local",
        "administrator@pfe.local",
        "administrateurs",
        "admins du domaine",
        "domain admins",
        "administrateurs de l’entreprise",
        "administrateurs du schéma",
        "enterprise admins",
        "schema admins",
        "nt authority\\system",
        "autorite nt\\system",
        "autorité nt\\système",
    }

    if u in bad_values:
        return True

    if u.endswith("$"):
        return True

    return False


def _is_admin_group(group_name: str) -> bool:
    if not group_name:
        return False
    g = str(group_name).lower().replace("’", "'")
    keywords = [k.lower().replace("’", "'") for k in ADMIN_GROUP_KEYWORDS]
    return any(k in g for k in keywords)


def _account_category(user: str) -> str:
    u = (user or "").lower()
    if not u:
        return "unknown"
    if u.endswith("$"):
        return "machine"
    if u.startswith(SERVICE_USER_PREFIXES):
        return "service"
    if u.startswith(TEST_USER_PREFIXES):
        return "test"
    return "human"


def _is_likely_legit_action(row) -> bool:
    subject = (_clean(row.get("subject_user")) or "")
    host = (_clean(row.get("host")) or "")
    target = (_clean(row.get("target_user")) or _clean(row.get("user")) or "").lower()

    if subject in TRUSTED_SUBJECTS and host in TRUSTED_HOSTS:
        return True
    if target.startswith(TEST_USER_PREFIXES):
        return True
    return False


def _context_details(row):
    hour = row.get("hour")
    return {
        "night_activity": bool(hour is not None and (hour <= 5 or hour >= 23)),
        "failures_5min": _safe_float(row.get("failures_5min", 0), 0.0),
        "unique_ips_user": _safe_float(row.get("unique_ips_user", 0), 0.0),
        "unique_hosts_user": _safe_float(row.get("unique_hosts_user", 0), 0.0),
        "success_after_fail": _safe_int(row.get("success_after_fail", 0), 0),
    }


def _suspicious_context(row) -> bool:
    d = _context_details(row)
    if d["failures_5min"] >= 8:
        return True
    if d["unique_ips_user"] >= 4:
        return True
    if d["unique_hosts_user"] >= 4:
        return True
    if d["success_after_fail"] == 1:
        return True
    if d["night_activity"] and (
        d["failures_5min"] >= 1 or
        d["unique_ips_user"] >= 2 or
        d["unique_hosts_user"] >= 2 or
        d["success_after_fail"] == 1
    ):
        return True
    return False


def _severity_from_score(score: float) -> str:
    if score >= 95:
        return "CRITICAL"
    if score >= 80:
        return "HIGH"
    if score >= 60:
        return "MEDIUM"
    return "LOW"


def _level_from_severity(sev: str) -> int:
    return {"LOW": 7, "MEDIUM": 10, "HIGH": 13, "CRITICAL": 15}.get(sev, 7)


def _build_score_details(
    base_score: float,
    ml_risk=None,
    ctx_suspicious: bool = False,
    ml_anom: bool = False,
    correlation_bonus: float = 0.0,
    legit_reduction: float = 0.0,
):
    score = float(base_score)

    details = {
        "base_score": round(float(base_score), 2),
        "ml_bonus": 0.0,
        "context_bonus": 0.0,
        "anomaly_bonus": 0.0,
        "correlation_bonus": round(float(correlation_bonus), 2),
        "legit_reduction": round(float(legit_reduction), 2),
    }

    if ml_risk is not None:
        try:
            ml_bonus = min(12.0, float(ml_risk) * 0.12)
            details["ml_bonus"] = round(ml_bonus, 2)
            score += ml_bonus
        except Exception:
            pass

    if ctx_suspicious:
        details["context_bonus"] = 5.0
        score += 5.0

    if ml_anom:
        details["anomaly_bonus"] = 5.0
        score += 5.0

    score += correlation_bonus
    score -= legit_reduction

    score = max(0.0, min(100.0, score))
    return round(score, 2), details


def _pick_ml_from_rows(primary_row, fallback_row=None):
    ml_label = primary_row.get("ml_label") if primary_row is not None else None
    ml_risk = primary_row.get("ml_risk") if primary_row is not None else None
    ml_anom = primary_row.get("ml_anomaly") if primary_row is not None else None

    if fallback_row is not None:
        if ml_label is None:
            ml_label = fallback_row.get("ml_label")
        if ml_risk is None:
            ml_risk = fallback_row.get("ml_risk")
        if ml_anom is None:
            ml_anom = fallback_row.get("ml_anomaly")

    return (
        _safe_float(ml_risk),
        ml_label,
        bool(ml_anom) if ml_anom is not None else False,
    )


def _find_related_events(d: pd.DataFrame, user_value: str, start_time, end_time) -> pd.DataFrame:
    if not user_value or pd.isna(start_time) or pd.isna(end_time):
        return pd.DataFrame()

    conditions = (
        (d["timestamp"] >= start_time) &
        (d["timestamp"] <= end_time)
    )

    user_match = pd.Series(False, index=d.index)
    for col in ["user", "target_user", "member_user"]:
        if col in d.columns:
            user_match = user_match | (d[col] == user_value)

    return d[conditions & user_match]


# ========= ML =========
_MODEL_CACHE = {"model": None, "n_features": None, "path": None}


def _to_numeric_df(df: pd.DataFrame) -> pd.DataFrame:
    X = df.copy()
    for c in X.columns:
        X[c] = pd.to_numeric(X[c], errors="coerce").fillna(0)
    return X


def _load_or_train_model(X: pd.DataFrame, model_path: str):
    if (
        _MODEL_CACHE["model"] is not None
        and _MODEL_CACHE["n_features"] == X.shape[1]
        and _MODEL_CACHE["path"] == model_path
    ):
        return _MODEL_CACHE["model"]

    if model_path and os.path.exists(model_path):
        try:
            model = joblib.load(model_path)
            if getattr(model, "n_features_in_", None) == X.shape[1]:
                _MODEL_CACHE.update({"model": model, "n_features": X.shape[1], "path": model_path})
                return model
        except Exception:
            pass

    model = IsolationForest(
        n_estimators=300,
        contamination=0.02,
        random_state=42
    )
    model.fit(X)

    if model_path:
        try:
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            joblib.dump(model, model_path)
        except Exception:
            pass

    _MODEL_CACHE.update({"model": model, "n_features": X.shape[1], "path": model_path})
    return model


def _risk_from_raw(raw: np.ndarray) -> np.ndarray:
    raw = raw.astype(float)

    if len(raw) == 0:
        return np.array([], dtype=float)

    if len(raw) == 1:
        return np.array([50.0], dtype=float)

    inv = -raw
    order = np.argsort(inv)
    ranks = np.empty_like(order, dtype=float)
    ranks[order] = np.linspace(0, 1, num=len(inv), endpoint=True)

    risk = np.clip(ranks, 0, 1) * 100.0

    # si la décision ML est positive, on limite le risque
    risk = np.where(raw > 0, np.minimum(risk, 45.0), risk)

    return risk


def _ml_score_batch(context, df_features: pd.DataFrame) -> pd.DataFrame:
    if df_features is None or df_features.empty:
        return pd.DataFrame(index=getattr(df_features, "index", None))

    X = _to_numeric_df(df_features)

    cfg = getattr(context, "config", None)
    model_path = getattr(cfg, "ML_MODEL_PATH", None) if cfg else None
    thr01 = float(getattr(cfg, "ML_ANOMALY_THRESHOLD", 0.60)) if cfg else 0.60
    thr = thr01 * 100.0

    model = _load_or_train_model(X, model_path)
    raw = model.decision_function(X)

    risk = _risk_from_raw(raw)
    anomaly = risk >= thr
    label = np.where(anomaly, "suspicious", "benign")

    return pd.DataFrame({
        "ml_anomaly": anomaly.astype(bool),
        "ml_risk": risk.astype(float),
        "ml_label": label.astype(str),
    }, index=df_features.index)


def _add_recent_flag(df: pd.DataFrame, context) -> pd.DataFrame:
    d = df.copy()
    now = _now()

    cfg = getattr(context, "config", None)
    alert_window = int(getattr(cfg, "ALERT_WINDOW_MINUTES", 5)) if cfg else 5

    d["timestamp"] = pd.to_datetime(d["timestamp"], utc=True, errors="coerce")
    cutoff = now - timedelta(minutes=alert_window)
    d["is_recent"] = d["timestamp"] >= cutoff
    d["is_recent"] = d["is_recent"].fillna(False)

    return d


# ========= Correlations =========
def _correlate_create_delete(df: pd.DataFrame, max_delta_minutes: int = 2):
    alerts = []
    consumed = set()

    if df is None or df.empty:
        return alerts, consumed

    d = df.copy()
    d["timestamp"] = pd.to_datetime(d["timestamp"], utc=True, errors="coerce")
    d = d.dropna(subset=["timestamp"])
    d["event_id"] = d["event_id"].astype(str)
    d = d.sort_values("timestamp")

    creates = d[d["event_id"] == CREATE_EVENT]
    deletes = d[d["event_id"] == DELETE_EVENT]
    if creates.empty or deletes.empty:
        return alerts, consumed

    creates_by_user = {}
    for idx, r in creates.iterrows():
        tu = _clean(r.get("target_user")) or _clean(r.get("user"))
        if not tu:
            continue
        creates_by_user.setdefault(tu, []).append((idx, r))

    now = _now()
    max_delta = timedelta(minutes=max_delta_minutes)

    for del_idx, del_row in deletes.iterrows():
        if not bool(del_row.get("is_recent", False)):
            continue

        tu = _clean(del_row.get("target_user")) or _clean(del_row.get("user"))
        del_time = del_row.get("timestamp")
        if not tu or pd.isna(del_time) or tu not in creates_by_user:
            continue

        best_create = None
        best_create_idx = None
        best_dt = None

        for cr_idx, cr in creates_by_user[tu]:
            cr_time = cr.get("timestamp")
            if pd.isna(cr_time) or cr_time > del_time:
                continue
            dt = del_time - cr_time
            if best_dt is None or dt < best_dt:
                best_dt = dt
                best_create = cr
                best_create_idx = cr_idx

        if best_create is None or best_dt is None or best_dt > max_delta:
            continue

        delta_sec = best_dt.total_seconds()
        used_before_delete = not _find_related_events(d, tu, best_create.get("timestamp"), del_time)[
            lambda x: x["event_id"].isin({"4624", "4672", "4728", "4732", "4756"})
        ].empty

        trusted_action = _is_likely_legit_action(del_row) or _is_likely_legit_action(best_create)
        account_type = _account_category(tu)

        if delta_sec <= 5:
            base_score = 88.0
        elif delta_sec <= 30:
            base_score = 80.0
        else:
            base_score = 72.0

        correlation_bonus = 6.0
        if used_before_delete:
            correlation_bonus += 4.0

        legit_reduction = 0.0
        if trusted_action:
            legit_reduction += 10.0
        if account_type == "test":
            legit_reduction += 8.0
        elif account_type == "service":
            legit_reduction += 5.0

        ctx_suspicious = (
            _suspicious_context(del_row) or
            _suspicious_context(best_create) or
            delta_sec <= 5 or
            used_before_delete
        )

        ml_risk, ml_label, ml_anom = _pick_ml_from_rows(del_row, best_create)
        soc, score_details = _build_score_details(
            base_score=base_score,
            ml_risk=ml_risk,
            ctx_suspicious=ctx_suspicious,
            ml_anom=ml_anom,
            correlation_bonus=correlation_bonus,
            legit_reduction=legit_reduction,
        )
        severity = _severity_from_score(soc)

        alerts.append({
            "@timestamp": now.isoformat(),
            "source": "soc-ai",
            "alert_type": "ad_user_lifecycle_suspicious",
            "rule_level": _level_from_severity(severity),
            "title": f"[{severity}] Create/Delete rapide: {tu}",
            "description": f"Compte créé (4720) puis supprimé (4726) en {best_dt}. Pattern suspect.",
            "severity": severity,
            "soc_score": soc,
            "mitre_attack": _mitre_for_correlation("create_delete"),
            "event_id": "CORRELATED",
            "event_ids": ["4720", "4726"],
            "user": str(tu),
            "target_user": str(tu),
            "subject_user": _clean(del_row.get("subject_user")) or _clean(best_create.get("subject_user")),
            "ip": str(_clean(del_row.get("ip")) or _clean(best_create.get("ip")) or "0.0.0.0"),
            "host": str(_clean(del_row.get("host")) or _clean(best_create.get("host")) or "unknown"),
            "ctx_suspicious": bool(ctx_suspicious),
            "ml_label": ml_label,
            "ml_risk": ml_risk,
            "ml_anomaly": bool(ml_anom),
        })

        consumed.add(del_idx)
        if best_create_idx is not None:
            consumed.add(best_create_idx)

    return alerts, consumed


def _correlate_reset_then_logon(df: pd.DataFrame, max_delta_minutes: int = 10):
    alerts = []
    consumed = set()

    if df is None or df.empty:
        return alerts, consumed

    d = df.copy()
    d["timestamp"] = pd.to_datetime(d["timestamp"], utc=True, errors="coerce")
    d = d.dropna(subset=["timestamp"])
    d["event_id"] = d["event_id"].astype(str)
    d = d.sort_values("timestamp")

    resets = d[d["event_id"] == PASSWORD_RESET_EVENT]
    logons = d[d["event_id"] == SUCCESS_LOGON_EVENT]
    if resets.empty or logons.empty:
        return alerts, consumed

    resets_by_user = {}
    for idx, r in resets.iterrows():
        u = _clean(r.get("target_user")) or _clean(r.get("user"))
        if not u:
            continue
        resets_by_user.setdefault(u, []).append((idx, r))

    now = _now()
    max_delta = timedelta(minutes=max_delta_minutes)

    for lg_idx, lg in logons.iterrows():
        if not bool(lg.get("is_recent", False)):
            continue

        u = _clean(lg.get("user"))
        lg_time = lg.get("timestamp")
        if not u or pd.isna(lg_time) or u not in resets_by_user:
            continue

        best_reset = None
        best_reset_idx = None
        best_dt = None

        for rr_idx, rr in resets_by_user[u]:
            rr_time = rr.get("timestamp")
            if pd.isna(rr_time) or rr_time > lg_time:
                continue
            dt = lg_time - rr_time
            if best_dt is None or dt < best_dt:
                best_dt = dt
                best_reset = rr
                best_reset_idx = rr_idx

        if best_reset is None or best_dt is None or best_dt > max_delta:
            continue

        delta_sec = best_dt.total_seconds()
        trusted_action = _is_likely_legit_action(best_reset)

        if delta_sec <= 120:
            base_score = 86.0
        elif delta_sec <= 300:
            base_score = 78.0
        else:
            base_score = 68.0

        legit_reduction = 8.0 if trusted_action else 0.0
        ctx_suspicious = (
            _suspicious_context(lg) or
            _suspicious_context(best_reset) or
            delta_sec <= 120
        )

        ml_risk, ml_label, ml_anom = _pick_ml_from_rows(lg, best_reset)
        soc, score_details = _build_score_details(
            base_score=base_score,
            ml_risk=ml_risk,
            ctx_suspicious=ctx_suspicious,
            ml_anom=ml_anom,
            correlation_bonus=10.0,
            legit_reduction=legit_reduction,
        )
        severity = _severity_from_score(soc)

        alerts.append({
            "@timestamp": now.isoformat(),
            "source": "soc-ai",
            "alert_type": "ad_account_takeover_suspected",
            "rule_level": _level_from_severity(severity),
            "title": f"[{severity}] Reset → Logon: {u}",
            "description": f"Password reset (4724) puis logon success (4624) en {best_dt}. Possibilité de prise de compte.",
            "severity": severity,
            "soc_score": soc,
            "mitre_attack": _mitre_for_correlation("reset_then_logon"),
            "event_id": "CORRELATED",
            "event_ids": ["4724", "4624"],
            "user": str(u),
            "target_user": str(u),
            "subject_user": _clean(best_reset.get("subject_user")),
            "ip": str(_clean(lg.get("ip")) or _clean(best_reset.get("ip")) or "0.0.0.0"),
            "host": str(_clean(lg.get("host")) or _clean(best_reset.get("host")) or "unknown"),
            "ctx_suspicious": bool(ctx_suspicious),
            "ml_label": ml_label,
            "ml_risk": ml_risk,
            "ml_anomaly": bool(ml_anom),
        })

        consumed.add(lg_idx)
        if best_reset_idx is not None:
            consumed.add(best_reset_idx)

    return alerts, consumed


# ========= Main =========
def run(context):
    df = context.df
    if df is None or df.empty:
        return []

    alerts = []
    now = _now()

    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df["event_id"] = df["event_id"].astype(str)
    df = _add_recent_flag(df, context)

    df_features = getattr(context, "features", None)
    df_ml = _ml_score_batch(context, df_features)

    if df_ml is not None and not df_ml.empty:
        df = df.join(df_ml)
    else:
        df["ml_anomaly"] = False
        df["ml_risk"] = None
        df["ml_label"] = None

    consumed = set()
    best_4625_alerts = {}

    cd_alerts, cd_consumed = _correlate_create_delete(df, max_delta_minutes=2)
    alerts.extend(cd_alerts)
    consumed |= cd_consumed

    rl_alerts, rl_consumed = _correlate_reset_then_logon(df, max_delta_minutes=10)
    alerts.extend(rl_alerts)
    consumed |= rl_consumed

    for idx, row in df.iterrows():
        if idx in consumed:
            continue

        event_id = str(row.get("event_id") or "").strip()
        if not event_id:
            continue

        user = _clean(row.get("user")) or _clean(row.get("target_user")) or "unknown"
        if _is_machine_account(str(user)):
            continue

        ctx_suspicious = _suspicious_context(row)
        ml_risk = _safe_float(row.get("ml_risk"))
        ml_label = row.get("ml_label")
        ml_anom = bool(row.get("ml_anomaly"))

        severity = None
        base_score = None
        legit_reduction = 0.0

        if _is_likely_legit_action(row):
            legit_reduction += 8.0

        acct = _account_category(user)
        if acct == "test":
            legit_reduction += 8.0
        elif acct == "service":
            legit_reduction += 4.0

        # ===== GROUP EVENTS CORRIGES =====
        if event_id in GROUP_ADD_EVENTS:
            if not bool(row.get("is_recent", False)):
                continue

            raw_group_name = _clean(row.get("group_name"))
            raw_member_user = _clean(row.get("member_user"))
            raw_target_user = _clean(row.get("target_user"))
            raw_user = _clean(row.get("user"))

            sid_to_group = {
                "-512": "Admins du domaine",
                "-519": "Administrateurs de l’entreprise",
                "-518": "Administrateurs du schéma",
                "-544": "Administrateurs",
            }

            group_name = raw_group_name
            if group_name and group_name.startswith("S-1-5-"):
                for suffix, friendly_name in sid_to_group.items():
                    if group_name.endswith(suffix):
                        group_name = friendly_name
                        break

            member_user = raw_member_user or "unknown_member"

            if group_name and member_user and str(member_user).strip().lower() == str(group_name).strip().lower():
                member_user = "unknown_member"

            if _is_bad_member_candidate(member_user):
                member_user = "unknown_member"

            # ===== INFERENCE DU USER ESCALADE =====
            if member_user == "unknown_member":
                current_ts = row.get("timestamp")
                current_host = _clean(row.get("host"))

                if pd.notna(current_ts):
                    window_start = current_ts - timedelta(minutes=5)

                    candidates = df[
                        (df["timestamp"] >= window_start) &
                        (df["timestamp"] <= current_ts)
                    ].copy()

                    if current_host:
                        candidates = candidates[candidates["host"] == current_host]

                    # 1) priorite au dernier compte cree
                    created_candidates = candidates[candidates["event_id"] == CREATE_EVENT]
                    if not created_candidates.empty:
                        last_created = created_candidates.sort_values("timestamp").iloc[-1]
                        cand_user = _clean(last_created.get("target_user")) or _clean(last_created.get("user"))
                        if cand_user and not _is_bad_member_candidate(cand_user):
                            member_user = cand_user

                    # 2) sinon dernier user humain pertinent vu sur l'hote
                    if member_user == "unknown_member":
                        generic_candidates = candidates.sort_values("timestamp", ascending=False)

                        for _, cand in generic_candidates.iterrows():
                            cand_user = _clean(cand.get("target_user")) or _clean(cand.get("user"))
                            if cand_user and not _is_bad_member_candidate(cand_user):
                                member_user = cand_user
                                break

            soc, _ = _build_score_details(
                base_score=85.0,
                ml_risk=ml_risk,
                ctx_suspicious=True,
                ml_anom=ml_anom,
                correlation_bonus=5.0,
                legit_reduction=0.0,
            )
            severity = _severity_from_score(soc)

            alerts.append({
                "@timestamp": now.isoformat(),
                "source": "soc-ai",
                "alert_type": "ad_privilege_escalation_direct",
                "title": f"[{severity}] Ajout à groupe privilégié: {group_name or 'groupe inconnu'}",
                "description": (
                    f"Event {event_id} détecté. "
                    f"group_name={group_name}, member_user={member_user}, "
                    f"raw_group_name={raw_group_name}, raw_member_user={raw_member_user}"
                ),
                "severity": severity,
                "rule_level": _level_from_severity(severity),
                "soc_score": soc,
                "mitre_attack": _mitre_for_event(event_id),
                "event_id": event_id,
                "user": str(member_user),
                "target_user": member_user,
                "subject_user": _clean(row.get("subject_user")),
                "ip": str(_clean(row.get("ip")) or "0.0.0.0"),
                "host": str(_clean(row.get("host")) or "unknown"),
                "workstation": _clean(row.get("workstation")),
                "group_name": group_name,
                "member_user": member_user,
                "ctx_suspicious": True,
                "ml_label": ml_label,
                "ml_risk": ml_risk,
                "ml_anomaly": bool(ml_anom),
            })
            continue

        # ===== AUTRES EVENTS =====
        if not bool(row.get("is_recent", False)):
            continue

        if event_id == "1102":
            severity = "CRITICAL"
            base_score = 90.0

        elif event_id == DELETE_EVENT:
            severity = "HIGH"
            base_score = 75.0
            if ctx_suspicious or ml_anom:
                base_score = 80.0

        elif event_id == PASSWORD_RESET_EVENT:
            severity = "HIGH"
            base_score = 74.0
            if ctx_suspicious or ml_anom:
                base_score = 80.0

        elif event_id == PRIV_EVENT:
            if str(user).lower() in {"administrateur", "administrator"} and not (ctx_suspicious or ml_anom):
                continue
            severity = "MEDIUM"
            base_score = 60.0
            if ctx_suspicious or ml_anom:
                severity = "HIGH"
                base_score = 72.0

        elif event_id in WATCH_EVENT_IDS:
            if not (ctx_suspicious or ml_anom):
                continue

            severity = "MEDIUM"
            base_score = 58.0

            details = _context_details(row)
            if details["success_after_fail"] == 1:
                base_score = 62.0
                severity = "HIGH"
            elif details["failures_5min"] >= 10:
                base_score = 60.0
            elif details["unique_ips_user"] >= 4 or details["unique_hosts_user"] >= 4:
                base_score = 60.0

        elif event_id == CREATE_EVENT:
            severity = "MEDIUM"
            base_score = 55.0
            if ctx_suspicious or ml_anom:
                severity = "HIGH"
                base_score = 68.0

        else:
            continue

        soc, score_details = _build_score_details(
            base_score=base_score,
            ml_risk=ml_risk,
            ctx_suspicious=ctx_suspicious,
            ml_anom=ml_anom,
            correlation_bonus=0.0,
            legit_reduction=legit_reduction,
        )

        severity = (
            _severity_from_score(soc)
            if event_id != PRIV_EVENT
            else max(
                severity,
                _severity_from_score(soc),
                key=lambda s: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(s)
            )
        )

        alert_obj = {
            "@timestamp": now.isoformat(),
            "source": "soc-ai",
            "alert_type": "ad_soc_ml_pro",
            "title": f"[{severity}] {_event_desc(event_id)}: {user}",
            "description": _event_desc(event_id),
            "severity": severity,
            "rule_level": _level_from_severity(severity),
            "soc_score": soc,
            "mitre_attack": _mitre_for_event(event_id),
            "event_id": event_id,
            "user": str(user),
            "target_user": _clean(row.get("target_user")),
            "subject_user": _clean(row.get("subject_user")),
            "ip": str(_clean(row.get("ip")) or "0.0.0.0"),
            "host": str(_clean(row.get("host")) or "unknown"),
            "workstation": _clean(row.get("workstation")),
            "group_name": _clean(row.get("group_name")),
            "member_user": _clean(row.get("member_user")),
            "ctx_suspicious": bool(ctx_suspicious),
            "ml_label": ml_label,
            "ml_risk": ml_risk,
            "ml_anomaly": bool(ml_anom),
        }

        if event_id == "4625":
            existing = best_4625_alerts.get(user)
            if existing is None or alert_obj["soc_score"] > existing["soc_score"]:
                best_4625_alerts[user] = alert_obj
        else:
            alerts.append(alert_obj)

    alerts.extend(best_4625_alerts.values())
    return alerts