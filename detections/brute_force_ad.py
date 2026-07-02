# detections/brute_force_ad.py

from datetime import datetime, timezone, timedelta

def run(context):
    df = context.df
    alerts = []

    if df.empty:
        return []

    now = datetime.now(timezone.utc)
    window_minutes = int(getattr(context.config, "ALERT_WINDOW_MINUTES", 5))
    cutoff = now - timedelta(minutes=window_minutes)

    bf = df[df["failures_5min"] >= 10]

    if bf.empty:
        return []

    summary = bf.groupby("user").agg(
        failures_max=("failures_5min", "max"),
        ips=("ip", lambda x: list(set(x))),
        hosts=("host", lambda x: list(set(x))),
        last_seen=("timestamp", "max")
    ).reset_index()

    for _, r in summary.iterrows():

        # 🚨 Ignore les attaques anciennes
        if r["last_seen"] < cutoff:
            continue

        alerts.append({
            "@timestamp": now.isoformat(),
            "alert_type": "brute_force",
            "severity": "HIGH" if r["failures_max"] >= 20 else "MEDIUM",
            "user": r["user"],
            "failures_5min": int(r["failures_max"]),
            "ips": r["ips"],
            "hosts": r["hosts"],
            "last_seen": r["last_seen"].isoformat(),
            "mitre": "T1110",
            "source": "soc-ai"
        })

    return alerts