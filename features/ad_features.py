import pandas as pd

# === Liste officielle des features AD ===
AD_FEATURE_COLUMNS = [
    "hour",
    "failures_5min",
    "unique_ips_user",
    "unique_hosts_user",
    "success_after_fail"
]

def build_features(df: pd.DataFrame):
    df = df.copy()

    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df.sort_values(["user", "timestamp"], inplace=True)
    df.reset_index(drop=True, inplace=True)

    df["hour"] = df["timestamp"].dt.hour
    df["is_failed"] = df["auth_failed"]
    df["is_success"] = (df["event_id"] == "4624").astype(int)

    df["failures_5min"] = 0.0

    for user, g in df.groupby("user", sort=False):
        df.loc[g.index, "failures_5min"] = (
            g.set_index("timestamp")["is_failed"]
            .rolling("5min")
            .sum()
            .fillna(0)
            .values
        )

    df["bruteforce_flag"] = (df["failures_5min"] >= 10).astype(int)
    df["unique_ips_user"] = df.groupby("user")["ip"].transform("nunique")
    df["unique_hosts_user"] = df.groupby("user")["host"].transform("nunique")

    df["success_after_fail"] = (
        (df["is_success"] == 1) & (df["bruteforce_flag"] == 1)
    ).astype(int)

    return df, df[AD_FEATURE_COLUMNS]

