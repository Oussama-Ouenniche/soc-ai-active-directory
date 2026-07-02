"""SOC-AI application entry point."""

import logging
from pathlib import Path

from collectors.wazuh_ad import get_client, extract_ad_events
from features.ad_features import build_features
from core.context import SOCContext
from core.engine import run_engine
from responders.opensearch import push_alerts
from config.settings import SOCConfig


def configure_logging(log_file: str) -> None:
    """Configure file and console logging for a local run."""
    log_path = Path(log_file)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            handlers=[
                logging.FileHandler(log_path, encoding="utf-8"),
                logging.StreamHandler(),
            ],
        )
    except OSError:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        )


def main() -> None:
    config = SOCConfig()
    configure_logging(config.LOG_FILE)

    client = get_client(config)
    df = extract_ad_events(client, config)

    if df.empty:
        logging.info("No relevant Active Directory events were found in the selected window.")
        return

    df, features = build_features(df)

    context = SOCContext(
        df=df,
        features=features,
        client=client,
        config=config,
    )

    alerts = run_engine(context)
    context.alerts = alerts
    push_alerts(context)

    logging.info("SOC-AI run complete: %s alert(s) generated.", len(alerts))


if __name__ == "__main__":
    main()
