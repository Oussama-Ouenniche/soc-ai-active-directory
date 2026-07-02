# core/context.py

from typing import List, Dict, Any

class SOCContext:
    def __init__(self, df, features, client, config):
        self.df = df
        self.features = features
        self.client = client
        self.alerts: List[Dict[str, Any]] = []
        self.config = config

