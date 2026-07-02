# core/engine.py

import logging
from core.loader import load_detection_modules

def run_engine(context):
    alerts = []

    for module in load_detection_modules():
        try:
            module_alerts = module.run(context)
            alerts.extend(module_alerts)
        except Exception as e:
            logging.error(f"Detection {module.__name__} failed: {e}")

    return alerts

"""
import os
import importlib

def run_engine(context):
    alerts = []

    detections_path = "detections"

    for file in os.listdir(detections_path):
        if file.endswith(".py") and file != "__init__.py":
            module_name = f"detections.{file[:-3]}"
            module = importlib.import_module(module_name)

            if hasattr(module, "run"):
                alerts += module.run(context)

    return alerts


"""