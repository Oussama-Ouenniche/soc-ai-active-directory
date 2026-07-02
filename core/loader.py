# core/loader.py

import importlib
import pkgutil
import detections

def load_detection_modules():
    modules = []

    for _, name, _ in pkgutil.iter_modules(detections.__path__):
        module = importlib.import_module(f"detections.{name}")
        if hasattr(module, "run"):
            modules.append(module)

    return modules
