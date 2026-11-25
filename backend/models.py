"""Load the release models once and evaluate an operator-supplied flow."""

import logging
import math
from importlib import import_module
from threading import Lock

from ai.features.feature_contract import FEATURE_NAMES, FlowFeatureVector
from ai.models.release import BILSTM_FILE, ISOLATION_FOREST_FILE, XGBOOST_FILE


LOGGER = logging.getLogger(__name__)
MODELS = {
    "xgboost": ("XGBoost", XGBOOST_FILE, "xgboost_classifier", "XGBoostThreatClassifier"),
    "bilstm": ("Bi-LSTM", BILSTM_FILE, "bilstm_classifier", "BiLSTMThreatClassifier"),
    "isolation_forest": (
        "Isolation Forest", ISOLATION_FOREST_FILE, "isolation_forest", "IsolationForestDetector"
    ),
}


def parse_features(payload):
    if not isinstance(payload, dict) or set(payload) != set(FEATURE_NAMES):
        raise ValueError("Provide all six flow measurements.")

    features = {}
    for name in FEATURE_NAMES:
        value = payload[name]
        if type(value) not in (int, float) or not 0 <= value <= 3.4028234663852886e38:
            raise ValueError(f"{name} must be a finite, nonnegative number in the model's range.")
        if name in ("packet_count", "byte_count") and int(value) != value:
            raise ValueError(f"{name} must be a whole number.")
        features[name] = float(value)
    return FlowFeatureVector(features=features, is_valid=True)


class ReleaseModels:
    def __init__(self, directory):
        self.models = {}
        self.status = {}
        self.lock = Lock()
        for key, (name, filename, module, class_name) in MODELS.items():
            path = directory / filename
            message = f"Missing {filename}."
            if path.is_file():
                try:
                    if key == "bilstm":
                        import torch

                        # The console scores one flow at a time on this process.
                        torch.set_num_threads(1)
                    classifier = getattr(import_module(f"ai.models.{module}"), class_name)
                    model = classifier(model_path=str(path))
                    if model.load():
                        self.models[key] = model
                        self.status[key] = {
                            "name": name, "ready": True, "version": model.model_version,
                        }
                        continue
                    message = "Model could not be loaded. Check the backend log."
                except ImportError as error:
                    LOGGER.warning("%s dependencies unavailable: %s", name, error)
                    message = "Model dependencies are unavailable. See the setup guide."
                except Exception:
                    LOGGER.exception("%s could not be loaded", name)
                    message = "Model could not be loaded. Check the backend log."
            self.status[key] = {"name": name, "ready": False, "message": message}

    def check(self, features):
        if not self.models:
            return {}

        vector = features.to_array()
        results = {}
        for key, model in self.models.items():
            try:
                prediction = model.predict(vector)
                if key == "isolation_forest":
                    label = "unusual" if prediction.is_anomalous else "within_baseline"
                    result = {"label": label, "anomaly_score": prediction.anomaly_score}
                else:
                    result = {
                        "label": prediction.predicted_label,
                        "confidence": prediction.max_probability,
                    }
                if not all(math.isfinite(value) for value in result.values() if isinstance(value, float)):
                    raise ValueError("Model returned a nonfinite score.")
                results[key] = {**result, "version": prediction.model_version}
            except Exception:
                LOGGER.exception("%s inference failed", key)
        return results
