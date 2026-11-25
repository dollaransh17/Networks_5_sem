"""
ai/models/isolation_forest.py

Phase 4.4: Isolation Forest Anomaly Detector
References: PRD (Section 5, Phase 4), DESIGN.md, AGENTS.md, ARCHITECTURE.md

Key Constraints (AGENTS.md):
- Trained on BENIGN-ONLY traffic as a baseline deviation detector.
- If model file is missing, inference returns None (not a fake score).
- Do NOT put inference inside Ryu's event loop.
- Do NOT invent anomaly scores or thresholds. Report actual values.
- Contamination parameter is explicitly configurable (default 0.05, i.e. 5%).
- Both XGBoost AND Isolation Forest must agree before broad quarantine action is approved.

Anomaly Score convention (sklearn Isolation Forest):
  - sklearn returns: score = -1 * raw isolation score, in range roughly [-0.5, 0.5]
  - More negative  = more anomalous
  - We expose: anomaly_score (raw sklearn), and is_anomalous (bool: score < threshold)
  - Default decision threshold: sklearn's built-in (contamination fraction).
"""

import os
import pickle
import logging
import time
from dataclasses import dataclass
from typing import Optional, List
import numpy as np

from ai.models.release import ISOLATION_FOREST_FILE, RELEASE_VERSION, load_preprocessing

logger = logging.getLogger(__name__)

MODEL_SAVE_PATH = os.path.join(os.path.dirname(__file__), "iforest_model.pkl")


@dataclass
class IForestPrediction:
    """Result of a single Isolation Forest inference call."""
    is_anomalous: bool
    anomaly_score: float          # sklearn decision_function output (more negative = more anomalous)
    raw_label: int                # -1 = anomaly, 1 = normal (sklearn convention)
    model_version: str
    contamination: float          # configured contamination fraction
    inference_time_s: Optional[float] = None


@dataclass
class IForestTrainResult:
    """Actual measured results from training the Isolation Forest."""
    n_train_benign: int = 0
    contamination: float = 0.05
    n_estimators: int = 100
    max_samples: str = "auto"
    train_duration_s: Optional[float] = None
    model_version: str = "unset"
    # We do NOT report accuracy here because IForest is unsupervised on benign data only.
    # Evaluation on labelled data is done externally via verify scripts.


class IsolationForestDetector:
    """
    Wraps sklearn's IsolationForest for OVS flow anomaly detection.

    Training: fit ONLY on benign-labelled samples to build a baseline.
    Inference: score any new sample against that baseline.

    Usage:
        ifd = IsolationForestDetector(contamination=0.05)
        result = ifd.train(X_benign)
        ifd.save()
        pred = ifd.predict(feature_vector)
    """

    def __init__(
        self,
        contamination: float = 0.05,
        model_path: str = MODEL_SAVE_PATH,
    ):
        """
        Args:
            contamination: Expected proportion of anomalies in the training data
                           (must be in (0, 0.5]).  Default 5%.
                           Lower = tighter boundary = more false positives.
            model_path: Where to save/load the model pickle.
        """
        if not (0 < contamination <= 0.5):
            raise ValueError(f"contamination must be in (0, 0.5], got {contamination}")

        self._model = None
        self._scaler = None
        self._contamination = contamination
        self._model_path = model_path
        self._model_version: str = "not_loaded"

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(
        self,
        X_benign: np.ndarray,
        n_estimators: int = 100,
        max_samples: str = "auto",
        random_state: int = 42,
    ) -> IForestTrainResult:
        """
        Trains on BENIGN-ONLY samples to learn the normal traffic baseline.

        Args:
            X_benign: Feature matrix of benign-labelled samples (n, 6)
            n_estimators: Number of trees in the forest
            max_samples: Samples per tree ('auto' = min(256, n_samples))
            random_state: Random seed for reproducibility

        Returns:
            IForestTrainResult with ACTUAL training metadata.
        """
        try:
            from sklearn.ensemble import IsolationForest as _IForest
        except ImportError:
            raise ImportError(
                "scikit-learn is required. Run: pip install scikit-learn"
            )

        result = IForestTrainResult(
            n_train_benign=len(X_benign),
            contamination=self._contamination,
            n_estimators=n_estimators,
            max_samples=max_samples,
        )

        logger.info(
            "[IForest] Training on %d benign samples | contamination=%.3f | estimators=%d",
            len(X_benign), self._contamination, n_estimators
        )

        self._model = _IForest(
            n_estimators=n_estimators,
            max_samples=max_samples,
            contamination=self._contamination,
            random_state=random_state,
            n_jobs=-1,
        )

        t_start = time.monotonic()
        self._model.fit(X_benign)
        self._scaler = None
        t_end = time.monotonic()

        result.train_duration_s = t_end - t_start
        self._model_version = f"iforest-{int(time.time())}"
        result.model_version = self._model_version

        logger.info(
            "[IForest] Training complete: %.2fs on %d samples",
            result.train_duration_s, len(X_benign)
        )
        return result

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: Optional[str] = None) -> str:
        """Saves the trained model as a pickle file."""
        save_path = path or self._model_path
        if self._model is None:
            raise RuntimeError("No trained model to save. Call train() first.")

        bundle = {
            "model": self._model,
            "contamination": self._contamination,
            "model_version": self._model_version,
        }
        if self._scaler is not None:
            bundle["scaler"] = self._scaler
        with open(save_path, "wb") as f:
            pickle.dump(bundle, f, protocol=pickle.HIGHEST_PROTOCOL)

        logger.info("[IForest] Model saved to %s", save_path)
        return save_path

    def load(self, path: Optional[str] = None) -> bool:
        """
        Loads a saved model.  Returns True if loaded, False if file not found.
        Never raises for missing file (returns None-safe prediction instead).
        """
        load_path = path or self._model_path
        if not os.path.exists(load_path):
            logger.warning("[IForest] Model file not found at %s", load_path)
            return False

        with open(load_path, "rb") as f:
            bundle = pickle.load(f)

        if os.path.basename(load_path) == ISOLATION_FOREST_FILE and not isinstance(bundle, dict):
            bundle = {
                "model": bundle,
                "contamination": bundle.contamination,
                "model_version": RELEASE_VERSION,
                "scaler": load_preprocessing(load_path)["scaler"],
            }

        self._model = bundle["model"]
        self._contamination = bundle.get("contamination", 0.05)
        self._model_version = bundle.get("model_version", "unknown")
        self._scaler = bundle.get("scaler")
        logger.info("[IForest] Model loaded from %s (version=%s)", load_path, self._model_version)
        return True

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict(self, feature_vector: np.ndarray) -> Optional[IForestPrediction]:
        """
        Scores a single 1D feature vector.

        Returns:
            IForestPrediction — or None if model is not loaded.
            Never returns a fake score.
        """
        if self._model is None:
            logger.warning("[IForest] Model not loaded. Returning None.")
            return None

        t0 = time.monotonic()
        X = feature_vector.reshape(1, -1).astype(np.float32)
        if self._scaler is not None:
            X = self._scaler.transform(X)

        # decision_function: more negative = more anomalous
        anomaly_score = float(self._model.decision_function(X)[0])
        raw_label     = int(self._model.predict(X)[0])  # -1 or 1
        is_anomalous  = (raw_label == -1)

        t1 = time.monotonic()

        return IForestPrediction(
            is_anomalous=is_anomalous,
            anomaly_score=anomaly_score,
            raw_label=raw_label,
            model_version=self._model_version,
            contamination=self._contamination,
            inference_time_s=t1 - t0,   # actual elapsed time
        )

    # ------------------------------------------------------------------
    # Batch evaluation (for external verify scripts)
    # ------------------------------------------------------------------

    def evaluate(self, X: np.ndarray, y_true_binary: List[int]) -> dict:
        """
        Evaluates the model on labelled data where y_true_binary[i] = 1 (normal) or -1 (anomaly).
        Returns actual precision, recall, f1 for the anomaly class.
        Never fabricates numbers; returns None if model not loaded.
        """
        if self._model is None:
            return {"error": "model_not_loaded"}

        try:
            from sklearn.metrics import precision_score, recall_score, f1_score
        except ImportError:
            return {"error": "scikit-learn not installed"}

        X = X.astype(np.float32)
        if self._scaler is not None:
            X = self._scaler.transform(X)
        y_pred = self._model.predict(X)

        # sklearn iforest uses -1=anomaly, 1=normal
        prec  = float(precision_score(y_true_binary, y_pred, pos_label=-1, zero_division=0))
        rec   = float(recall_score(y_true_binary, y_pred, pos_label=-1, zero_division=0))
        f1    = float(f1_score(y_true_binary, y_pred, pos_label=-1, zero_division=0))

        return {
            "anomaly_precision": prec,
            "anomaly_recall": rec,
            "anomaly_f1": f1,
            "n_samples": len(y_true_binary),
            "n_predicted_anomaly": int(np.sum(y_pred == -1)),
        }

    @property
    def is_loaded(self) -> bool:
        return self._model is not None

    @property
    def model_version(self) -> str:
        return self._model_version

    @property
    def contamination(self) -> float:
        return self._contamination

