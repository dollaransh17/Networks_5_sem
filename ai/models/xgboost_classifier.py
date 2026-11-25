"""
ai/models/xgboost_classifier.py

Phase 4.3: XGBoost Multi-class Threat Classifier
References: PRD (Section 5, Phase 4), DESIGN.md, AGENTS.md, ARCHITECTURE.md, DATABASE.md

Key Constraints (AGENTS.md):
- Do NOT put AI inference inside Ryu's event loop.
- Do NOT invent metrics, latencies, or accuracy. Report actual evaluation metrics only.
- Do NOT use future data at decision time (feature contract is frozen).
- Model is trained once from labelled InSDN data, saved as a .pkl file.
- At inference time, the classifier returns class probabilities + predicted label.
- If model file is missing, inference returns None (not a fake score).

Training split: time-ordered train/test to avoid future data leakage.
  - 80% of rows (in original order) → training
  - 20% of rows (in original order, later data) → test
"""

import os
import pickle
import logging
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any
import numpy as np

from ai.features.feature_contract import FEATURE_NAMES
from ai.models.release import RELEASE_VERSION, XGBOOST_FILE, load_preprocessing

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MODEL_SAVE_PATH = os.path.join(os.path.dirname(__file__), "xgboost_model.pkl")
METADATA_SAVE_PATH = os.path.join(os.path.dirname(__file__), "xgboost_metadata.json")

# Class labels in fixed order (must match encoder)
CLASS_LABELS: List[str] = ["benign", "dos", "portscan", "bruteforce"]


@dataclass
class XGBPrediction:
    """Result of a single inference call."""
    predicted_label: str
    probabilities: Dict[str, float]      # {label: probability}
    max_probability: float
    model_version: str
    inference_time_s: Optional[float] = None  # actual elapsed time


@dataclass
class XGBTrainResult:
    """Actual measured evaluation results after training."""
    accuracy: Optional[float] = None           # None until measured
    per_class_f1: Optional[Dict[str, float]] = None
    n_train: int = 0
    n_test: int = 0
    train_duration_s: Optional[float] = None
    model_version: str = "unset"
    feature_names: List[str] = field(default_factory=list)
    class_distribution_train: Optional[Dict[str, int]] = None
    class_distribution_test: Optional[Dict[str, int]] = None


class XGBoostThreatClassifier:
    """
    Wraps an XGBoost multi-class classifier for mid-flow SDN telemetry.

    Usage:
        clf = XGBoostThreatClassifier()
        result = clf.train(X_train, y_train, X_test, y_test)
        clf.save()
        pred = clf.predict(feature_vector)
    """

    def __init__(self, model_path: str = MODEL_SAVE_PATH):
        self._model = None
        self._label_encoder = None
        self._model_path = model_path
        self._model_version: str = "not_loaded"
        self._feature_names: List[str] = []

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(
        self,
        X_train: np.ndarray,
        y_train: List[str],
        X_test: np.ndarray,
        y_test: List[str],
        n_estimators: int = 200,
        max_depth: int = 6,
        learning_rate: float = 0.1,
        random_state: int = 42,
        feature_names: Optional[List[str]] = None,
    ) -> XGBTrainResult:
        """
        Trains the XGBoost classifier with time-ordered splits (caller must
        ensure X_train comes from earlier data than X_test).

        Args:
            X_train: Training feature matrix (n_samples, 6)
            y_train: Training labels (string class names)
            X_test:  Held-out test matrix
            y_test:  Held-out test labels
            n_estimators: Number of boosting rounds
            max_depth: Max tree depth
            learning_rate: Boosting learning rate (eta)
            random_state: Seed for reproducibility
            feature_names: Optional list of feature names for SHAP/logging

        Returns:
            XGBTrainResult with ACTUAL measured accuracy, f1, and counts.
        """
        try:
            from xgboost import XGBClassifier
            from sklearn.preprocessing import LabelEncoder
            from sklearn.metrics import accuracy_score, f1_score
            from collections import Counter
        except ImportError as e:
            raise ImportError(
                f"Required package missing: {e}. "
                "Run: pip install xgboost scikit-learn"
            )

        result = XGBTrainResult(
            n_train=len(y_train),
            n_test=len(y_test),
            feature_names=feature_names or [],
        )

        # Encode string labels → integers based on the classes present in y_train
        self._label_encoder = LabelEncoder()
        train_classes = sorted(list(set(y_train)))
        self._label_encoder.fit(train_classes)

        y_train_enc = self._label_encoder.transform(y_train)

        # Filter test set for eval_set to only contain classes present in training
        valid_test_idx = [i for i, y in enumerate(y_test) if y in train_classes]
        if valid_test_idx:
            X_eval = X_test[valid_test_idx]
            y_eval_enc = self._label_encoder.transform([y_test[i] for i in valid_test_idx])
            eval_data = [(X_eval, y_eval_enc)]
        else:
            eval_data = None

        # Class distribution (for the record — do not fake)
        result.class_distribution_train = dict(Counter(y_train))
        result.class_distribution_test  = dict(Counter(y_test))

        logger.info(
            "[XGB] Training on %d samples (%s classes) | test: %d samples",
            len(y_train), len(self._label_encoder.classes_), len(y_test)
        )

        # Compute scale_pos_weight for binary; for multiclass use sample_weight
        # Build class weights inversely proportional to frequency (imbalance handling)
        from collections import Counter as _Counter
        counts = _Counter(y_train)
        total = len(y_train)
        # sample_weight array: weight[i] = total / (n_classes * count[class_i])
        n_classes = len(counts)
        sample_weight = np.array([
            total / (n_classes * counts[label]) for label in y_train
        ], dtype=np.float32)

        # Actual training with timing
        self._model = XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            use_label_encoder=False,
            eval_metric="mlogloss",
            random_state=random_state,
            n_jobs=-1,            # Use all available cores
            verbosity=0,
        )

        t_start = time.monotonic()
        fit_kwargs = {"sample_weight": sample_weight, "verbose": False}
        if eval_data is not None:
            fit_kwargs["eval_set"] = eval_data
        self._model.fit(X_train, y_train_enc, **fit_kwargs)
        t_end = time.monotonic()

        result.train_duration_s = t_end - t_start

        # Evaluate on held-out test data (ACTUAL metrics, never fabricated)
        y_pred_enc = self._model.predict(X_test)
        y_pred     = self._label_encoder.inverse_transform(y_pred_enc)

        result.accuracy = float(accuracy_score(y_test, y_pred))

        # Per-class F1 (macro across all present classes)
        f1_scores = f1_score(
            y_test, y_pred,
            labels=list(self._label_encoder.classes_),
            average=None,
            zero_division=0,
        )
        result.per_class_f1 = {
            cls: float(f1_scores[i])
            for i, cls in enumerate(self._label_encoder.classes_)
        }

        self._feature_names = feature_names or []
        self._model_version = f"xgb-{int(time.time())}"
        result.model_version = self._model_version

        logger.info(
            "[XGB] Training complete: accuracy=%.4f | duration=%.2fs",
            result.accuracy, result.train_duration_s
        )
        for cls, f1 in result.per_class_f1.items():
            logger.info("  F1[%s] = %.4f", cls, f1)

        return result

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: Optional[str] = None) -> str:
        """Saves model + encoder + metadata as a pickle bundle."""
        import json
        save_path = path or self._model_path
        if self._model is None:
            raise RuntimeError("No trained model to save. Call train() first.")

        bundle = {
            "model": self._model,
            "label_encoder": self._label_encoder,
            "model_version": self._model_version,
            "feature_names": self._feature_names,
        }
        with open(save_path, "wb") as f:
            pickle.dump(bundle, f, protocol=pickle.HIGHEST_PROTOCOL)

        logger.info("[XGB] Model saved to %s", save_path)
        return save_path

    def load(self, path: Optional[str] = None) -> bool:
        """
        Loads a saved model bundle.  Returns True if loaded successfully,
        False if file does not exist.  Never raises for missing file.
        """
        load_path = path or self._model_path
        if not os.path.exists(load_path):
            logger.warning("[XGB] Model file not found at %s", load_path)
            return False

        with open(load_path, "rb") as f:
            bundle = pickle.load(f)

        if os.path.basename(load_path) == XGBOOST_FILE and not isinstance(bundle, dict):
            bundle = {
                "model": bundle,
                "label_encoder": load_preprocessing(load_path)["encoder"],
                "model_version": RELEASE_VERSION,
                "feature_names": FEATURE_NAMES.copy(),
            }

        self._model = bundle["model"]
        self._label_encoder = bundle["label_encoder"]
        self._model_version = bundle.get("model_version", "unknown")
        self._feature_names = bundle.get("feature_names", [])
        logger.info("[XGB] Model loaded from %s (version=%s)", load_path, self._model_version)
        return True

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict(self, feature_vector: np.ndarray) -> Optional[XGBPrediction]:
        """
        Runs inference on a single 1D feature vector.

        Returns None if model is not loaded (never a fake score).
        Uses actual elapsed time for inference_time_s.
        """
        if self._model is None or self._label_encoder is None:
            logger.warning("[XGB] Model not loaded. Returning None.")
            return None

        t0 = time.monotonic()

        # Reshape to (1, n_features) for sklearn API
        X = feature_vector.reshape(1, -1).astype(np.float32)

        proba = self._model.predict_proba(X)[0]  # shape (n_classes,)
        pred_idx = int(np.argmax(proba))
        pred_label = self._label_encoder.inverse_transform([pred_idx])[0]

        # Build probability dict keyed by class name
        proba_dict = {
            cls: float(proba[i])
            for i, cls in enumerate(self._label_encoder.classes_)
        }
        # Add zero probability for any CLASS_LABELS not in encoder
        for lbl in CLASS_LABELS:
            if lbl not in proba_dict:
                proba_dict[lbl] = 0.0

        t1 = time.monotonic()

        return XGBPrediction(
            predicted_label=str(pred_label),
            probabilities=proba_dict,
            max_probability=float(proba[pred_idx]),
            model_version=self._model_version,
            inference_time_s=t1 - t0,   # actual elapsed, not hardcoded
        )

    @property
    def is_loaded(self) -> bool:
        return self._model is not None

    @property
    def model_version(self) -> str:
        return self._model_version

    @property
    def classes(self) -> List[str]:
        if self._label_encoder is None:
            return []
        return list(self._label_encoder.classes_)

