"""
ai/models/bilstm_classifier.py

Phase 4.5: PyTorch Bidirectional LSTM (Bi-LSTM) Threat Classifier
References: PRD (Section 5, Phase 4), ARCHITECTURE.md, AGENTS.md, DATABASE.md

Key Constraints (AGENTS.md):
- Do NOT put AI inference inside Ryu's event loop.
- Do NOT invent metrics, latencies, or accuracy. Report actual evaluation metrics only.
- Feature contract is frozen: exactly 6 features.
- If model file is missing, inference returns None (never a fake score).
- Robust feature scaling (StandardScaler) to prevent neural network gradient instability.
- Class-weighted Cross-Entropy loss to handle severe NIDS class imbalance.
"""

import os
import time
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any
import numpy as np

from ai.models.release import BILSTM_FILE, RELEASE_VERSION, load_preprocessing

logger = logging.getLogger(__name__)

MODEL_SAVE_PATH = os.path.join(os.path.dirname(__file__), "bilstm_model.pt")

# Class labels in canonical order
CLASS_LABELS: List[str] = ["benign", "dos", "portscan", "bruteforce"]


@dataclass
class BiLSTMPrediction:
    """Result of a single Bi-LSTM inference call."""
    predicted_label: str
    probabilities: Dict[str, float]      # {label: probability}
    max_probability: float
    model_version: str
    inference_time_s: Optional[float] = None


@dataclass
class BiLSTMTrainResult:
    """Actual measured evaluation metrics after training."""
    accuracy: Optional[float] = None
    macro_f1: Optional[float] = None
    per_class_f1: Optional[Dict[str, float]] = None
    n_train: int = 0
    n_test: int = 0
    train_duration_s: Optional[float] = None
    model_version: str = "unset"
    epochs_trained: int = 0
    class_distribution_train: Optional[Dict[str, int]] = None
    class_distribution_test: Optional[Dict[str, int]] = None


# ---------------------------------------------------------------------------
# PyTorch Neural Network Definition
# ---------------------------------------------------------------------------
def _build_torch_network(input_dim: int = 6, hidden_dim: int = 64, num_layers: int = 2, num_classes: int = 4):
    try:
        import torch
        import torch.nn as nn

        class BiLSTMNet(nn.Module):
            def __init__(self):
                super().__init__()
                self.proj = nn.Linear(input_dim, hidden_dim)
                self.lstm = nn.LSTM(
                    input_size=hidden_dim,
                    hidden_size=hidden_dim,
                    num_layers=num_layers,
                    batch_first=True,
                    bidirectional=True,
                    dropout=0.2 if num_layers > 1 else 0.0,
                )
                self.norm = nn.LayerNorm(hidden_dim * 2)
                self.fc = nn.Sequential(
                    nn.Linear(hidden_dim * 2, hidden_dim),
                    nn.ReLU(),
                    nn.Dropout(0.3),
                    nn.Linear(hidden_dim, num_classes),
                )

            def forward(self, x):
                # x shape: (batch_size, seq_len, input_dim) or (batch_size, input_dim)
                if x.dim() == 2:
                    x = x.unsqueeze(1)  # shape (batch, 1, input_dim)
                h_proj = self.proj(x)
                out, (hn, cn) = self.lstm(h_proj)
                # Max-pooling across sequence dimension
                pooled, _ = torch.max(out, dim=1)
                normed = self.norm(pooled)
                logits = self.fc(normed)
                return logits

        return BiLSTMNet()
    except ImportError:
        return None


class BiLSTMThreatClassifier:
    """
    Wraps a PyTorch Bidirectional LSTM multi-class classifier for mid-flow SDN telemetry.
    Learns temporal rate trajectories and feature combinations.
    """

    def __init__(self, model_path: str = MODEL_SAVE_PATH):
        self._model = None
        self._scaler = None
        self._label_encoder = None
        self._model_path = model_path
        self._model_version: str = "not_loaded"
        self._device = "cpu"

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(
        self,
        X_train: np.ndarray,
        y_train: List[str],
        X_test: np.ndarray,
        y_test: List[str],
        epochs: int = 20,
        batch_size: int = 128,
        lr: float = 0.001,
        hidden_dim: int = 64,
        num_layers: int = 2,
        random_state: int = 42,
    ) -> BiLSTMTrainResult:
        """
        Trains the Bi-LSTM model on standardized features with class-balanced weighting.
        """
        try:
            import torch
            import torch.nn as nn
            from torch.utils.data import TensorDataset, DataLoader
            from sklearn.preprocessing import StandardScaler, LabelEncoder
            from sklearn.metrics import accuracy_score, f1_score
            from collections import Counter
        except ImportError as e:
            raise ImportError(
                f"Required package missing for Bi-LSTM: {e}. "
                "Run: pip install torch scikit-learn"
            )

        torch.manual_seed(random_state)
        np.random.seed(random_state)

        result = BiLSTMTrainResult(
            n_train=len(y_train),
            n_test=len(y_test),
        )

        # Device selection: use CUDA if available
        self._device = "cuda" if torch.cuda.is_available() else "cpu"

        # Fit LabelEncoder on training classes
        self._label_encoder = LabelEncoder()
        train_classes = sorted(list(set(y_train)))
        self._label_encoder.fit(train_classes)
        num_classes = len(train_classes)

        y_train_enc = self._label_encoder.transform(y_train)

        # Fit StandardScaler
        self._scaler = StandardScaler()
        X_train_scaled = self._scaler.fit_transform(X_train)
        X_test_scaled = self._scaler.transform(X_test)

        # Filter test set for evaluation to classes known in training
        valid_test_idx = [i for i, y in enumerate(y_test) if y in train_classes]
        X_test_valid = X_test_scaled[valid_test_idx]
        y_test_valid_enc = self._label_encoder.transform([y_test[i] for i in valid_test_idx])

        result.class_distribution_train = dict(Counter(y_train))
        result.class_distribution_test = dict(Counter(y_test))

        # Compute balanced class weights for CrossEntropyLoss
        counts = Counter(y_train_enc)
        total_samples = len(y_train_enc)
        class_weights = [total_samples / (num_classes * counts.get(c, 1)) for c in range(num_classes)]
        weights_tensor = torch.tensor(class_weights, dtype=torch.float32).to(self._device)

        # Build PyTorch Network
        self._model = _build_torch_network(
            input_dim=X_train.shape[1],
            hidden_dim=hidden_dim,
            num_layers=num_layers,
            num_classes=num_classes,
        ).to(self._device)

        criterion = nn.CrossEntropyLoss(weight=weights_tensor)
        optimizer = torch.optim.AdamW(self._model.parameters(), lr=lr, weight_decay=1e-4)
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

        # Prepare DataLoader
        train_dataset = TensorDataset(
            torch.tensor(X_train_scaled, dtype=torch.float32),
            torch.tensor(y_train_enc, dtype=torch.long),
        )
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)

        logger.info(
            "[BiLSTM] Starting training: %d samples, %d epochs, batch_size=%d on %s",
            len(y_train), epochs, batch_size, self._device
        )

        t_start = time.monotonic()
        self._model.train()
        for epoch in range(epochs):
            for batch_x, batch_y in train_loader:
                batch_x, batch_y = batch_x.to(self._device), batch_y.to(self._device)
                optimizer.zero_grad()
                logits = self._model(batch_x)
                loss = criterion(logits, batch_y)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self._model.parameters(), max_norm=1.0)
                optimizer.step()
            scheduler.step()

        t_end = time.monotonic()
        result.train_duration_s = t_end - t_start
        result.epochs_trained = epochs

        # Evaluation on test set
        self._model.eval()
        with torch.no_grad():
            test_x_tensor = torch.tensor(X_test_valid, dtype=torch.float32).to(self._device)
            test_logits = self._model(test_x_tensor)
            preds_enc = torch.argmax(test_logits, dim=-1).cpu().numpy()

        y_pred = self._label_encoder.inverse_transform(preds_enc)
        y_true = [y_test[i] for i in valid_test_idx]

        result.accuracy = float(accuracy_score(y_true, y_pred))
        result.macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))

        f1_scores = f1_score(
            y_true, y_pred,
            labels=list(self._label_encoder.classes_),
            average=None,
            zero_division=0,
        )
        result.per_class_f1 = {
            cls: float(f1_scores[i])
            for i, cls in enumerate(self._label_encoder.classes_)
        }

        self._model_version = f"bilstm-{int(time.time())}"
        result.model_version = self._model_version

        logger.info(
            "[BiLSTM] Training complete: accuracy=%.4f | macro_f1=%.4f | duration=%.2fs",
            result.accuracy, result.macro_f1, result.train_duration_s
        )
        for cls, f1 in result.per_class_f1.items():
            logger.info("  F1[%s] = %.4f", cls, f1)

        return result

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: Optional[str] = None) -> str:
        """Saves PyTorch state_dict, scaler, and label encoder."""
        try:
            import torch
        except ImportError:
            raise RuntimeError("PyTorch is required to save Bi-LSTM.")

        save_path = path or self._model_path
        if self._model is None:
            raise RuntimeError("No trained model to save. Call train() first.")

        bundle = {
            "model_state": self._model.state_dict(),
            "scaler": self._scaler,
            "label_encoder": self._label_encoder,
            "model_version": self._model_version,
            "device": "cpu",
        }
        torch.save(bundle, save_path)
        logger.info("[BiLSTM] Model saved to %s", save_path)
        return save_path

    def load(self, path: Optional[str] = None) -> bool:
        """
        Loads saved Bi-LSTM model. Returns True if loaded successfully,
        False if file does not exist. Never raises for missing file.
        """
        load_path = path or self._model_path
        if not os.path.exists(load_path):
            logger.warning("[BiLSTM] Model file not found at %s", load_path)
            return False

        try:
            import torch
        except ImportError:
            logger.warning("[BiLSTM] PyTorch not available. Model cannot be loaded.")
            return False

        try:
            device = "cuda" if torch.cuda.is_available() else "cpu"
            is_release = os.path.basename(load_path) == BILSTM_FILE
            bundle = torch.load(load_path, map_location=device, weights_only=is_release)
            if is_release:
                preprocessing = load_preprocessing(load_path)
                bundle = {
                    "model_state": bundle,
                    "scaler": preprocessing["scaler"],
                    "label_encoder": preprocessing["encoder"],
                    "model_version": RELEASE_VERSION,
                }

            scaler = bundle["scaler"]
            encoder = bundle["label_encoder"]
            model = _build_torch_network(input_dim=6, num_classes=len(encoder.classes_)).to(device)
            model.load_state_dict(bundle["model_state"])
            model.eval()

            self._device = device
            self._scaler = scaler
            self._label_encoder = encoder
            self._model_version = bundle.get("model_version", "unknown")
            self._model = model

            logger.info("[BiLSTM] Model loaded from %s (version=%s)", load_path, self._model_version)
            return True
        except Exception as e:
            logger.warning("[BiLSTM] Failed to load model from %s: %s", load_path, e)
            return False

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict(self, feature_vector: np.ndarray) -> Optional[BiLSTMPrediction]:
        """
        Performs inference on a single 1D feature vector of shape (6,).
        Returns BiLSTMPrediction or None if model is not loaded.
        """
        if self._model is None or self._scaler is None or self._label_encoder is None:
            return None

        try:
            import torch
        except ImportError:
            return None

        t0 = time.monotonic()
        vec = feature_vector.reshape(1, -1).astype(np.float32)
        vec_scaled = self._scaler.transform(vec)

        self._model.eval()
        with torch.no_grad():
            x_tensor = torch.tensor(vec_scaled, dtype=torch.float32).to(self._device)
            logits = self._model(x_tensor)
            probs = torch.softmax(logits, dim=-1).cpu().numpy()[0]

        t1 = time.monotonic()

        classes = self._label_encoder.classes_
        prob_dict = {cls: float(probs[i]) for i, cls in enumerate(classes)}
        best_idx = int(np.argmax(probs))
        predicted_label = str(classes[best_idx])
        max_prob = float(probs[best_idx])

        return BiLSTMPrediction(
            predicted_label=predicted_label,
            probabilities=prob_dict,
            max_probability=max_prob,
            model_version=self._model_version,
            inference_time_s=t1 - t0,
        )

    @property
    def is_loaded(self) -> bool:
        return self._model is not None

    @property
    def model_version(self) -> str:
        return self._model_version
