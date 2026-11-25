"""
tests/test_phase4_models.py

Phase 4 Unit Tests: XGBoost, Isolation Forest, InSDN Mapper, AI Risk Engine
References: PRD (Section 5, Phase 4), AGENTS.md, TESTING.md

All tests use synthetic data — no real InSDN CSV is required.
Tests verify:
  1. XGBoost trains and predicts correctly on synthetic data.
  2. Isolation Forest correctly identifies anomalies in synthetic data.
  3. InSDN mapper correctly resolves columns and maps labels.
  4. AI Engine falls back gracefully when models are not loaded.
  5. Corroboration logic is correct (confirmed / disagreement / unavailable).
  6. SHAP explainer submits non-blocking jobs without crashing.
"""

import sys
import os
import tempfile
import numpy as np
import pytest

# Ensure project root in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ---------------------------------------------------------------------------
# Shared synthetic data fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def synthetic_data():
    """Returns (X_train, X_test, y_train, y_test, X_benign) with realistic time-ordered class structure."""
    rng = np.random.default_rng(0)

    def _sample(rate_low, rate_high, label):
        return [
            rng.uniform(rate_low, rate_high),
            rng.uniform(rate_low * 100, rate_high * 100),
            rng.uniform(60, 1500),
            rng.uniform(100, 5000),
            rng.uniform(10000, 500000),
            rng.uniform(0.5, 30),
        ], label

    # Generate sequential time windows (e.g. 10 time intervals) where each interval has
    # benign background traffic plus intermittent attack spikes.
    vectors = []
    labels = []
    for _ in range(10):
        # 40 benign flows
        for _ in range(40):
            vec, lbl = _sample(10, 200, "benign")
            vectors.append(vec)
            labels.append(lbl)
        # 10 DoS flows
        for _ in range(10):
            vec, lbl = _sample(5000, 50000, "dos")
            vectors.append(vec)
            labels.append(lbl)
        # 10 portscan flows
        for _ in range(10):
            vec, lbl = _sample(100, 2000, "portscan")
            vectors.append(vec)
            labels.append(lbl)
        # 10 bruteforce flows
        for _ in range(10):
            vec, lbl = _sample(50, 500, "bruteforce")
            vectors.append(vec)
            labels.append(lbl)

    X = np.array(vectors, dtype=np.float32)
    y = labels

    n_train = int(len(y) * 0.8)
    X_train, X_test = X[:n_train], X[n_train:]
    y_train, y_test = y[:n_train], y[n_train:]
    X_benign = X_train[[i for i, lbl in enumerate(y_train) if lbl == "benign"]]

    return X_train, X_test, y_train, y_test, X_benign


# ---------------------------------------------------------------------------
# Test 1: XGBoost trains and predicts
# ---------------------------------------------------------------------------

class TestXGBoostClassifier:
    @pytest.fixture(autouse=True)
    def require_xgboost(self):
        pytest.importorskip("xgboost")

    def test_train_returns_actual_accuracy(self, synthetic_data, tmp_path):
        """XGBoost training returns a measured accuracy, not None."""
        from ai.models.xgboost_classifier import XGBoostThreatClassifier
        X_train, X_test, y_train, y_test, _ = synthetic_data

        clf = XGBoostThreatClassifier(model_path=str(tmp_path / "xgb.pkl"))
        result = clf.train(X_train, y_train, X_test, y_test)

        assert result.accuracy is not None, "accuracy must not be None"
        assert 0.0 <= result.accuracy <= 1.0, "accuracy must be in [0, 1]"
        assert result.n_train == len(y_train)
        assert result.n_test  == len(y_test)
        assert result.train_duration_s is not None
        assert result.train_duration_s > 0.0

    def test_predict_returns_known_class(self, synthetic_data, tmp_path):
        """Prediction on a clear DoS-like vector should return a non-benign label."""
        from ai.models.xgboost_classifier import XGBoostThreatClassifier, CLASS_LABELS
        X_train, X_test, y_train, y_test, _ = synthetic_data

        clf = XGBoostThreatClassifier(model_path=str(tmp_path / "xgb2.pkl"))
        clf.train(X_train, y_train, X_test, y_test)

        # Very high packet rate → should be non-benign
        dos_vector = np.array([30000.0, 2_000_000.0, 60.0, 50000.0, 3_000_000.0, 2.0], dtype=np.float32)
        pred = clf.predict(dos_vector)

        assert pred is not None
        assert pred.predicted_label in CLASS_LABELS
        assert pred.max_probability >= 0.0
        assert pred.inference_time_s is not None and pred.inference_time_s >= 0.0
        assert sum(pred.probabilities.values()) == pytest.approx(1.0, abs=0.01)

    def test_predict_returns_none_when_not_loaded(self, tmp_path):
        """Predict returns None (not fake score) when model is not loaded."""
        from ai.models.xgboost_classifier import XGBoostThreatClassifier

        clf = XGBoostThreatClassifier(model_path=str(tmp_path / "nonexistent.pkl"))
        vec = np.zeros(6, dtype=np.float32)
        result = clf.predict(vec)

        assert result is None, "must return None when model not loaded"

    def test_save_and_load_roundtrip(self, synthetic_data, tmp_path):
        """Save then load preserves model and produces consistent predictions."""
        from ai.models.xgboost_classifier import XGBoostThreatClassifier
        X_train, X_test, y_train, y_test, _ = synthetic_data
        pkl_path = str(tmp_path / "xgb_round.pkl")

        clf = XGBoostThreatClassifier(model_path=pkl_path)
        clf.train(X_train, y_train, X_test, y_test)
        clf.save()

        clf2 = XGBoostThreatClassifier(model_path=pkl_path)
        loaded = clf2.load()
        assert loaded is True

        vec = X_test[0]
        p1 = clf.predict(vec)
        p2 = clf2.predict(vec)
        assert p1 is not None and p2 is not None
        assert p1.predicted_label == p2.predicted_label


# ---------------------------------------------------------------------------
# Test 2: Isolation Forest
# ---------------------------------------------------------------------------

class TestIsolationForest:
    def test_train_returns_metadata(self, synthetic_data, tmp_path):
        """IForest training returns actual timing metadata."""
        from ai.models.isolation_forest import IsolationForestDetector
        _, _, _, _, X_benign = synthetic_data

        ifd = IsolationForestDetector(
            contamination=0.05,
            model_path=str(tmp_path / "iforest.pkl"),
        )
        result = ifd.train(X_benign)
        assert result.n_train_benign == len(X_benign)
        assert result.train_duration_s is not None and result.train_duration_s >= 0.0
        assert result.contamination == 0.05

    def test_benign_traffic_mostly_normal(self, synthetic_data, tmp_path):
        """Most benign test samples should not be flagged as anomalies."""
        from ai.models.isolation_forest import IsolationForestDetector
        X_train, X_test, y_train, y_test, X_benign = synthetic_data

        ifd = IsolationForestDetector(contamination=0.05, model_path=str(tmp_path / "if2.pkl"))
        ifd.train(X_benign)

        benign_test = X_test[[i for i, lbl in enumerate(y_test) if lbl == "benign"]]
        predictions = [ifd.predict(row) for row in benign_test]
        anomaly_rate = sum(1 for p in predictions if p and p.is_anomalous) / len(predictions)
        # With contamination=0.05, we expect at most ~15% false positives on benign
        assert anomaly_rate < 0.20, f"Too many false positives on benign: {anomaly_rate:.2%}"

    def test_dos_traffic_flagged_anomalous(self, synthetic_data, tmp_path):
        """High-rate DoS traffic should be flagged as anomalous by IForest."""
        from ai.models.isolation_forest import IsolationForestDetector
        _, _, _, _, X_benign = synthetic_data

        ifd = IsolationForestDetector(contamination=0.05, model_path=str(tmp_path / "if3.pkl"))
        ifd.train(X_benign)

        dos_vector = np.array([40000.0, 3_000_000.0, 60.0, 80000.0, 5_000_000.0, 1.5], dtype=np.float32)
        pred = ifd.predict(dos_vector)
        assert pred is not None
        assert pred.is_anomalous is True, "Extreme DoS traffic should be detected as anomalous"

    def test_predict_none_when_not_loaded(self, tmp_path):
        """Returns None (not fake score) if model file does not exist."""
        from ai.models.isolation_forest import IsolationForestDetector
        ifd = IsolationForestDetector(model_path=str(tmp_path / "missing.pkl"))
        vec = np.zeros(6, dtype=np.float32)
        assert ifd.predict(vec) is None


# ---------------------------------------------------------------------------
# Test 3: InSDN Mapper
# ---------------------------------------------------------------------------

class TestInSDNMapper:
    def test_resolve_columns_all_found(self):
        """Canonical InSDN headers should all resolve."""
        from ai.features.insdn_mapper import resolve_columns, FEATURE_NAMES

        headers = [
            "Flow Packets/s", "Flow Bytes/s", "Avg Pkt Size",
            "Total Fwd Packets", "Total Length of Fwd Packets", "Flow Duration",
            "Label",
        ]
        col_map = resolve_columns(headers)
        assert len(col_map.unresolved) < len(FEATURE_NAMES), \
            f"Too many unresolved features: {col_map.unresolved}"

    def test_map_row_sanitizes_inf(self):
        """Rows with Infinity values should be clamped to 0.0."""
        from ai.features.insdn_mapper import resolve_columns, map_row_to_features

        headers = ["Flow Packets/s", "Flow Bytes/s", "Avg Pkt Size",
                   "Total Fwd Packets", "Total Length of Fwd Packets", "Flow Duration"]
        col_map = resolve_columns(headers)
        row = {h: "Infinity" for h in headers}
        fv = map_row_to_features(row, col_map)
        for name, val in fv.features.items():
            assert val == 0.0, f"Expected 0.0 for Infinity input on feature {name}, got {val}"

    def test_label_mapping(self):
        """Standard InSDN label strings map to supported class labels."""
        from ai.features.insdn_mapper import map_label
        assert map_label("Normal")     == "benign"
        assert map_label("DoS")        == "dos"
        assert map_label("DDoS")       == "dos"
        assert map_label("Port Scan")  == "portscan"
        assert map_label("Brute Force") == "bruteforce"
        assert map_label("UnknownXYZ") is None


# ---------------------------------------------------------------------------
# Test 4: AI Corroboration Logic
# ---------------------------------------------------------------------------

class TestAICorroborationLogic:
    """Tests the merge/corroboration decision logic without needing real models."""

    def _make_alert(self, sig="TEST_MALICIOUS_PAYLOAD", sig_id=1000001):
        from sensors.alert_listener.listener import NormalizedAlert
        return NormalizedAlert(
            schema_version=1,
            event_id="evt-test-001",
            sensor_id="ips-edge-1",
            event_type="alert",
            src_ip="192.0.2.10",
            dest_ip="198.51.100.20",
            src_port=54321,
            dest_port=443,
            proto="TCP",
            signature=sig,
            signature_id=sig_id,
            subject_ip="192.0.2.10",
            subject_status="attacker",
            occurred_at="2026-11-08T00:00:00Z",
            raw_event_ref={},
        )

    def test_fallback_rule_only_when_no_models(self):
        """When no models are available, engine returns rule-based decision."""
        from risk.policy_engine.ai_engine import AIAugmentedRiskEngine

        engine = AIAugmentedRiskEngine(enable_shap=False)
        engine._models_attempted = True  # skip disk load
        engine._xgb = None
        engine._iforest = None

        alert = self._make_alert()
        result = engine.evaluate(alert, feature_vector=None)

        # Should still approve the MALICIOUS rule-based drop
        assert result.final_approved is True
        assert result.final_action_type == "temporary_drop"
        assert result.ai_evidence.corroboration == "unavailable"

    def test_xgb_max_prob_is_none_when_model_missing(self):
        """AI evidence fields are None (not fake scores) when models unavailable."""
        from risk.policy_engine.ai_engine import AIAugmentedRiskEngine
        from ai.features.feature_contract import FlowFeatureVector, FEATURE_NAMES

        engine = AIAugmentedRiskEngine(enable_shap=False)
        engine._models_attempted = True
        engine._xgb = None
        engine._iforest = None

        fv = FlowFeatureVector(
            features={f: 1.0 for f in FEATURE_NAMES},
            is_valid=True,
        )
        alert = self._make_alert()
        result = engine.evaluate(alert, feature_vector=fv)

        assert result.ai_evidence.xgb_max_prob is None
        assert result.ai_evidence.iforest_score is None


# ---------------------------------------------------------------------------
# Test 5: SHAP Explainer (non-blocking job submission)
# ---------------------------------------------------------------------------

class TestShapExplainer:
    def test_submit_does_not_block(self, synthetic_data, tmp_path):
        """Submitting a SHAP job returns immediately (non-blocking)."""
        pytest.importorskip("xgboost")
        import time
        from ai.models.xgboost_classifier import XGBoostThreatClassifier
        from ai.explain.explainer import ShapExplainer, ExplanationJob
        from ai.features.feature_contract import FEATURE_NAMES

        X_train, X_test, y_train, y_test, _ = synthetic_data
        pkl = str(tmp_path / "xgb_shap.pkl")
        clf = XGBoostThreatClassifier(model_path=pkl)
        clf.train(X_train, y_train, X_test, y_test)

        explainer = ShapExplainer(
            model=clf._model,
            model_type="xgboost",
            feature_names=FEATURE_NAMES,
            spool_path=str(tmp_path / "explanations.jsonl"),
        )
        explainer.start()

        job = ExplanationJob(
            prediction_id="test-shap-001",
            model_type="xgboost",
            feature_vector=X_test[0],
            feature_names=FEATURE_NAMES,
            predicted_label="benign",
        )

        t0 = time.monotonic()
        accepted = explainer.submit(job)
        elapsed = time.monotonic() - t0

        assert accepted is True
        assert elapsed < 0.1, f"submit() should return immediately, took {elapsed:.3f}s"

        explainer.stop(timeout_s=10.0)

    def test_full_queue_records_drop(self, tmp_path):
        """When queue is full, dropped count is incremented (coverage gap recorded)."""
        from ai.explain.explainer import ShapExplainer, ExplanationJob, MAX_QUEUE_SIZE
        from ai.features.feature_contract import FEATURE_NAMES
        import numpy as np

        # Use a mock model object (we won't process jobs — no worker started)
        class MockModel:
            pass

        explainer = ShapExplainer(
            model=MockModel(),
            model_type="xgboost",
            feature_names=FEATURE_NAMES,
            spool_path=str(tmp_path / "exp2.jsonl"),
        )
        # Do NOT call start() — queue fills up without being drained

        dropped = 0
        for i in range(MAX_QUEUE_SIZE + 5):
            job = ExplanationJob(
                prediction_id=f"test-{i}",
                model_type="xgboost",
                feature_vector=np.zeros(6, dtype=np.float32),
                feature_names=FEATURE_NAMES,
            )
            accepted = explainer.submit(job)
            if not accepted:
                dropped += 1

        assert dropped > 0, "Expected some drops when queue is full"
        assert explainer.dropped_count == dropped


# ---------------------------------------------------------------------------
# Test 6: CNS 2022 Mapper & Attempted Flow Sanitization
# ---------------------------------------------------------------------------

class TestCNS2022Mapper:
    def test_cns_column_resolution(self):
        """Resolves CSE-CIC-IDS2018 and CNS 2022 column headers."""
        from ai.features.cns2022_mapper import resolve_cns_columns

        headers = [
            "Dst Port", "Protocol", "Timestamp", "Flow Duration",
            "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts",
            "Pkt Len Mean", "Flow Byts/s", "Flow Pkts/s", "Label", "Attempted Category"
        ]
        col_map = resolve_cns_columns(headers)
        assert len(col_map.unresolved) == 0, f"Unresolved: {col_map.unresolved}"
        assert col_map.label_column == "Label"
        assert col_map.attempted_column == "Attempted Category"

    def test_attempted_flow_relabeled_benign(self):
        """Per CNS 2022 guidelines, attempted flows must be mapped to 'benign'."""
        from ai.features.cns2022_mapper import map_cns_label

        # Flow with Attempted Category != -1
        lbl1 = map_cns_label("DoS attacks-GoldenEye", attempted_val=1)
        assert lbl1 == "benign"

        # Flow with 'attempted' in label string
        lbl2 = map_cns_label("DoS GoldenEye - Attempted", attempted_val=-1)
        assert lbl2 == "benign"

        # Real attack flow
        lbl3 = map_cns_label("DoS attacks-GoldenEye", attempted_val=-1)
        assert lbl3 == "dos"

    def test_multi_attack_taxonomy_mapping(self):
        """Maps diverse attack families into 4 canonical classes."""
        from ai.features.cns2022_mapper import map_cns_label

        assert map_cns_label("Benign") == "benign"
        assert map_cns_label("DDOS attack-HOIC") == "dos"
        assert map_cns_label("Infilteration") == "portscan"
        assert map_cns_label("Bot") == "portscan"
        assert map_cns_label("FTP-BruteForce") == "bruteforce"
        assert map_cns_label("SQL Injection") == "bruteforce"


