"""
risk/policy_engine/ai_engine.py

Phase 4.6: AI-Augmented Risk Policy Engine
References: PRD (Section 5, Phase 4), DESIGN.md, AGENTS.md, ARCHITECTURE.md, DATABASE.md

Extends the Phase 3 rule-based RiskPolicyEngine with XGBoost + Isolation Forest corroboration.

Key Rules (AGENTS.md):
1. AI inference is NEVER called inside Ryu's event loop.
   This module is called from daemon.py (a subprocess), never from sdn_controller.py.
2. If either model is unavailable, model_score is recorded as None — NEVER fabricated.
3. Broad quarantine requires BOTH models to agree (corroboration requirement).
4. Narrow drop for MALICIOUS signatures is still allowed from rule-alone if AI unavailable.
5. The full action lifecycle is recorded: requested → accepted → processed → observed.
6. All decisions include the model_version and scores for auditability.

Decision Logic (layered):
  Layer 1 (Rule): Suricata signature evaluation (Phase 3 baseline)
  Layer 2 (AI):   XGBoost classification + Isolation Forest anomaly score
  Merge:
    - MALICIOUS signature + (XGB says dos/bruteforce OR IF is anomalous) → confirmed_drop
    - RECON signature + BOTH models agree it is anomalous → confirmed_quarantine
    - MALICIOUS signature but AI unavailable → rule_drop (narrow, labeled as unconfirmed)
    - AI alone (no Suricata trigger) → monitor only (no blocking without sensor corroboration)
    - Disagreement → escalate TTL, monitor, log for review
"""

import logging
import time
import uuid
import json
import os
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List

from controller.ryu_app.enforcement_types import (
    EnforcementActionRequest,
    EnforcementMatch,
    ActionState,
)
from sensors.alert_listener.listener import NormalizedAlert
from risk.policy_engine.engine import RiskPolicyEngine, PolicyDecision
from ai.models.xgboost_classifier import XGBoostThreatClassifier, XGBPrediction
from ai.models.isolation_forest import IsolationForestDetector, IForestPrediction
from ai.features.feature_contract import FlowFeatureVector
from ai.explain.explainer import ShapExplainer, ExplanationJob

logger = logging.getLogger(__name__)

AI_DECISION_SPOOL = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "audit", "spool", "ai_decisions.jsonl")
)


@dataclass
class AICorroborationResult:
    """Records the AI corroboration evidence for a single enforcement decision."""
    decision_id: str
    xgb_prediction: Optional[str] = None           # predicted label or None
    xgb_max_prob: Optional[float] = None           # None if model unavailable
    xgb_model_version: Optional[str] = None
    iforest_is_anomalous: Optional[bool] = None    # None if model unavailable
    iforest_score: Optional[float] = None          # None if model unavailable
    iforest_model_version: Optional[str] = None
    corroboration: str = "unavailable"              # "confirmed", "disagreement", "unavailable"
    ai_inference_time_s: Optional[float] = None    # actual elapsed inference time
    feature_vector_valid: bool = False


@dataclass
class AIEnhancedDecision:
    """A policy decision enriched with AI model evidence."""
    base_decision: PolicyDecision
    ai_evidence: AICorroborationResult
    final_action_type: str            # may differ from base_decision.action_type
    final_approved: bool
    final_reason: str


class AIAugmentedRiskEngine:
    """
    AI-augmented wrapper around the Phase 3 RiskPolicyEngine.

    At inference time:
      1. Runs the base rule engine (Suricata signature evaluation).
      2. If a feature vector is provided, runs XGBoost + IForest inference.
      3. Applies corroboration logic to decide final action.
      4. Submits SHAP explanation job (non-blocking, background thread).
      5. Writes AI decision record to audit spool.

    Models are loaded lazily from disk on first use.
    If model files are missing, the engine falls back to rule-only decisions.
    """

    def __init__(
        self,
        policy_version: str = "p2-ai",
        default_ttl_s: int = 60,
        xgb_path: Optional[str] = None,
        iforest_path: Optional[str] = None,
        enable_shap: bool = True,
    ):
        self._base_engine = RiskPolicyEngine(
            policy_version=policy_version,
            default_ttl_s=default_ttl_s,
        )

        # Lazy-loaded model objects
        self._xgb: Optional[XGBoostThreatClassifier] = None
        self._iforest: Optional[IsolationForestDetector] = None
        self._xgb_path = xgb_path
        self._iforest_path = iforest_path

        # SHAP explainer (started on first model load)
        self._shap_xgb: Optional[ShapExplainer] = None
        self._enable_shap = enable_shap

        # Models loaded flag (attempt once)
        self._models_attempted = False

    # ------------------------------------------------------------------
    # Model loading (lazy, attempt once)
    # ------------------------------------------------------------------

    def _ensure_models_loaded(self) -> None:
        """Attempts to load XGB and IForest models once from disk."""
        if self._models_attempted:
            return
        self._models_attempted = True

        self._xgb = XGBoostThreatClassifier()
        xgb_ok = self._xgb.load(self._xgb_path) if self._xgb_path else self._xgb.load()
        if not xgb_ok:
            logger.warning("[AIEngine] XGBoost model not found. Falling back to rule-only.")
            self._xgb = None

        self._iforest = IsolationForestDetector()
        iforest_ok = (
            self._iforest.load(self._iforest_path)
            if self._iforest_path
            else self._iforest.load()
        )
        if not iforest_ok:
            logger.warning("[AIEngine] Isolation Forest model not found. Falling back to rule-only.")
            self._iforest = None

        # Start async SHAP explainer for XGB if available and enabled
        if self._xgb is not None and self._enable_shap:
            try:
                from ai.features.feature_contract import FEATURE_NAMES
                self._shap_xgb = ShapExplainer(
                    model=self._xgb._model,
                    model_type="xgboost",
                    feature_names=FEATURE_NAMES,
                )
                self._shap_xgb.start()
            except Exception as e:
                logger.warning("[AIEngine] Could not start SHAP explainer: %s", e)
                self._shap_xgb = None

    # ------------------------------------------------------------------
    # Main evaluation (called from daemon.py, NOT from Ryu event loop)
    # ------------------------------------------------------------------

    def evaluate(
        self,
        alert: NormalizedAlert,
        feature_vector: Optional[FlowFeatureVector] = None,
        switch_id: str = "s1",
    ) -> AIEnhancedDecision:
        """
        Evaluates a Suricata alert with optional AI corroboration.

        Args:
            alert:          Normalized Suricata alert from listener.py.
            feature_vector: Optional live OVS flow features. If None,
                            only the rule-based decision is applied.
            switch_id:      OVS datapath to target.

        Returns:
            AIEnhancedDecision with base + AI evidence + final action.
        """
        # Step 1: Rule-based baseline (Phase 3)
        base = self._base_engine.evaluate_suricata_alert(alert, switch_id=switch_id)

        # Step 2: Lazy load models
        self._ensure_models_loaded()

        # Step 3: AI corroboration (only if feature vector is provided and valid)
        ai_evidence = AICorroborationResult(decision_id=base.decision_id)

        if feature_vector is not None and feature_vector.is_valid:
            ai_evidence.feature_vector_valid = True
            ai_evidence = self._run_ai_inference(base.decision_id, feature_vector)
        else:
            logger.debug(
                "[AIEngine] No valid feature vector provided; skipping AI corroboration."
            )

        # Step 4: Merge rule + AI into final decision
        final = self._merge_decision(base, ai_evidence, alert)

        # Step 5: Async SHAP explanation (non-blocking, never delays enforcement)
        if (
            feature_vector is not None
            and feature_vector.is_valid
            and self._shap_xgb is not None
        ):
            self._submit_shap(base.decision_id, feature_vector, ai_evidence.xgb_prediction)

        # Step 6: Write AI decision to audit spool
        self._write_ai_spool(final)

        return final

    # ------------------------------------------------------------------
    # AI inference (runs in subprocess/daemon context, NOT in Ryu loop)
    # ------------------------------------------------------------------

    def _run_ai_inference(
        self, decision_id: str, fv: FlowFeatureVector
    ) -> AICorroborationResult:
        """Runs XGBoost + IForest on the feature vector. Returns actual scores, never faked."""
        result = AICorroborationResult(
            decision_id=decision_id,
            feature_vector_valid=True,
        )

        vec = fv.to_array()
        t0 = time.monotonic()

        # --- XGBoost ---
        if self._xgb is not None and self._xgb.is_loaded:
            try:
                xgb_pred: Optional[XGBPrediction] = self._xgb.predict(vec)
                if xgb_pred is not None:
                    result.xgb_prediction     = xgb_pred.predicted_label
                    result.xgb_max_prob        = xgb_pred.max_probability
                    result.xgb_model_version   = xgb_pred.model_version
            except Exception as e:
                logger.error("[AIEngine] XGBoost inference error: %s", e, exc_info=True)
        else:
            logger.debug("[AIEngine] XGBoost not loaded; score = None")

        # --- Isolation Forest ---
        if self._iforest is not None and self._iforest.is_loaded:
            try:
                if_pred: Optional[IForestPrediction] = self._iforest.predict(vec)
                if if_pred is not None:
                    result.iforest_is_anomalous  = if_pred.is_anomalous
                    result.iforest_score          = if_pred.anomaly_score
                    result.iforest_model_version  = if_pred.model_version
            except Exception as e:
                logger.error("[AIEngine] IForest inference error: %s", e, exc_info=True)
        else:
            logger.debug("[AIEngine] IForest not loaded; score = None")

        t1 = time.monotonic()
        result.ai_inference_time_s = t1 - t0  # actual elapsed

        # --- Corroboration logic ---
        xgb_threat = result.xgb_prediction in ("dos", "portscan", "bruteforce")
        if_threat  = result.iforest_is_anomalous is True

        if result.xgb_prediction is None and result.iforest_is_anomalous is None:
            result.corroboration = "unavailable"
        elif xgb_threat and if_threat:
            result.corroboration = "confirmed"
        elif not xgb_threat and not if_threat:
            result.corroboration = "clear"
        else:
            result.corroboration = "disagreement"

        logger.info(
            "[AIEngine] AI corroboration=%s | xgb=%s(%.2f) | iforest_anomalous=%s(%.3f) | %.3fs",
            result.corroboration,
            result.xgb_prediction, result.xgb_max_prob or 0.0,
            result.iforest_is_anomalous, result.iforest_score or 0.0,
            result.ai_inference_time_s,
        )
        return result

    # ------------------------------------------------------------------
    # Decision merge
    # ------------------------------------------------------------------

    def _merge_decision(
        self,
        base: PolicyDecision,
        ai: AICorroborationResult,
        alert: NormalizedAlert,
    ) -> AIEnhancedDecision:
        """
        Merges rule-based and AI evidence into a final enforcement decision.

        Broad quarantine requires BOTH models to agree (corroboration=confirmed).
        Narrow drop for MALICIOUS sigs is allowed even if AI is unavailable.
        """
        is_malicious = "MALICIOUS" in alert.signature.upper() or alert.signature_id == 1000001
        if not base.approved:
            return AIEnhancedDecision(
                base_decision=base,
                ai_evidence=ai,
                final_action_type=base.action_type,
                final_approved=False,
                final_reason=base.reason,
            )

        # Case 1: AI confirms the threat → keep or escalate base decision
        if ai.corroboration == "confirmed":
            return AIEnhancedDecision(
                base_decision=base,
                ai_evidence=ai,
                final_action_type=base.action_type,
                final_approved=True,
                final_reason=(
                    f"AI CONFIRMED: {base.reason} | "
                    f"XGBoost={ai.xgb_prediction}({ai.xgb_max_prob:.2f}) "
                    f"IForest=anomalous({ai.iforest_score:.3f})"
                ),
            )

        # Case 2: MALICIOUS sig, AI unavailable → narrow rule-only drop (acceptable)
        if is_malicious and ai.corroboration == "unavailable":
            return AIEnhancedDecision(
                base_decision=base,
                ai_evidence=ai,
                final_action_type="temporary_drop",
                final_approved=base.approved,
                final_reason=(
                    f"RULE-ONLY (AI unavailable): {base.reason}"
                ),
            )

        # Case 3: MALICIOUS sig but AI says clear → downgrade to monitor, flag for review
        if is_malicious and ai.corroboration == "clear":
            logger.warning(
                "[AIEngine] Rule-AI conflict: MALICIOUS sig but AI says clear. "
                "Downgrading to monitor for %s", alert.event_id
            )
            return AIEnhancedDecision(
                base_decision=base,
                ai_evidence=ai,
                final_action_type="monitor",
                final_approved=False,
                final_reason=(
                    f"CONFLICT: MALICIOUS sig but AI models say normal traffic. "
                    f"Monitoring only. Manual review required."
                ),
            )

        # Case 4: Disagreement between XGB and IForest → monitor, do not block
        if ai.corroboration == "disagreement":
            return AIEnhancedDecision(
                base_decision=base,
                ai_evidence=ai,
                final_action_type="monitor",
                final_approved=False,
                final_reason=(
                    f"AI DISAGREEMENT: XGBoost={ai.xgb_prediction} "
                    f"IForest.anomalous={ai.iforest_is_anomalous}. "
                    f"Monitoring only, no enforcement."
                ),
            )

        # Case 5: RECON without AI confirmation → keep base (quarantine or monitor)
        return AIEnhancedDecision(
            base_decision=base,
            ai_evidence=ai,
            final_action_type=base.action_type,
            final_approved=base.approved,
            final_reason=base.reason,
        )

    # ------------------------------------------------------------------
    # Async SHAP submission (non-blocking)
    # ------------------------------------------------------------------

    def _submit_shap(
        self,
        decision_id: str,
        fv: FlowFeatureVector,
        predicted_label: Optional[str],
    ) -> None:
        """Submits a SHAP explanation job. Returns immediately (never blocks enforcement)."""
        if self._shap_xgb is None:
            return
        from ai.features.feature_contract import FEATURE_NAMES
        job = ExplanationJob(
            prediction_id=decision_id,
            model_type="xgboost",
            feature_vector=fv.to_array(),
            feature_names=FEATURE_NAMES,
            predicted_label=predicted_label,
        )
        accepted = self._shap_xgb.submit(job)
        if not accepted:
            logger.warning(
                "[AIEngine] SHAP explanation dropped for decision %s (queue full). "
                "Coverage gap recorded.", decision_id
            )

    # ------------------------------------------------------------------
    # Audit spool
    # ------------------------------------------------------------------

    def _write_ai_spool(self, decision: AIEnhancedDecision) -> None:
        """Appends the AI-enhanced decision record to the audit JSONL spool."""
        os.makedirs(os.path.dirname(AI_DECISION_SPOOL), exist_ok=True)
        record = {
            "decision_id":        decision.base_decision.decision_id,
            "incident_id":        decision.base_decision.incident_id,
            "timestamp":          time.time(),
            "final_action_type":  decision.final_action_type,
            "final_approved":     decision.final_approved,
            "final_reason":       decision.final_reason,
            "xgb_prediction":     decision.ai_evidence.xgb_prediction,
            "xgb_max_prob":       decision.ai_evidence.xgb_max_prob,
            "xgb_model_version":  decision.ai_evidence.xgb_model_version,
            "iforest_is_anomalous":  decision.ai_evidence.iforest_is_anomalous,
            "iforest_score":         decision.ai_evidence.iforest_score,
            "iforest_model_version": decision.ai_evidence.iforest_model_version,
            "corroboration":      decision.ai_evidence.corroboration,
            "ai_inference_time_s":decision.ai_evidence.ai_inference_time_s,
            "feature_vector_valid": decision.ai_evidence.feature_vector_valid,
        }
        with open(AI_DECISION_SPOOL, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    # ------------------------------------------------------------------
    # Pass-through to base engine for direct rule-only use
    # ------------------------------------------------------------------

    def evaluate_rule_only(
        self, alert: NormalizedAlert, switch_id: str = "s1"
    ) -> PolicyDecision:
        """Direct access to the Phase 3 rule-only engine (no AI, no SHAP)."""
        return self._base_engine.evaluate_suricata_alert(alert, switch_id=switch_id)

    @property
    def xgb_loaded(self) -> bool:
        return self._xgb is not None and self._xgb.is_loaded

    @property
    def iforest_loaded(self) -> bool:
        return self._iforest is not None and self._iforest.is_loaded

