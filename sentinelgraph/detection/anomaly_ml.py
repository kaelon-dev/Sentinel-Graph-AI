"""Supplementary ML anomaly detector using Isolation Forest."""
from datetime import datetime
from typing import List, Optional
from sentinelgraph.models import NormalizedEvent, DetectionSignal

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class MLAnomalyDetector:
    """Optional Isolation Forest model providing supplementary anomaly scoring."""

    def __init__(self, random_seed: int = 42):
        self.random_seed = random_seed
        self.model: Optional[Any] = None
        if SKLEARN_AVAILABLE:
            self.model = IsolationForest(
                n_estimators=100,
                contamination=0.05,
                random_state=self.random_seed
            )

    def fit_predict(self, events: List[NormalizedEvent]) -> List[DetectionSignal]:
        """Extract lightweight numerical features and produce supplementary anomaly signals."""
        if not SKLEARN_AVAILABLE or self.model is None or len(events) < 10:
            return []

        # Extract numerical features:
        # 1. Hour of day (0-23)
        # 2. Is sensitive file (0 or 1)
        # 3. Bytes transferred (log scale)
        # 4. Is non-login event (0 or 1)
        features = []
        for e in events:
            hour = e.timestamp.hour
            is_sens = 1.0 if e.file_sensitivity in ("HIGH", "CRITICAL", "CONFIDENTIAL") else 0.0
            bytes_log = np.log1p(float(e.bytes_transferred or 0))
            is_non_login = 0.0 if "login" in e.event_type else 1.0
            features.append([hour, is_sens, bytes_log, is_non_login])

        X = np.array(features)
        try:
            self.model.fit(X)
            # Scores: lower values mean more anomalous
            scores = self.model.decision_function(X)
            preds = self.model.predict(X)  # -1 for anomaly, 1 for inlier
        except Exception:
            return []

        signals: List[DetectionSignal] = []
        for i, (pred, score) in enumerate(zip(preds, scores)):
            if pred == -1:
                e = events[i]
                # Invert score to 0..1 scale where 1 is highest anomaly
                norm_score = round(float(np.clip(1.0 - (score + 0.5), 0.0, 1.0)), 2)
                signals.append(
                    DetectionSignal(
                        signal_id=f"SIG-ML-ANOMALY-{e.event_id}",
                        detector_name="supplementary_isolation_forest",
                        signal_score=5.0,  # Low supportive weight, never exceeds MEDIUM
                        severity="INFO",
                        confidence=0.60,
                        explanation=f"Supplementary ML Anomaly Signal: Isolation Forest identified statistical outlier (score: {norm_score})",
                        event_ids=[e.event_id],
                        timestamp=e.timestamp,
                        affected_user_id=e.user_id,
                        affected_device_id=e.device_id,
                        affected_ip_address=e.ip_address,
                        affected_application=e.application,
                        baseline_comparison={"ml_model": "IsolationForest", "anomaly_score": norm_score},
                        recommended_stage="Unknown / Suspicious Activity",
                        evidence={"event_id": e.event_id, "anomaly_score": norm_score},
                        metadata={"is_supplementary_ml": True}
                    )
                )

        return signals
