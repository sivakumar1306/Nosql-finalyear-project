"""
Hybrid anomaly detector combining rule-based and model-based detection.
Preserves rule-only, model-only, and hybrid baselines as requested.
"""

from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import numpy as np

from models.log_schema import WindowFeatures, AnomalyDetectionResult
from ml.isolation_forest_model import IsolationForestAnomalyDetector
from rules.rule_engine import RuleEngine
from ml.window_feature_extractor import WindowFeatureExtractor


class HybridAnomalyDetector:
    """
    Hybrid anomaly detector combining rule-based and model-based approaches.
    
    Implements:
    - Rule-only detection (baseline)
    - Model-only detection (baseline with borderline persistence)
    - Hybrid detection (combination of both)
    - Configurable voting strategies
    """
    
    def __init__(self, 
                 model_detector: IsolationForestAnomalyDetector,
                 rule_engine: RuleEngine,
                 voting_strategy: str = "weighted"):
        """
        Initialize hybrid detector.
        
        Args:
            model_detector: Isolation Forest model detector
            rule_engine: Rule-based detection engine
            voting_strategy: How to combine detections ("weighted", "majority", "union", "intersection")
        """
        self.model_detector = model_detector
        self.rule_engine = rule_engine
        self.voting_strategy = voting_strategy
        self.feature_extractor = WindowFeatureExtractor()
        
        # Weights for weighted voting (rule_weight + model_weight = 1.0)
        self.rule_weight = 0.4
        self.model_weight = 0.6
        
        # Performance tracking
        self.detection_counts = {
            "rule_only": 0,
            "model_only": 0,
            "hybrid": 0,
            "borderline_persistence": 0,
            "total": 0
        }
        
        # Latency tracking
        self.detection_latencies = []
        
        # Duplicate alert prevention
        self.recent_alerts = []
        self.max_recent_alerts = 100
        self.duplicate_window_minutes = 5
    
    def detect_anomaly(self, 
                      window_features: WindowFeatures,
                      previous_results: List[Dict[str, Any]] = None,
                      previous_windows: List[WindowFeatures] = None,
                      track_latency: bool = True) -> Dict[str, Any]:
        """
        Detect anomaly using hybrid approach.
        
        Args:
            window_features: Current window features
            previous_results: Previous detection results for persistence
            previous_windows: Previous window features for rule rate changes
            track_latency: Whether to track detection latency
            
        Returns:
            Dictionary with detection results from all methods
        """
        start_time = datetime.utcnow() if track_latency else None
        
        # 1. Rule-only detection
        rule_violations = self.rule_engine.evaluate_window(
            window_features, previous_windows
        )
        rule_is_anomaly = len(rule_violations) > 0
        rule_confidence = self._calculate_rule_confidence(rule_violations)
        
        # 2. Model-only detection (with borderline persistence)
        model_available = self.model_detector.model is not None
        if model_available:
            model_result = self.model_detector.predict_with_persistence(
                window_features,
                previous_results or []
            )
        else:
            # No trained model yet: report a neutral model result
            model_result = {
                "anomaly_score": 0.0,
                "decision_score": None,
                "is_borderline": False,
                "borderline_score": None,
                "consecutive_borderline_windows": 0,
                "persistence_triggered": False,
                "final_is_anomaly": False
            }
        model_is_anomaly = model_result["final_is_anomaly"]
        model_confidence = model_result["anomaly_score"]

        # 3. Hybrid detection based on voting strategy
        if model_available:
            hybrid_is_anomaly, hybrid_confidence = self._combine_detections(
                rule_is_anomaly, rule_confidence,
                model_is_anomaly, model_confidence
            )
        else:
            # Fall back to rule-only detection until a model is trained
            hybrid_is_anomaly, hybrid_confidence = rule_is_anomaly, rule_confidence
        
        # Determine detection method for reporting
        detection_method = self._determine_detection_method(
            rule_is_anomaly, model_result, hybrid_is_anomaly
        )
        
        # Check for duplicate alerts before proceeding
        is_duplicate_alert = self._is_duplicate_alert(
            window_features, rule_violations, detection_method
        )
        
        # If it's a duplicate, suppress the alert but still record the detection
        if is_duplicate_alert:
            hybrid_is_anomaly = False
            detection_method = "duplicate_suppressed"
        
        # Update detection counts
        self._update_detection_counts(detection_method)
        
        # Calculate detection latency if tracking
        detection_latency_ms = None
        if track_latency and start_time:
            detection_latency_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            self.detection_latencies.append(detection_latency_ms)
        
        # Build comprehensive result
        result = {
            # Window information
            "window_start": window_features.window_start,
            "window_end": window_features.window_end,
            "service_name": window_features.service_name,
            
            # Rule detection results
            "rule_is_anomaly": rule_is_anomaly,
            "rule_violations": [v["rule_name"] for v in rule_violations],
            "rule_violation_details": rule_violations,
            "rule_confidence": rule_confidence,
            
            # Model detection results
            "model_is_anomaly": model_is_anomaly,
            "model_anomaly_score": model_result["anomaly_score"],
            "model_decision_score": model_result["decision_score"],
            "model_borderline": model_result["is_borderline"],
            "model_borderline_score": model_result["borderline_score"],
            "model_consecutive_borderline": model_result["consecutive_borderline_windows"],
            "model_persistence_triggered": model_result["persistence_triggered"],
            "model_confidence": model_confidence,
            
            # Hybrid detection results
            "hybrid_is_anomaly": hybrid_is_anomaly,
            "hybrid_confidence": hybrid_confidence,
            "hybrid_voting_strategy": self.voting_strategy,
            
            # Final determination
            "final_is_anomaly": hybrid_is_anomaly,  # Default to hybrid result
            "detection_method": detection_method,
            "confidence": hybrid_confidence,
            "is_duplicate": is_duplicate_alert,
            
            # Performance metrics
            "detection_latency_ms": detection_latency_ms,
            "window_feature_count": len(window_features.feature_vector),
            
            # Timestamps
            "detection_timestamp": datetime.utcnow(),
        }
        
        self.detection_counts["total"] += 1
        
        # Add to recent alerts for duplicate detection
        if hybrid_is_anomaly and not is_duplicate_alert:
            self._add_to_recent_alerts(result)
        
        return result
    
    def _calculate_rule_confidence(self, rule_violations: List[Dict[str, Any]]) -> float:
        """
        Calculate confidence score for rule-based detection.
        
        Args:
            rule_violations: List of rule violations
            
        Returns:
            Confidence score between 0 and 1
        """
        if not rule_violations:
            return 0.0
        
        # Severity weights
        severity_weights = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.6,
            "low": 0.4
        }
        
        # Calculate weighted average based on severity
        total_weight = 0
        weighted_sum = 0
        
        for violation in rule_violations:
            severity = violation.get("severity", "medium")
            weight = severity_weights.get(severity, 0.6)
            
            # For threshold violations, confidence increases with distance from threshold
            metric_value = violation.get("metric_value", 0)
            threshold = violation.get("threshold", 0)
            
            if violation["condition_type"] == "threshold":
                if violation["operator"] in [">", ">="]:
                    # Value above threshold
                    if threshold > 0:
                        distance_ratio = max(0, metric_value - threshold) / threshold
                    else:
                        distance_ratio = 1.0 if metric_value > threshold else 0.0
                else:  # "<" or "<="
                    # Value below threshold
                    if threshold > 0:
                        distance_ratio = max(0, threshold - metric_value) / threshold
                    else:
                        distance_ratio = 1.0 if metric_value < threshold else 0.0

                violation_confidence = min(1.0, distance_ratio)
            else:
                # For rate changes, use fixed high confidence
                violation_confidence = 0.8
            
            weighted_sum += violation_confidence * weight
            total_weight += weight
        
        if total_weight > 0:
            return weighted_sum / total_weight
        return 0.0
    
    def _combine_detections(self,
                           rule_is_anomaly: bool,
                           rule_confidence: float,
                           model_is_anomaly: bool,
                           model_confidence: float) -> Tuple[bool, float]:
        """
        Combine rule and model detections based on voting strategy.
        
        Args:
            rule_is_anomaly: Rule detection result
            rule_confidence: Rule confidence score
            model_is_anomaly: Model detection result
            model_confidence: Model confidence score
            
        Returns:
            Tuple of (is_anomaly, confidence)
        """
        if self.voting_strategy == "weighted":
            # Weighted combination of confidences
            combined_confidence = (
                rule_confidence * self.rule_weight +
                model_confidence * self.model_weight
            )
            
            # Determine anomaly based on combined confidence
            anomaly_threshold = 0.5
            is_anomaly = combined_confidence >= anomaly_threshold
            
            return is_anomaly, combined_confidence
        
        elif self.voting_strategy == "majority":
            # Majority vote (rule + model)
            votes = [rule_is_anomaly, model_is_anomaly]
            is_anomaly = sum(votes) >= 1  # At least one says anomaly
            
            # Confidence is average of participating detectors
            confidences = []
            if rule_is_anomaly:
                confidences.append(rule_confidence)
            if model_is_anomaly:
                confidences.append(model_confidence)
            
            confidence = np.mean(confidences) if confidences else 0.0
            return is_anomaly, confidence
        
        elif self.voting_strategy == "union":
            # Union: anomaly if either detector says anomaly
            is_anomaly = rule_is_anomaly or model_is_anomaly
            confidence = max(rule_confidence, model_confidence)
            return is_anomaly, confidence
        
        elif self.voting_strategy == "intersection":
            # Intersection: anomaly only if both detectors say anomaly
            is_anomaly = rule_is_anomaly and model_is_anomaly
            confidence = min(rule_confidence, model_confidence)
            return is_anomaly, confidence
        
        else:
            # Default to weighted strategy
            return self._combine_detections(
                rule_is_anomaly, rule_confidence,
                model_is_anomaly, model_confidence
            )
    
    def _determine_detection_method(self,
                                   rule_is_anomaly: bool,
                                   model_result: Dict[str, Any],
                                   hybrid_is_anomaly: bool) -> str:
        """
        Determine which detection method triggered the anomaly.
        
        Args:
            rule_is_anomaly: Rule detection result
            model_result: Model detection result
            hybrid_is_anomaly: Hybrid detection result
            
        Returns:
            Detection method string
        """
        if not hybrid_is_anomaly:
            return "normal"
        
        # Check if persistence triggered
        if model_result.get("persistence_triggered", False):
            return "borderline_persistence"
        
        # Check individual contributions
        if rule_is_anomaly and model_result["final_is_anomaly"]:
            return "hybrid_both"
        elif rule_is_anomaly:
            return "rule_only"
        elif model_result["final_is_anomaly"]:
            return "model_only"
        else:
            return "hybrid"  # Combined voting triggered it
    
    def _update_detection_counts(self, detection_method: str):
        """Update detection counts based on method."""
        if detection_method == "rule_only":
            self.detection_counts["rule_only"] += 1
        elif detection_method == "model_only":
            self.detection_counts["model_only"] += 1
        elif detection_method == "borderline_persistence":
            self.detection_counts["borderline_persistence"] += 1
        elif detection_method in ["hybrid", "hybrid_both"]:
            self.detection_counts["hybrid"] += 1
    
    def _is_duplicate_alert(self, 
                           window_features: WindowFeatures,
                           rule_violations: List[Dict[str, Any]],
                           detection_method: str) -> bool:
        """
        Check if this alert is a duplicate of a recent alert.
        
        Prevents duplicate alerts for:
        1. Same service with same rule violations within time window
        2. Repeated borderline persistence triggers
        3. Consecutive windows with similar anomaly patterns
        """
        if not self.recent_alerts:
            return False

        # Compare window times (not wall-clock time) so batch re-processing
        # of historical logs suppresses duplicates the same way as real-time
        duplicate_window = timedelta(minutes=self.duplicate_window_minutes)

        # Check recent alerts for duplicates
        for alert in self.recent_alerts:
            # Skip alerts outside the duplicate window
            if abs(window_features.window_start - alert["window_start"]) > duplicate_window:
                continue
            
            # Check for same service
            if alert.get("service_name") != window_features.service_name:
                continue
            
            # Check for same rule violations
            current_rules = set([v["rule_name"] for v in rule_violations])
            alert_rules = set(alert.get("rule_violations", []))
            
            if current_rules and alert_rules and current_rules == alert_rules:
                return True
            
            # Check for similar anomaly patterns
            if (detection_method == alert.get("detection_method") and
                alert.get("model_borderline_score") and 
                window_features.error_rate > 0.2):  # High error rate pattern
                return True
        
        return False
    
    def _add_to_recent_alerts(self, alert: Dict[str, Any]):
        """Add alert to recent alerts list for duplicate detection."""
        self.recent_alerts.append(alert)
        
        # Keep only recent alerts
        if len(self.recent_alerts) > self.max_recent_alerts:
            self.recent_alerts = self.recent_alerts[-self.max_recent_alerts:]
    
    def clear_recent_alerts(self):
        """Clear recent alerts cache."""
        self.recent_alerts = []
    
    def save_detection_result(self, db, detection_result: Dict[str, Any]) -> str:
        """
        Save detection result to MongoDB.
        
        Args:
            db: MongoDB database instance
            detection_result: Detection result dictionary
            
        Returns:
            Document ID
        """
        collection = db["anomaly_results"]
        insert_result = collection.insert_one(self.build_result_document(detection_result))

        return str(insert_result.inserted_id)

    def build_result_document(self, detection_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build the MongoDB document for a detection result.

        The document timestamp is the end of the analysed window (capped at the
        detection time for real-time windows that are still open), so
        time-range filters on the dashboard match when the anomaly happened.
        """
        detected_at = detection_result.get("detection_timestamp", datetime.utcnow())
        result = AnomalyDetectionResult(
            timestamp=min(detection_result["window_end"], detected_at),
            window_start=detection_result["window_start"],
            window_end=detection_result["window_end"],
            service_name=detection_result["service_name"],
            detection_method=detection_result["detection_method"],
            isolation_forest_score=detection_result.get("model_anomaly_score"),
            rule_violations=detection_result.get("rule_violations", []),
            is_anomaly=detection_result["final_is_anomaly"],
            confidence=detection_result["confidence"],
            borderline_score=detection_result.get("model_borderline_score"),
            consecutive_borderline_windows=detection_result.get("model_consecutive_borderline", 0),
            persistence_triggered=detection_result.get("model_persistence_triggered", False),
            detection_latency_ms=detection_result.get("detection_latency_ms"),
            metadata={
                "voting_strategy": self.voting_strategy,
                "rule_confidence": detection_result.get("rule_confidence"),
                "model_confidence": detection_result.get("model_confidence"),
                "hybrid_confidence": detection_result.get("hybrid_confidence"),
                "rule_violation_details": detection_result.get("rule_violation_details", []),
                "detected_at": detected_at
            }
        )

        return result.dict(by_alias=True)
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """
        Get performance summary of the hybrid detector.
        
        Returns:
            Dictionary with performance metrics
        """
        avg_latency = np.mean(self.detection_latencies) if self.detection_latencies else 0
        p95_latency = np.percentile(self.detection_latencies, 95) if self.detection_latencies else 0
        
        return {
            "detection_counts": self.detection_counts,
            "detection_rate_per_minute": self._calculate_detection_rate(),
            "average_latency_ms": avg_latency,
            "p95_latency_ms": p95_latency,
            "total_detections": self.detection_counts["total"],
            "voting_strategy": self.voting_strategy,
            "rule_weight": self.rule_weight,
            "model_weight": self.model_weight
        }
    
    def _calculate_detection_rate(self) -> float:
        """Calculate detection rate per minute."""
        if self.detection_counts["total"] == 0:
            return 0.0
        
        # Assuming 5-minute windows, each detection represents 5 minutes of monitoring
        hours_monitored = (self.detection_counts["total"] * 5) / 60
        if hours_monitored > 0:
            return self.detection_counts["total"] / hours_monitored
        return 0.0
    
    def set_voting_weights(self, rule_weight: float, model_weight: float):
        """
        Set voting weights for weighted strategy.
        
        Args:
            rule_weight: Weight for rule-based detection (0-1)
            model_weight: Weight for model-based detection (0-1)
        """
        if abs(rule_weight + model_weight - 1.0) > 0.001:
            raise ValueError("Weights must sum to 1.0")
        
        self.rule_weight = rule_weight
        self.model_weight = model_weight
    
    def get_detector_config(self) -> Dict[str, Any]:
        """Get configuration of the hybrid detector."""
        model_config = self.model_detector.get_model_summary()
        rule_summary = self.rule_engine.get_rule_summary()
        
        return {
            "voting_strategy": self.voting_strategy,
            "rule_weight": self.rule_weight,
            "model_weight": self.model_weight,
            "model_config": model_config,
            "rule_summary": rule_summary,
            "feature_extractor": {
                "window_size_minutes": self.feature_extractor.window_size_minutes,
                "slide_minutes": self.feature_extractor.slide_minutes,
                "feature_count": len(self.feature_extractor.get_feature_names())
            }
        }