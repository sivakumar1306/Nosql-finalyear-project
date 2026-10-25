"""
Rule-based anomaly detection engine.
Implements custom rules for threshold-based, rate change, and pattern detection.
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
from collections import defaultdict

from models.log_schema import WindowFeatures, AnomalyDetectionResult, DetectionRule
from ml.window_feature_extractor import WindowFeatureExtractor


# Smallest baseline used for rate-change rules, so a jump from 0 to one
# error is not reported as a huge relative spike
RATE_CHANGE_MIN_BASELINE = {
    "error_rate": 0.05,
}


class RuleEngine:
    """
    Rule-based anomaly detection engine.
    
    Supports:
    - Threshold-based rules (error_rate > 0.1, avg_response_time > 1000ms, etc.)
    - Rate change detection (sudden spikes/drops)
    - Pattern matching (repeating patterns of anomalies)
    - Service-specific and global rules
    """
    
    def __init__(self, feature_extractor: Optional[WindowFeatureExtractor] = None):
        """
        Initialize rule engine.
        
        Args:
            feature_extractor: Window feature extractor
        """
        self.feature_extractor = feature_extractor or WindowFeatureExtractor()
        self.rules: List[DetectionRule] = []
        self.rule_cache: Dict[str, DetectionRule] = {}
        
        # Default rules
        self._create_default_rules()
    
    def _create_default_rules(self):
        """Create default detection rules."""
        default_rules = [
            DetectionRule(
                rule_name="high_error_rate",
                description="Error rate exceeds 10%",
                condition_type="threshold",
                metric="error_rate",
                operator=">",
                threshold=0.1,
                window_size_minutes=5,
                severity="high",
                alert_message_template="Error rate for {service_name} is {value:.1%} (threshold: {threshold:.1%})"
            ),
            DetectionRule(
                rule_name="very_high_error_rate",
                description="Error rate exceeds 25%",
                condition_type="threshold",
                metric="error_rate",
                operator=">",
                threshold=0.25,
                window_size_minutes=5,
                severity="critical",
                alert_message_template="CRITICAL: Error rate for {service_name} is {value:.1%} (threshold: {threshold:.1%})"
            ),
            DetectionRule(
                rule_name="high_latency_p95",
                description="95th percentile response time exceeds 1 second",
                condition_type="threshold",
                metric="p95_response_time_ms",
                operator=">",
                threshold=1000,
                window_size_minutes=5,
                severity="medium",
                alert_message_template="High latency for {service_name}: P95 response time is {value:.0f}ms (threshold: {threshold:.0f}ms)"
            ),
            DetectionRule(
                rule_name="high_latency_p99",
                description="99th percentile response time exceeds 2 seconds",
                condition_type="threshold",
                metric="p99_response_time_ms",
                operator=">",
                threshold=2000,
                window_size_minutes=5,
                severity="high",
                alert_message_template="Very high latency for {service_name}: P99 response time is {value:.0f}ms (threshold: {threshold:.0f}ms)"
            ),
            DetectionRule(
                rule_name="low_traffic",
                description="Request count drops below threshold",
                condition_type="threshold",
                metric="request_count",
                operator="<",
                threshold=10,
                window_size_minutes=5,
                severity="medium",
                alert_message_template="Low traffic for {service_name}: only {value:.0f} requests (threshold: {threshold:.0f})"
            ),
            DetectionRule(
                rule_name="sudden_traffic_drop",
                description="Traffic drops by more than 50% compared to previous window",
                condition_type="rate_change",
                metric="request_count",
                operator="<",
                threshold=0.5,  # 50% drop
                window_size_minutes=5,
                severity="high",
                alert_message_template="Sudden traffic drop for {service_name}: {current_value:.0f} requests (was {previous_value:.0f})"
            ),
            DetectionRule(
                rule_name="sudden_error_spike",
                description="Error rate increases by more than 300%",
                condition_type="rate_change",
                metric="error_rate",
                operator=">",
                threshold=3.0,  # 300% increase
                window_size_minutes=5,
                severity="high",
                alert_message_template="Sudden error spike for {service_name}: error rate is {current_value:.1%} (was {previous_value:.1%})"
            ),
        ]
        
        self.rules.extend(default_rules)
        self._update_rule_cache()
    
    def _update_rule_cache(self):
        """Update rule cache for fast lookup."""
        self.rule_cache = {rule.rule_name: rule for rule in self.rules}
    
    def add_rule(self, rule: DetectionRule) -> bool:
        """
        Add a new detection rule.
        
        Args:
            rule: DetectionRule to add
            
        Returns:
            True if added successfully
        """
        self.rules.append(rule)
        self._update_rule_cache()
        return True
    
    def update_rule(self, rule_name: str, updates: Dict[str, Any]) -> bool:
        """
        Update an existing rule.
        
        Args:
            rule_name: Name of rule to update
            updates: Dictionary of fields to update
            
        Returns:
            True if updated successfully
        """
        if rule_name not in self.rule_cache:
            return False
        
        rule = self.rule_cache[rule_name]
        
        # Update rule fields
        for key, value in updates.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
        
        self._update_rule_cache()
        return True
    
    def enable_rule(self, rule_name: str) -> bool:
        """
        Enable a rule.
        
        Args:
            rule_name: Name of rule to enable
            
        Returns:
            True if enabled successfully
        """
        return self.update_rule(rule_name, {"enabled": True})
    
    def disable_rule(self, rule_name: str) -> bool:
        """
        Disable a rule.
        
        Args:
            rule_name: Name of rule to disable
            
        Returns:
            True if disabled successfully
        """
        return self.update_rule(rule_name, {"enabled": False})
    
    def delete_rule(self, rule_name: str) -> bool:
        """
        Delete a rule.
        
        Args:
            rule_name: Name of rule to delete
            
        Returns:
            True if deleted successfully
        """
        if rule_name not in self.rule_cache:
            return False
        
        self.rules = [rule for rule in self.rules if rule.rule_name != rule_name]
        self._update_rule_cache()
        return True
    
    def get_rules_for_service(self, service_name: Optional[str] = None) -> List[DetectionRule]:
        """
        Get rules for a specific service or all services.
        
        Args:
            service_name: Service name filter (None for all services)
            
        Returns:
            List of applicable rules
        """
        applicable_rules = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            # Check if rule applies to this service
            if rule.service_name is None or rule.service_name == service_name:
                applicable_rules.append(rule)
        
        return applicable_rules
    
    def evaluate_window(self, 
                       window_features: WindowFeatures,
                       previous_windows: List[WindowFeatures] = None) -> List[Dict[str, Any]]:
        """
        Evaluate window features against all applicable rules.
        
        Args:
            window_features: Current window features
            previous_windows: Previous window features for rate change detection
            
        Returns:
            List of rule violations
        """
        violations = []
        applicable_rules = self.get_rules_for_service(window_features.service_name)
        
        for rule in applicable_rules:
            result = self._evaluate_rule(rule, window_features, previous_windows)
            if result["violated"]:
                violations.append(result)
        
        return violations
    
    def _evaluate_rule(self, 
                      rule: DetectionRule,
                      window_features: WindowFeatures,
                      previous_windows: List[WindowFeatures] = None) -> Dict[str, Any]:
        """
        Evaluate a single rule against window features.
        
        Args:
            rule: Detection rule
            window_features: Current window features
            previous_windows: Previous window features for rate change detection
            
        Returns:
            Dictionary with evaluation result
        """
        # Get metric value from window features
        metric_value = self._get_metric_value(window_features, rule.metric)
        
        if metric_value is None:
            return {
                "rule_name": rule.rule_name,
                "violated": False,
                "reason": f"Metric {rule.metric} not available"
            }
        
        # Evaluate based on condition type
        if rule.condition_type == "threshold":
            violated = self._evaluate_threshold(metric_value, rule.operator, rule.threshold)
            previous_value = None
        
        elif rule.condition_type == "rate_change":
            if previous_windows:
                # Get previous metric value (average of last 3 windows)
                prev_values = []
                for prev_window in previous_windows[-3:]:  # Last 3 windows
                    val = self._get_metric_value(prev_window, rule.metric)
                    if val is not None:
                        prev_values.append(val)
                
                if prev_values:
                    previous_value = np.mean(prev_values)
                    baseline = max(previous_value, RATE_CHANGE_MIN_BASELINE.get(rule.metric, 0.001))  # Avoid division by zero
                    rate_change = metric_value / baseline
                    violated = self._evaluate_threshold(rate_change, rule.operator, rule.threshold)
                else:
                    violated = False
                    previous_value = None
            else:
                violated = False
                previous_value = None
        
        elif rule.condition_type == "pattern":
            # Pattern matching would require more complex logic
            # For now, skip pattern rules
            violated = False
            previous_value = None
        
        else:
            return {
                "rule_name": rule.rule_name,
                "violated": False,
                "reason": f"Unknown condition type: {rule.condition_type}"
            }
        
        # Build result
        result = {
            "rule_name": rule.rule_name,
            "rule_description": rule.description,
            "violated": violated,
            "condition_type": rule.condition_type,
            "metric": rule.metric,
            "metric_value": metric_value,
            "previous_metric_value": previous_value,
            "operator": rule.operator,
            "threshold": rule.threshold,
            "severity": rule.severity,
            "window_size_minutes": rule.window_size_minutes
        }
        
        # Add alert message if violated
        if violated:
            alert_message = rule.alert_message_template.format(
                service_name=window_features.service_name,
                value=metric_value,
                threshold=rule.threshold,
                current_value=metric_value,
                previous_value=previous_value if previous_value is not None else "N/A"
            )
            result["alert_message"] = alert_message
        
        return result
    
    def _get_metric_value(self, window_features: WindowFeatures, metric: str) -> Optional[float]:
        """
        Get metric value from window features.
        
        Args:
            window_features: WindowFeatures object
            metric: Metric name
            
        Returns:
            Metric value or None if not available
        """
        metric_mapping = {
            "request_count": window_features.request_count,
            "error_count": window_features.error_count,
            "error_rate": window_features.error_rate,
            "avg_response_time_ms": window_features.avg_response_time_ms,
            "p95_response_time_ms": window_features.p95_response_time_ms,
            "p99_response_time_ms": window_features.p99_response_time_ms,
            "max_response_time_ms": window_features.max_response_time_ms,
            "avg_request_size_bytes": window_features.avg_request_size_bytes,
            "avg_response_size_bytes": window_features.avg_response_size_bytes,
        }
        
        return metric_mapping.get(metric)
    
    def _evaluate_threshold(self, value: float, operator: str, threshold: float) -> bool:
        """
        Evaluate threshold condition.
        
        Args:
            value: Current value
            operator: Comparison operator
            threshold: Threshold value
            
        Returns:
            True if condition is met
        """
        # Plain float so the result is a Python bool that MongoDB can store
        value = float(value)

        if operator == ">":
            return value > threshold
        elif operator == "<":
            return value < threshold
        elif operator == ">=":
            return value >= threshold
        elif operator == "<=":
            return value <= threshold
        elif operator == "==":
            return abs(value - threshold) < 0.0001  # Floating point tolerance
        else:
            return False
    
    def save_rules_to_db(self, db) -> bool:
        """
        Save all rules to MongoDB.
        
        Args:
            db: MongoDB database instance
            
        Returns:
            True if saved successfully
        """
        try:
            collection = db["detection_rules"]
            
            # Clear existing rules
            collection.delete_many({})
            
            # Insert all rules
            rule_dicts = [rule.dict(by_alias=True) for rule in self.rules]
            if rule_dicts:
                collection.insert_many(rule_dicts)
            
            print(f"Saved {len(self.rules)} rules to database")
            return True
            
        except Exception as e:
            print(f"Failed to save rules to database: {e}")
            return False
    
    def load_rules_from_db(self, db) -> bool:
        """
        Load rules from MongoDB.
        
        Args:
            db: MongoDB database instance
            
        Returns:
            True if loaded successfully
        """
        try:
            collection = db["detection_rules"]
            rules = []
            
            for doc in collection.find():
                try:
                    rule = DetectionRule(**doc)
                    rules.append(rule)
                except Exception as e:
                    print(f"Failed to parse rule document: {e}")
                    continue

            if not rules:
                # First run: keep the default rules and persist them
                print("No rules in database, saving default rules")
                return self.save_rules_to_db(db)

            self.rules = rules
            self._update_rule_cache()
            
            print(f"Loaded {len(self.rules)} rules from database")
            return True
            
        except Exception as e:
            print(f"Failed to load rules from database: {e}")
            return False
    
    def get_rule_summary(self) -> Dict[str, Any]:
        """Get summary of all rules."""
        enabled_count = sum(1 for rule in self.rules if rule.enabled)
        service_specific_count = sum(1 for rule in self.rules if rule.service_name is not None)
        
        # Count by condition type
        condition_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        
        for rule in self.rules:
            condition_counts[rule.condition_type] += 1
            severity_counts[rule.severity] += 1
        
        return {
            "total_rules": len(self.rules),
            "enabled_rules": enabled_count,
            "disabled_rules": len(self.rules) - enabled_count,
            "service_specific_rules": service_specific_count,
            "global_rules": len(self.rules) - service_specific_count,
            "condition_type_distribution": dict(condition_counts),
            "severity_distribution": dict(severity_counts)
        }