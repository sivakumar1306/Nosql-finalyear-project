"""
Isolation Forest model for anomaly detection with borderline persistence.
Implements configurable persistence rule for borderline scores across consecutive windows.
"""

import pickle
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
import warnings

from models.log_schema import WindowFeatures, AnomalyDetectionResult, ModelMetadata
from ml.window_feature_extractor import WindowFeatureExtractor


class IsolationForestAnomalyDetector:
    """
    Isolation Forest based anomaly detector with borderline persistence.
    
    Features:
    - Isolation Forest training and prediction
    - Borderline score persistence across consecutive windows
    - Configurable thresholds and persistence rules
    - Model versioning and metadata tracking
    """

    # Steepness of the decision score -> [0, 1] anomaly score mapping
    SCORE_SCALE = 20.0

    def __init__(self, 
                 contamination: float = 0.1,
                 n_estimators: int = 100,
                 max_samples: float = 0.8,
                 borderline_threshold: float = 0.4,
                 persistence_window_count: int = 3):
        """
        Initialize Isolation Forest detector.
        
        Args:
            contamination: Expected proportion of anomalies in the data
            n_estimators: Number of trees in the forest
            max_samples: Number of samples to draw for each tree
            borderline_threshold: Score threshold for borderline cases (0-1)
            persistence_window_count: Number of consecutive borderline windows to trigger alert
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        
        # Borderline persistence configuration
        self.borderline_threshold = borderline_threshold
        self.persistence_window_count = persistence_window_count
        
        # Model components
        self.model = None
        self.scaler = StandardScaler()
        self.feature_extractor = WindowFeatureExtractor()
        self.feature_names = self.feature_extractor.get_feature_names()
        
        # Training metadata
        self.trained_on_window_count = 0
        self.training_start_time = None
        self.training_end_time = None
        
        # Performance metrics
        self.precision = None
        self.recall = None
        self.f1_score_val = None
        self.false_positive_rate = None
        self.confusion_matrix_data = None
        
    def train(self, training_features: List[WindowFeatures], 
              labels: Optional[List[bool]] = None) -> bool:
        """
        Train Isolation Forest model on window features.
        
        Args:
            training_features: List of WindowFeatures for training
            labels: Optional ground truth labels for evaluation
            
        Returns:
            True if training successful
        """
        if not training_features:
            raise ValueError("No training features provided")
        
        print(f"Training Isolation Forest model on {len(training_features)} windows...")
        
        # Extract feature vectors
        X = np.array([wf.feature_vector for wf in training_features])
        
        # Standardize features
        X_scaled = self.scaler.fit_transform(X)
        
        # Initialize and train model
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            max_samples=self.max_samples,
            random_state=42,
            n_jobs=-1
        )
        
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self.model.fit(X_scaled)
        
        # Update training metadata
        self.trained_on_window_count = len(training_features)
        self.training_start_time = min(wf.window_start for wf in training_features)
        self.training_end_time = max(wf.window_end for wf in training_features)
        
        # Evaluate if labels are provided
        if labels is not None:
            self.evaluate(training_features, labels)
        
        print("Model training completed successfully.")
        return True
    
    def predict(self, window_features: WindowFeatures) -> Dict[str, Any]:
        """
        Predict anomaly for a single window.
        
        Args:
            window_features: WindowFeatures to predict
            
        Returns:
            Dictionary with prediction results
        """
        if self.model is None:
            raise RuntimeError("Model not trained. Call train() first.")
        
        # Extract and scale features
        X = np.array([window_features.feature_vector])
        X_scaled = self.scaler.transform(X)
        
        # Get anomaly score (-1 for anomalies, 1 for normal)
        raw_prediction = self.model.predict(X_scaled)[0]
        
        # Get decision function score (more negative = more anomalous)
        decision_score = self.model.decision_function(X_scaled)[0]
        
        # Convert to anomaly score between 0 and 1
        # Normalize decision score to [0, 1] where 1 = most anomalous
        anomaly_score = self._normalize_score(decision_score)
        
        # Determine if anomaly based on threshold
        is_anomaly = raw_prediction == -1
        
        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "decision_score": decision_score,
            "raw_prediction": raw_prediction
        }
    
    def predict_with_persistence(self, 
                                window_features: WindowFeatures,
                                previous_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Predict anomaly with borderline persistence logic.
        
        Args:
            window_features: Current window features
            previous_results: Previous prediction results for same service
            
        Returns:
            Dictionary with prediction results including persistence logic
        """
        # Get base prediction
        base_prediction = self.predict(window_features)
        anomaly_score = base_prediction["anomaly_score"]
        
        # Check if score is borderline
        is_borderline = self.borderline_threshold <= anomaly_score < 0.5
        
        # Count consecutive borderline windows
        consecutive_borderline = 0
        # previous_results are oldest first; stored anomaly_results documents
        # carry borderline_score instead of is_borderline
        for result in reversed(previous_results):
            if result.get("is_borderline", result.get("borderline_score") is not None):
                consecutive_borderline += 1
            else:
                break
        
        # Determine if persistence triggers anomaly
        persistence_triggered = False
        if is_borderline:
            consecutive_borderline += 1
            if consecutive_borderline >= self.persistence_window_count:
                persistence_triggered = True
        
        # Final anomaly determination
        final_is_anomaly = base_prediction["is_anomaly"] or persistence_triggered
        
        # Build result
        result = {
            **base_prediction,
            "is_borderline": is_borderline,
            "borderline_score": anomaly_score if is_borderline else None,
            "consecutive_borderline_windows": consecutive_borderline,
            "persistence_triggered": persistence_triggered,
            "final_is_anomaly": final_is_anomaly,
            "detection_method": "model_only"
        }
        
        # Update detection method if persistence was involved
        if persistence_triggered:
            result["detection_method"] = "borderline_persistence"
        
        return result
    
    def evaluate(self, test_features: List[WindowFeatures], 
                 true_labels: List[bool]) -> Dict[str, Any]:
        """
        Evaluate model performance.
        
        Args:
            test_features: Test window features
            true_labels: Ground truth labels
            
        Returns:
            Dictionary with evaluation metrics
        """
        if self.model is None:
            raise RuntimeError("Model not trained. Call train() first.")
        
        print("Evaluating model performance...")
        
        # Extract features
        X = np.array([wf.feature_vector for wf in test_features])
        X_scaled = self.scaler.transform(X)
        
        # Get predictions
        predictions = self.model.predict(X_scaled)
        predicted_labels = (predictions == -1)  # Convert to boolean
        
        # Calculate metrics
        precision = precision_score(true_labels, predicted_labels, zero_division=0)
        recall = recall_score(true_labels, predicted_labels, zero_division=0)
        f1 = f1_score(true_labels, predicted_labels, zero_division=0)
        
        # Calculate false positive rate
        tn, fp, fn, tp = confusion_matrix(true_labels, predicted_labels).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        # Store confusion matrix
        cm = confusion_matrix(true_labels, predicted_labels)
        cm_dict = {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp)
        }
        
        # Store metrics
        self.precision = precision
        self.recall = recall
        self.f1_score_val = f1
        self.false_positive_rate = fpr
        self.confusion_matrix_data = cm_dict
        
        # Calculate per-scenario metrics if we have scenario info
        per_scenario_recall = self._calculate_per_scenario_recall(
            test_features, true_labels, predicted_labels
        )
        
        metrics = {
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "false_positive_rate": fpr,
            "confusion_matrix": cm_dict,
            "per_scenario_recall": per_scenario_recall,
            "test_window_count": len(test_features),
            "anomaly_count_true": sum(true_labels),
            "anomaly_count_predicted": sum(predicted_labels)
        }
        
        print(f"Evaluation complete: F1={f1:.3f}, Precision={precision:.3f}, Recall={recall:.3f}")
        return metrics
    
    def _calculate_per_scenario_recall(self, test_features: List[WindowFeatures],
                                      true_labels: List[bool],
                                      predicted_labels: List[bool]) -> Dict[str, float]:
        """
        Calculate recall for different anomaly scenarios.
        
        Args:
            test_features: Test window features
            true_labels: Ground truth labels
            predicted_labels: Predicted labels
            
        Returns:
            Dictionary with recall per scenario
        """
        # Group anomalies by scenario (simplified - in real implementation,
        # you would have scenario labels in metadata)
        scenarios = {}
        
        # For now, create scenarios based on feature patterns
        for i, (wf, true, pred) in enumerate(zip(test_features, true_labels, predicted_labels)):
            if true:  # Only for actual anomalies
                # Determine scenario type based on features
                if wf.error_rate > 0.3:
                    scenario = "high_error_rate"
                elif wf.avg_response_time_ms > 1000:
                    scenario = "high_latency"
                elif wf.request_count < 5:
                    scenario = "low_traffic"
                else:
                    scenario = "other"
                
                if scenario not in scenarios:
                    scenarios[scenario] = {"true": 0, "detected": 0}
                
                scenarios[scenario]["true"] += 1
                if pred:
                    scenarios[scenario]["detected"] += 1
        
        # Calculate recall per scenario
        per_scenario_recall = {}
        for scenario, counts in scenarios.items():
            recall = counts["detected"] / counts["true"] if counts["true"] > 0 else 0
            per_scenario_recall[scenario] = recall
        
        return per_scenario_recall
    
    def _normalize_score(self, decision_score: float) -> float:
        """
        Normalize decision score to [0, 1] where 1 = most anomalous.
        
        Args:
            decision_score: Isolation Forest decision function score
            
        Returns:
            Normalized anomaly score between 0 and 1
        """
        # Isolation Forest decision scores are negative for anomalies
        # We want to map to [0, 1] where 1 is most anomalous
        
        # Decision scores of real windows mostly fall in [-0.2, 0.2], with 0 at
        # the contamination cut-off. A steep sigmoid keeps 0 at 0.5 and spreads
        # that range over [0, 1], so only windows close to the cut-off land in
        # the borderline band instead of nearly every normal window.
        normalized = 1 / (1 + np.exp(self.SCORE_SCALE * decision_score))
        
        # Ensure it's in [0, 1]
        return max(0.0, min(1.0, normalized))
    
    def save_model_metadata(self, db, version: str = "1.0.0") -> str:
        """
        Save model metadata to MongoDB.
        
        Args:
            db: MongoDB database instance
            version: Model version string
            
        Returns:
            Model metadata ID
        """
        if self.model is None:
            raise RuntimeError("Model not trained. Call train() first.")
        
        # Serialize model
        model_bytes = pickle.dumps({
            "model": self.model,
            "scaler": self.scaler,
            "feature_names": self.feature_names
        })
        
        # Save model to GridFS
        from config.database import db_manager
        gridfs_id = db_manager.save_model_to_gridfs(
            model_bytes,
            filename=f"isolation_forest_v{version}",
            metadata={
                "contamination": self.contamination,
                "n_estimators": self.n_estimators,
                "max_samples": self.max_samples
            }
        )
        
        # Create metadata document
        metadata = ModelMetadata(
            model_name="isolation_forest",
            version=version,
            trained_on_window_count=self.trained_on_window_count,
            precision=self.precision,
            recall=self.recall,
            f1_score=self.f1_score_val,
            false_positive_rate=self.false_positive_rate,
            confusion_matrix=self.confusion_matrix_data,
            parameters={
                "contamination": self.contamination,
                "n_estimators": self.n_estimators,
                "max_samples": self.max_samples,
                "borderline_threshold": self.borderline_threshold,
                "persistence_window_count": self.persistence_window_count
            },
            feature_columns=self.feature_names,
            window_size_minutes=self.feature_extractor.window_size_minutes,
            borderline_threshold=self.borderline_threshold,
            persistence_window_count=self.persistence_window_count,
            model_gridfs_id=gridfs_id
        )
        
        # Save to MongoDB
        collection = db["model_metadata"]
        result = collection.insert_one(metadata.dict(by_alias=True))
        
        print(f"Model metadata saved with ID: {result.inserted_id}")
        return str(result.inserted_id)
    
    def load_model_metadata(self, db, version: Optional[str] = None) -> Optional[ModelMetadata]:
        """
        Load model metadata from MongoDB.
        
        Args:
            db: MongoDB database instance
            version: Specific version to load (loads latest if None)
            
        Returns:
            ModelMetadata object or None
        """
        collection = db["model_metadata"]
        
        query = {"model_name": "isolation_forest"}
        if version:
            query["version"] = version
        
        # Find the model
        doc = collection.find_one(query, sort=[("created_at", -1)])
        
        if not doc:
            return None
        
        return ModelMetadata(**doc)
    
    def load_model_from_metadata(self, db, metadata: ModelMetadata) -> bool:
        """
        Load model from GridFS using metadata.
        
        Args:
            db: MongoDB database instance
            metadata: ModelMetadata object
            
        Returns:
            True if loaded successfully
        """
        from config.database import db_manager
        
        try:
            # Load model from GridFS
            model_bytes = db_manager.load_model_from_gridfs(metadata.model_gridfs_id)
            model_data = pickle.loads(model_bytes)
            
            # Restore model components
            self.model = model_data["model"]
            self.scaler = model_data["scaler"]
            self.feature_names = model_data["feature_names"]
            
            # Restore configuration
            if "parameters" in metadata.dict():
                params = metadata.parameters
                self.contamination = params.get("contamination", 0.1)
                self.n_estimators = params.get("n_estimators", 100)
                self.max_samples = params.get("max_samples", 0.8)
                self.borderline_threshold = params.get("borderline_threshold", 0.4)
                self.persistence_window_count = params.get("persistence_window_count", 3)
            
            # Restore performance metrics
            self.precision = metadata.precision
            self.recall = metadata.recall
            self.f1_score_val = metadata.f1_score
            self.false_positive_rate = metadata.false_positive_rate
            self.confusion_matrix_data = metadata.confusion_matrix
            
            print(f"Model loaded successfully: version {metadata.version}")
            return True
            
        except Exception as e:
            print(f"Failed to load model: {e}")
            return False
    
    def get_model_summary(self) -> Dict[str, Any]:
        """Get summary of model configuration and performance."""
        return {
            "model_type": "IsolationForest",
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
            "max_samples": self.max_samples,
            "borderline_threshold": self.borderline_threshold,
            "persistence_window_count": self.persistence_window_count,
            "trained_on_window_count": self.trained_on_window_count,
            "feature_count": len(self.feature_names),
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score_val,
            "false_positive_rate": self.false_positive_rate,
            "training_time_range": {
                "start": self.training_start_time,
                "end": self.training_end_time
            } if self.training_start_time else None
        }