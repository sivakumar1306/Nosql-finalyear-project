"""
MongoDB schema definitions for log data and anomaly detection.
"""

from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from bson import ObjectId


class PyObjectId(ObjectId):
    """Custom ObjectId type for Pydantic."""
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v, _info=None):
        # Pydantic v2 passes a validation info argument, v1 does not
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid objectid")
        return ObjectId(v)

    @classmethod
    def __get_pydantic_json_schema__(cls, field_schema: Dict[str, Any]) -> None:
        field_schema.update(type="string")


class LogEntry(BaseModel):
    """Schema for individual log entries."""
    id: Optional[PyObjectId] = Field(default_factory=PyObjectId, alias="_id")
    timestamp: datetime = Field(...)
    service_name: str = Field(...)
    log_level: str = Field(...)  # INFO, WARNING, ERROR, DEBUG
    message: str = Field(...)
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    endpoint: Optional[str] = None
    http_method: Optional[str] = None
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    request_size_bytes: Optional[int] = None
    response_size_bytes: Optional[int] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "timestamp": "2024-01-01T12:00:00",
                "service_name": "auth-service",
                "log_level": "ERROR",
                "message": "Authentication failed",
                "source_ip": "192.168.1.1",
                "user_id": "user123",
                "endpoint": "/api/login",
                "http_method": "POST",
                "status_code": 401,
                "response_time_ms": 150.5,
                "metadata": {"error_code": "AUTH_FAILED"}
            }
        }


class WindowFeatures(BaseModel):
    """Rolling window-level features for anomaly detection."""
    id: Optional[PyObjectId] = Field(default_factory=PyObjectId, alias="_id")
    window_start: datetime = Field(...)
    window_end: datetime = Field(...)
    window_size_minutes: int = Field(default=5)
    service_name: str = Field(...)
    
    # Rolling window features
    request_count: int = Field(default=0)
    error_count: int = Field(default=0)
    error_rate: float = Field(default=0.0)
    
    # Latency statistics
    avg_response_time_ms: float = Field(default=0.0)
    p95_response_time_ms: float = Field(default=0.0)
    p99_response_time_ms: float = Field(default=0.0)
    max_response_time_ms: float = Field(default=0.0)
    
    # Request size statistics
    avg_request_size_bytes: float = Field(default=0.0)
    avg_response_size_bytes: float = Field(default=0.0)
    
    # HTTP method distribution
    http_method_distribution: Dict[str, int] = Field(default_factory=dict)
    
    # Status code distribution
    status_code_distribution: Dict[int, int] = Field(default_factory=dict)
    
    # Features for ML model
    feature_vector: List[float] = Field(default_factory=list)
    
    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}


class AnomalyDetectionResult(BaseModel):
    """Schema for anomaly detection results."""
    id: Optional[PyObjectId] = Field(default_factory=PyObjectId, alias="_id")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    window_start: datetime = Field(...)
    window_end: datetime = Field(...)
    service_name: str = Field(...)
    
    # Detection methods
    detection_method: str = Field(...)  # "rule", "model", "hybrid", "borderline_persistence"
    
    # Scores and predictions
    isolation_forest_score: Optional[float] = None
    rule_violations: List[str] = Field(default_factory=list)
    is_anomaly: bool = Field(...)
    confidence: float = Field(default=0.0)
    
    # Borderline persistence tracking
    borderline_score: Optional[float] = None
    consecutive_borderline_windows: int = Field(default=0)
    persistence_triggered: bool = Field(default=False)
    
    # Features at detection time
    window_features: Optional[WindowFeatures] = None
    
    # Performance metrics
    detection_latency_ms: Optional[float] = None  # From ingestion to detection
    processing_throughput_logs_per_sec: Optional[float] = None
    
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}


class ModelMetadata(BaseModel):
    """Schema for model versioning and metadata."""
    id: Optional[PyObjectId] = Field(default_factory=PyObjectId, alias="_id")
    model_name: str = Field(default="isolation_forest")
    version: str = Field(...)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    trained_on_window_count: int = Field(...)
    
    # Model performance
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    false_positive_rate: Optional[float] = None
    confusion_matrix: Optional[Dict[str, int]] = None
    
    # Model parameters
    parameters: Dict[str, Any] = Field(default_factory=dict)
    
    # Feature configuration
    feature_columns: List[str] = Field(default_factory=list)
    window_size_minutes: int = Field(default=5)
    
    # Borderline persistence config
    borderline_threshold: float = Field(default=0.4)
    persistence_window_count: int = Field(default=3)
    
    # Model binary (stored separately in GridFS)
    model_gridfs_id: Optional[str] = None
    
    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}


class DetectionRule(BaseModel):
    """Schema for custom detection rules."""
    id: Optional[PyObjectId] = Field(default_factory=PyObjectId, alias="_id")
    rule_name: str = Field(...)
    description: str = Field(...)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    enabled: bool = Field(default=True)
    
    # Rule conditions
    condition_type: str = Field(...)  # "threshold", "rate_change", "pattern"
    service_name: Optional[str] = None  # None means applies to all services
    metric: str = Field(...)  # "error_rate", "avg_response_time", "request_count"
    operator: str = Field(...)  # ">", "<", ">=", "<=", "=="
    threshold: float = Field(...)
    window_size_minutes: int = Field(default=5)
    
    # Pattern matching rules
    pattern: Optional[str] = None
    pattern_window_count: Optional[int] = None
    
    # Alert configuration
    severity: str = Field(default="medium")  # "low", "medium", "high", "critical"
    alert_message_template: str = Field(...)
    
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}