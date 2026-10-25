"""
MongoDB index definitions for optimal query performance.
"""

from pymongo import ASCENDING, DESCENDING, TEXT, HASHED


# Index definitions for different collections
LOG_ENTRY_INDEXES = [
    # Primary query patterns
    [("timestamp", DESCENDING), ("service_name", ASCENDING)],
    [("service_name", ASCENDING), ("timestamp", DESCENDING)],
    [("log_level", ASCENDING), ("timestamp", DESCENDING)],
    
    # For endpoint analysis
    [("endpoint", ASCENDING), ("timestamp", DESCENDING)],
    
    # For user-specific queries
    [("user_id", ASCENDING), ("timestamp", DESCENDING)],
    
    # For source IP analysis
    [("source_ip", ASCENDING), ("timestamp", DESCENDING)],
    
    # Text search on message field
    [("message", TEXT)],
    
    # Composite index for status monitoring
    [("status_code", ASCENDING), ("timestamp", DESCENDING)],
    
    # TTL index for automatic log expiration (30 days)
    [("timestamp", ASCENDING), {"expireAfterSeconds": 2592000}],
]


WINDOW_FEATURES_INDEXES = [
    # Primary query for window analysis
    [("window_start", DESCENDING), ("service_name", ASCENDING)],
    [("service_name", ASCENDING), ("window_start", DESCENDING)],
    
    # For time-range queries
    [("window_end", ASCENDING)],
    
    # For feature-based queries
    [("error_rate", DESCENDING), ("window_start", DESCENDING)],
    [("avg_response_time_ms", DESCENDING), ("window_start", DESCENDING)],
    
    # TTL index for window features (90 days)
    [("window_start", ASCENDING), {"expireAfterSeconds": 7776000}],
]


ANOMALY_RESULT_INDEXES = [
    # Primary query for anomaly detection results
    [("timestamp", DESCENDING), ("service_name", ASCENDING)],
    [("service_name", ASCENDING), ("timestamp", DESCENDING)],
    
    # For detection method analysis
    [("detection_method", ASCENDING), ("timestamp", DESCENDING)],
    
    # For anomaly severity queries
    [("is_anomaly", ASCENDING), ("timestamp", DESCENDING)],
    
    # For borderline persistence analysis
    [("borderline_score", DESCENDING), ("timestamp", DESCENDING)],
    [("consecutive_borderline_windows", DESCENDING)],
    
    # For window-based queries
    [("window_start", DESCENDING)],
    
    # For performance monitoring
    [("detection_latency_ms", DESCENDING)],
    
    # TTL index for anomaly results (180 days)
    [("timestamp", ASCENDING), {"expireAfterSeconds": 15552000}],
]


MODEL_METADATA_INDEXES = [
    # Version-based queries
    [("model_name", ASCENDING), ("version", DESCENDING)],
    
    # For model performance comparison
    [("f1_score", DESCENDING)],
    
    # Timestamp-based queries
    [("created_at", DESCENDING)],
]


DETECTION_RULE_INDEXES = [
    # Rule lookup by name and service
    [("rule_name", ASCENDING)],
    [("service_name", ASCENDING), ("enabled", ASCENDING)],
    
    # For rule type queries
    [("condition_type", ASCENDING), ("enabled", ASCENDING)],
    
    # For severity-based queries
    [("severity", ASCENDING), ("enabled", ASCENDING)],
]


def create_indexes(db):
    """
    Create all necessary indexes in the MongoDB database.
    
    Args:
        db: MongoDB database instance
    """
    print("Creating MongoDB indexes...")
    
    # Log entries collection
    log_collection = db["log_entries"]
    for index in LOG_ENTRY_INDEXES:
        if isinstance(index[-1], dict):  # TTL index
            log_collection.create_index([index[0]], **index[1])
        else:
            log_collection.create_index(index)
    
    # Window features collection
    window_collection = db["window_features"]
    for index in WINDOW_FEATURES_INDEXES:
        if isinstance(index[-1], dict):  # TTL index
            window_collection.create_index([index[0]], **index[1])
        else:
            window_collection.create_index(index)
    
    # Anomaly results collection
    anomaly_collection = db["anomaly_results"]
    for index in ANOMALY_RESULT_INDEXES:
        if isinstance(index[-1], dict):  # TTL index
            anomaly_collection.create_index([index[0]], **index[1])
        else:
            anomaly_collection.create_index(index)
    
    # Model metadata collection
    model_collection = db["model_metadata"]
    for index in MODEL_METADATA_INDEXES:
        model_collection.create_index(index)
    
    # Detection rules collection
    rule_collection = db["detection_rules"]
    for index in DETECTION_RULE_INDEXES:
        rule_collection.create_index(index)
    
    print("MongoDB indexes created successfully.")
    return True