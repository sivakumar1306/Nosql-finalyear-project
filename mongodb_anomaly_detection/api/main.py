"""
Main FastAPI application for the anomaly detection backend.
Implements all required REST API endpoints.
"""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Query, Depends, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import numpy as np

from config.database import get_db, db_manager
from models.log_schema import LogEntry, WindowFeatures, AnomalyDetectionResult, ModelMetadata, DetectionRule
from ml.window_feature_extractor import WindowFeatureExtractor
from ml.isolation_forest_model import IsolationForestAnomalyDetector
from rules.rule_engine import RuleEngine
from ml.hybrid_detector import HybridAnomalyDetector
from ml.detection_pipeline import run_detection_pipeline, window_to_document
import uuid


# Pydantic models for API requests/responses
class SummaryResponse(BaseModel):
    """Response model for /api/summary endpoint."""
    total_logs: int = Field(..., description="Total number of log entries")
    total_anomalies: int = Field(..., description="Total number of detected anomalies")
    services: List[str] = Field(..., description="List of unique service names")
    time_range: Dict[str, Optional[datetime]] = Field(..., description="Earliest and latest timestamps (null when no logs match)")
    anomaly_rate: float = Field(..., description="Percentage of logs that are anomalies")
    recent_anomalies: int = Field(..., description="Anomalies in the last 24 hours")
    
    # Window statistics
    total_windows: int = Field(..., description="Total number of window features")
    avg_window_size: Dict[str, float] = Field(..., description="Average window statistics")
    
    # Model statistics
    model_versions: List[str] = Field(..., description="Available model versions")
    active_rules: int = Field(..., description="Number of active detection rules")
    
    # Performance metrics
    avg_detection_latency_ms: Optional[float] = Field(None, description="Average detection latency")
    throughput_windows_per_hour: Optional[float] = Field(None, description="Throughput in windows per hour")


class ServiceResponse(BaseModel):
    """Response model for /api/services/:serviceName endpoint."""
    service_name: str = Field(..., description="Service name")
    total_logs: int = Field(..., description="Total logs for this service")
    total_anomalies: int = Field(..., description="Total anomalies for this service")
    anomaly_rate: float = Field(..., description="Anomaly rate for this service")
    
    # Time-based statistics
    logs_last_hour: int = Field(..., description="Logs in the last hour")
    anomalies_last_hour: int = Field(..., description="Anomalies in the last hour")
    
    # Performance metrics
    avg_response_time_ms: float = Field(..., description="Average response time")
    p95_response_time_ms: float = Field(..., description="95th percentile response time")
    error_rate: float = Field(..., description="Error rate")
    
    # Recent anomalies
    recent_anomalies: List[Dict[str, Any]] = Field(..., description="Recent anomalies (last 10)")
    
    # Window statistics
    window_stats: Dict[str, Any] = Field(..., description="Window-level statistics")
    
    # Detection method breakdown
    detection_methods: Dict[str, int] = Field(..., description="Breakdown by detection method")


class RetrainRequest(BaseModel):
    """Request model for /api/model/retrain endpoint."""
    training_hours: int = Field(default=24, description="Hours of training data to use")
    contamination: float = Field(default=0.1, description="Expected anomaly contamination")
    borderline_threshold: Optional[float] = Field(0.4, description="Borderline threshold")
    persistence_window_count: Optional[int] = Field(3, description="Persistence window count")
    version_suffix: Optional[str] = Field(None, description="Version suffix for the new model")


class RetrainResponse(BaseModel):
    """Response model for /api/model/retrain endpoint."""
    success: bool = Field(..., description="Whether retraining was successful")
    model_version: str = Field(..., description="New model version")
    training_windows: int = Field(..., description="Number of windows used for training")
    performance_metrics: Dict[str, float] = Field(..., description="Model performance metrics")
    training_time_seconds: float = Field(..., description="Time taken for training")
    message: str = Field(..., description="Status message")


class LogIngestionRequest(BaseModel):
    """Request model for log ingestion."""
    service_name: str = Field(..., description="Service name")
    log_level: str = Field(..., description="Log level (INFO, WARNING, ERROR, DEBUG)")
    message: str = Field(..., description="Log message")
    source_ip: Optional[str] = Field(None, description="Source IP address")
    user_id: Optional[str] = Field(None, description="User ID")
    endpoint: Optional[str] = Field(None, description="API endpoint")
    http_method: Optional[str] = Field(None, description="HTTP method")
    status_code: Optional[int] = Field(None, description="HTTP status code")
    response_time_ms: Optional[float] = Field(None, description="Response time in milliseconds")
    request_size_bytes: Optional[int] = Field(None, description="Request size in bytes")
    response_size_bytes: Optional[int] = Field(None, description="Response size in bytes")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")


class LogIngestionResponse(BaseModel):
    """Response model for log ingestion."""
    log_id: str = Field(..., description="Unique log entry ID")
    timestamp: datetime = Field(..., description="Ingestion timestamp")
    processed: bool = Field(..., description="Whether log was processed")
    detection_triggered: bool = Field(default=False, description="Whether anomaly detection was triggered")
    message: str = Field(..., description="Status message")


class PaginatedResponse(BaseModel):
    """Base model for paginated responses."""
    data: List[Dict[str, Any]]
    total: int
    page: int
    page_size: int
    total_pages: int


# Initialize FastAPI app
app = FastAPI(
    title="Log Anomaly Detection API",
    description="REST API for real-time log monitoring and anomaly detection",
    version="1.0.0"
)

# Add CORS middleware for React dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],  # React dev servers
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
feature_extractor = WindowFeatureExtractor(window_size_minutes=5, slide_minutes=1)
model_detector: Optional[IsolationForestAnomalyDetector] = None
rule_engine: Optional[RuleEngine] = None
hybrid_detector: Optional[HybridAnomalyDetector] = None


def get_detectors():
    """Dependency to get initialized detectors."""
    global model_detector, rule_engine, hybrid_detector
    
    if model_detector is None or rule_engine is None or hybrid_detector is None:
        db = get_db()
        
        # Load latest model
        model_detector = IsolationForestAnomalyDetector()
        metadata = model_detector.load_model_metadata(db)
        if metadata:
            model_detector.load_model_from_metadata(db, metadata)
        
        # Initialize rule engine
        rule_engine = RuleEngine(feature_extractor)
        rule_engine.load_rules_from_db(db)
        
        # Initialize hybrid detector
        hybrid_detector = HybridAnomalyDetector(
            model_detector=model_detector,
            rule_engine=rule_engine,
            voting_strategy="weighted"
        )
    
    return model_detector, rule_engine, hybrid_detector


@app.on_event("startup")
async def startup_event():
    """Initialize components on startup."""
    print("Starting up anomaly detection API...")
    
    # Initialize database
    if not db_manager.connect():
        print("Warning: Failed to connect to MongoDB")
    
    # Initialize detectors
    get_detectors()
    
    print("API startup complete")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    print("Shutting down anomaly detection API...")
    db_manager.disconnect()
    print("API shutdown complete")


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "message": "Log Anomaly Detection API",
        "version": "1.0.0",
        "endpoints": {
            "/api/summary": "GET - Get system summary statistics",
            "/api/services": "GET - Get list of all services",
            "/api/services/{service_name}": "GET - Get detailed service statistics",
            "/api/logs": "GET - Get paginated log entries",
            "/api/anomalies": "GET - Get paginated anomaly results",
            "/api/model/retrain": "POST - Retrain the anomaly detection model",
            "/api/model/versions": "GET - Get model versions",
            "/api/rules": "GET - Get detection rules",
            "/api/health": "GET - Health check"
        }
    }


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    db_status = "connected" if db_manager.db is not None else "disconnected"
    model_status = "loaded" if model_detector and model_detector.model else "not_loaded"
    rule_status = "loaded" if rule_engine and rule_engine.rules else "not_loaded"
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "database": db_status,
        "model": model_status,
        "rules": rule_status,
        "uptime_seconds": (datetime.utcnow() - app.startup_time).total_seconds() if hasattr(app, 'startup_time') else 0
    }


@app.get("/api/summary", response_model=SummaryResponse)
async def get_summary(
    time_range: Optional[str] = Query(None, description="Time range filter (e.g., '24h', '7d')")
):
    """
    Get system-wide summary statistics.
    
    Uses MongoDB aggregation for efficient querying.
    """
    db = get_db()
    
    try:
        # Build time filter
        time_filter = {}
        if time_range:
            hours = 24
            if time_range.endswith('h'):
                hours = int(time_range[:-1])
            elif time_range.endswith('d'):
                hours = int(time_range[:-1]) * 24
            
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            time_filter = {"timestamp": {"$gte": cutoff_time}}
        
        # Get total logs count
        total_logs = db["log_entries"].count_documents(time_filter)
        
        # Get total anomalies count
        anomaly_filter = {"is_anomaly": True}
        if time_filter:
            anomaly_filter.update(time_filter)
        
        total_anomalies = db["anomaly_results"].count_documents(anomaly_filter)
        
        # Get unique services using aggregation for efficiency
        services_pipeline = [
            {"$group": {"_id": "$service_name"}},
            {"$sort": {"_id": 1}}
        ]
        if time_filter:
            services_pipeline.insert(0, {"$match": time_filter})
        
        services_cursor = db["log_entries"].aggregate(services_pipeline)
        services = [doc["_id"] for doc in services_cursor]
        
        # Get time range using aggregation
        time_range_pipeline = [
            {"$group": {
                "_id": None,
                "min_time": {"$min": "$timestamp"},
                "max_time": {"$max": "$timestamp"}
            }}
        ]
        if time_filter:
            time_range_pipeline.insert(0, {"$match": time_filter})
        
        time_range_result = list(db["log_entries"].aggregate(time_range_pipeline))
        time_range_data = {
            "earliest": time_range_result[0]["min_time"] if time_range_result else None,
            "latest": time_range_result[0]["max_time"] if time_range_result else None
        }
        
        # Calculate anomaly rate
        anomaly_rate = total_anomalies / max(total_logs, 1)
        
        # Get recent anomalies (last 24 hours)
        recent_cutoff = datetime.utcnow() - timedelta(hours=24)
        recent_anomalies = db["anomaly_results"].count_documents({
            "is_anomaly": True,
            "timestamp": {"$gte": recent_cutoff}
        })
        
        # Get window statistics
        total_windows = db["window_features"].count_documents({})
        
        # Get average window statistics using aggregation
        window_stats_pipeline = [
            {"$group": {
                "_id": None,
                "avg_request_count": {"$avg": "$request_count"},
                "avg_error_rate": {"$avg": "$error_rate"},
                "avg_response_time": {"$avg": "$avg_response_time_ms"}
            }}
        ]
        
        window_stats_result = list(db["window_features"].aggregate(window_stats_pipeline))
        avg_window_size = {
            "request_count": window_stats_result[0]["avg_request_count"] if window_stats_result else 0,
            "error_rate": window_stats_result[0]["avg_error_rate"] if window_stats_result else 0,
            "response_time_ms": window_stats_result[0]["avg_response_time"] if window_stats_result else 0
        }
        
        # Get model versions
        model_versions = [doc["version"] for doc in db["model_metadata"].find({}, {"version": 1}).sort("created_at", -1)]
        
        # Get active rules count
        active_rules = db["detection_rules"].count_documents({"enabled": True})
        
        # Get performance metrics
        latency_pipeline = [
            {"$match": {"detection_latency_ms": {"$exists": True, "$ne": None}}},
            {"$group": {
                "_id": None,
                "avg_latency": {"$avg": "$detection_latency_ms"}
            }}
        ]
        
        latency_result = list(db["anomaly_results"].aggregate(latency_pipeline))
        avg_detection_latency = latency_result[0]["avg_latency"] if latency_result else None
        
        # Calculate throughput (windows per hour)
        throughput_pipeline = [
            {"$group": {
                "_id": {"$dateToString": {"format": "%Y-%m-%dT%H:00:00", "date": "$timestamp"}},
                "count": {"$sum": 1}
            }},
            {"$group": {
                "_id": None,
                "avg_per_hour": {"$avg": "$count"}
            }}
        ]
        
        throughput_result = list(db["window_features"].aggregate(throughput_pipeline))
        throughput_windows_per_hour = throughput_result[0]["avg_per_hour"] if throughput_result else None
        
        return SummaryResponse(
            total_logs=total_logs,
            total_anomalies=total_anomalies,
            services=services,
            time_range=time_range_data,
            anomaly_rate=anomaly_rate,
            recent_anomalies=recent_anomalies,
            total_windows=total_windows,
            avg_window_size=avg_window_size,
            model_versions=model_versions,
            active_rules=active_rules,
            avg_detection_latency_ms=avg_detection_latency,
            throughput_windows_per_hour=throughput_windows_per_hour
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating summary: {str(e)}")


@app.get("/api/services", response_model=List[str])
async def get_services():
    """Get list of all unique service names."""
    db = get_db()
    
    try:
        # Use aggregation with index for efficiency
        pipeline = [
            {"$group": {"_id": "$service_name"}},
            {"$sort": {"_id": 1}},
            {"$limit": 100}  # Limit to 100 services
        ]
        
        services_cursor = db["log_entries"].aggregate(pipeline)
        services = [doc["_id"] for doc in services_cursor]
        
        return services
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching services: {str(e)}")


@app.get("/api/services/{service_name}", response_model=ServiceResponse)
async def get_service_details(
    service_name: str,
    time_range: Optional[str] = Query(None, description="Time range filter (e.g., '24h', '7d')")
):
    """
    Get detailed statistics for a specific service.
    
    Uses MongoDB aggregation with indexes for optimal performance.
    """
    db = get_db()
    
    try:
        # Build time filter
        time_filter = {"service_name": service_name}
        if time_range:
            hours = 24
            if time_range.endswith('h'):
                hours = int(time_range[:-1])
            elif time_range.endswith('d'):
                hours = int(time_range[:-1]) * 24
            
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            time_filter["timestamp"] = {"$gte": cutoff_time}
        
        # Get total logs for this service
        total_logs = db["log_entries"].count_documents(time_filter)
        
        # Unknown service -> 404; a known service with no logs in the range returns zeros
        if total_logs == 0 and db["log_entries"].count_documents({"service_name": service_name}, limit=1) == 0:
            raise HTTPException(status_code=404, detail=f"Service '{service_name}' not found")
        
        # Get anomaly statistics
        anomaly_filter = {
            "service_name": service_name,
            "is_anomaly": True
        }
        if "timestamp" in time_filter:
            anomaly_filter["timestamp"] = time_filter["timestamp"]
        
        total_anomalies = db["anomaly_results"].count_documents(anomaly_filter)
        anomaly_rate = total_anomalies / max(total_logs, 1)
        
        # Get logs and anomalies from last hour
        last_hour_cutoff = datetime.utcnow() - timedelta(hours=1)
        last_hour_filter = {
            "service_name": service_name,
            "timestamp": {"$gte": last_hour_cutoff}
        }
        
        logs_last_hour = db["log_entries"].count_documents(last_hour_filter)
        
        last_hour_anomaly_filter = {
            "service_name": service_name,
            "is_anomaly": True,
            "timestamp": {"$gte": last_hour_cutoff}
        }
        anomalies_last_hour = db["anomaly_results"].count_documents(last_hour_anomaly_filter)
        
        # Get performance metrics using aggregation
        metrics_pipeline = [
            {"$match": time_filter},
            {"$group": {
                "_id": "$service_name",
                "avg_response_time": {"$avg": "$response_time_ms"},
                "p95_response_time": {"$percentile": {
                    "input": "$response_time_ms",
                    "p": [0.95],
                    "method": "approximate"
                }},
                "error_count": {"$sum": {"$cond": [{"$eq": ["$log_level", "ERROR"]}, 1, 0]}},
                "total_count": {"$sum": 1}
            }}
        ]
        
        metrics_result = list(db["log_entries"].aggregate(metrics_pipeline))
        
        if metrics_result:
            avg_response_time = metrics_result[0]["avg_response_time"] or 0
            p95_response_time = metrics_result[0]["p95_response_time"][0] if metrics_result[0]["p95_response_time"] else 0
            error_count = metrics_result[0]["error_count"]
            total_count = metrics_result[0]["total_count"]
            error_rate = error_count / max(total_count, 1)
        else:
            avg_response_time = 0
            p95_response_time = 0
            error_rate = 0
        
        # Get recent anomalies (last 10)
        recent_anomalies_cursor = db["anomaly_results"].find(
            {"service_name": service_name, "is_anomaly": True},
            sort=[("timestamp", -1)],
            limit=10
        )
        
        recent_anomalies = []
        for doc in recent_anomalies_cursor:
            # Convert ObjectId to string for JSON serialization
            doc["_id"] = str(doc["_id"])
            recent_anomalies.append(doc)
        
        # Get window statistics
        window_filter = {"service_name": service_name}
        if "timestamp" in time_filter:
            window_filter["window_start"] = time_filter["timestamp"]
        
        window_stats_pipeline = [
            {"$match": window_filter},
            {"$group": {
                "_id": "$service_name",
                "avg_request_count": {"$avg": "$request_count"},
                "avg_error_rate": {"$avg": "$error_rate"},
                "max_response_time": {"$max": "$max_response_time_ms"},
                "total_windows": {"$sum": 1}
            }}
        ]
        
        window_stats_result = list(db["window_features"].aggregate(window_stats_pipeline))
        
        window_stats = {
            "avg_request_count": window_stats_result[0]["avg_request_count"] if window_stats_result else 0,
            "avg_error_rate": window_stats_result[0]["avg_error_rate"] if window_stats_result else 0,
            "max_response_time": window_stats_result[0]["max_response_time"] if window_stats_result else 0,
            "total_windows": window_stats_result[0]["total_windows"] if window_stats_result else 0
        }
        
        # Get detection method breakdown
        detection_method_pipeline = [
            {"$match": {"service_name": service_name, "is_anomaly": True}},
            {"$group": {
                "_id": "$detection_method",
                "count": {"$sum": 1}
            }}
        ]
        
        detection_method_cursor = db["anomaly_results"].aggregate(detection_method_pipeline)
        detection_methods = {doc["_id"]: doc["count"] for doc in detection_method_cursor}
        
        return ServiceResponse(
            service_name=service_name,
            total_logs=total_logs,
            total_anomalies=total_anomalies,
            anomaly_rate=anomaly_rate,
            logs_last_hour=logs_last_hour,
            anomalies_last_hour=anomalies_last_hour,
            avg_response_time_ms=avg_response_time,
            p95_response_time_ms=p95_response_time,
            error_rate=error_rate,
            recent_anomalies=recent_anomalies,
            window_stats=window_stats,
            detection_methods=detection_methods
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching service details: {str(e)}")


def detect_recent_window(db, service_name: str, hybrid_detector: HybridAnomalyDetector) -> Optional[Dict[str, Any]]:
    """
    Run hybrid detection on the most recent window of a service.

    Persists the window and the detection result so the dashboard and
    borderline persistence can use them. Returns None if the last minutes
    do not contain enough traffic for a window.
    """
    recent_window = feature_extractor.extract_real_time(db, service_name, lookback_minutes=10)
    if recent_window is None:
        return None

    # Previous windows and results, oldest first, for rate-change rules and persistence
    previous_windows = [
        WindowFeatures(**doc) for doc in reversed(list(db["window_features"].find(
            {"service_name": service_name, "window_start": {"$lt": recent_window.window_start}},
            sort=[("window_start", -1)],
            limit=10
        )))
    ]
    previous_results = list(reversed(list(db["anomaly_results"].find(
        {"service_name": service_name},
        sort=[("timestamp", -1)],
        limit=10
    ))))

    detection_result = hybrid_detector.detect_anomaly(
        window_features=recent_window,
        previous_results=previous_results,
        previous_windows=previous_windows,
        track_latency=True
    )

    db["window_features"].insert_one(window_to_document(recent_window))
    hybrid_detector.save_detection_result(db, detection_result)
    return detection_result


@app.post("/api/detection/run", response_model=Dict[str, Any])
async def run_detection(
    retrain: bool = Query(False, description="Train a new model version even if one is loaded"),
    service_name: Optional[str] = Query(None, description="Only process this service"),
    detectors: tuple = Depends(get_detectors)
):
    """
    Run the full detection pipeline over the logs stored in MongoDB.

    Builds rolling windows, trains the Isolation Forest if no model exists
    yet, and stores rule/model/hybrid results for every window.
    """
    db = get_db()
    _, _, hybrid_detector = detectors

    try:
        return run_detection_pipeline(
            db,
            hybrid_detector,
            extractor=feature_extractor,
            services=[service_name] if service_name else None,
            retrain=retrain
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running detection: {str(e)}")


@app.post("/api/logs", response_model=LogIngestionResponse)
async def ingest_log(
    log_data: LogIngestionRequest,
    detectors: tuple = Depends(get_detectors)
):
    """
    Ingest a new log entry.
    
    Validates the log, stores it in MongoDB, and optionally triggers anomaly detection.
    """
    db = get_db()
    model_detector, rule_engine, hybrid_detector = detectors
    
    try:
        # Create LogEntry object with validation
        log_entry = LogEntry(
            timestamp=datetime.utcnow(),
            service_name=log_data.service_name,
            log_level=log_data.log_level.upper(),
            message=log_data.message,
            source_ip=log_data.source_ip,
            user_id=log_data.user_id,
            endpoint=log_data.endpoint,
            http_method=log_data.http_method,
            status_code=log_data.status_code,
            response_time_ms=log_data.response_time_ms,
            request_size_bytes=log_data.request_size_bytes,
            response_size_bytes=log_data.response_size_bytes,
            metadata=log_data.metadata
        )
        
        # Store in MongoDB
        result = db["log_entries"].insert_one(log_entry.dict(by_alias=True))
        log_id = str(result.inserted_id)
        
        # Check if we should trigger anomaly detection (for real-time processing)
        detection_triggered = False
        message = "Log ingested successfully"
        
        # For high priority logs (ERRORs or high latency), trigger immediate detection
        if (log_data.log_level.upper() == "ERROR" or
            (log_data.response_time_ms and log_data.response_time_ms > 1000)):
            try:
                detection_result = detect_recent_window(db, log_data.service_name, hybrid_detector)

                if detection_result and detection_result["final_is_anomaly"]:
                    detection_triggered = True
                    message = "Log ingested and anomaly detected"
            except Exception as detection_error:
                # Don't fail ingestion if detection fails
                print(f"Detection error during ingestion: {detection_error}")
        
        return LogIngestionResponse(
            log_id=log_id,
            timestamp=log_entry.timestamp,
            processed=True,
            detection_triggered=detection_triggered,
            message=message
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=400, 
            detail=f"Error ingesting log: {str(e)}"
        )


@app.post("/api/logs/batch", response_model=Dict[str, Any])
async def ingest_logs_batch(
    logs_data: List[LogIngestionRequest],
    detectors: tuple = Depends(get_detectors)
):
    """
    Ingest multiple log entries in batch.
    
    More efficient for bulk ingestion scenarios.
    """
    db = get_db()
    
    try:
        log_entries = []
        successful = 0
        failed = 0
        
        for log_data in logs_data:
            try:
                log_entry = LogEntry(
                    timestamp=datetime.utcnow(),
                    service_name=log_data.service_name,
                    log_level=log_data.log_level.upper(),
                    message=log_data.message,
                    source_ip=log_data.source_ip,
                    user_id=log_data.user_id,
                    endpoint=log_data.endpoint,
                    http_method=log_data.http_method,
                    status_code=log_data.status_code,
                    response_time_ms=log_data.response_time_ms,
                    request_size_bytes=log_data.request_size_bytes,
                    response_size_bytes=log_data.response_size_bytes,
                    metadata=log_data.metadata
                )
                log_entries.append(log_entry.dict(by_alias=True))
                successful += 1
            except Exception as e:
                print(f"Failed to validate log entry: {e}")
                failed += 1
        
        if log_entries:
            result = db["log_entries"].insert_many(log_entries)

        # Run real-time detection once per service in the batch
        _, _, hybrid_detector = detectors
        anomalies_detected = 0
        for service_name in sorted({entry["service_name"] for entry in log_entries}):
            try:
                detection_result = detect_recent_window(db, service_name, hybrid_detector)
                if detection_result and detection_result["final_is_anomaly"]:
                    anomalies_detected += 1
            except Exception as detection_error:
                print(f"Detection error during batch ingestion: {detection_error}")

        return {
            "successful": successful,
            "failed": failed,
            "total": len(logs_data),
            "anomalies_detected": anomalies_detected,
            "message": f"Batch ingestion completed: {successful} successful, {failed} failed"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=400, 
            detail=f"Error ingesting logs batch: {str(e)}"
        )


@app.get("/api/logs", response_model=PaginatedResponse)
async def get_logs(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=1000, description="Page size"),
    service_name: Optional[str] = Query(None, description="Filter by service name"),
    log_level: Optional[str] = Query(None, description="Filter by log level"),
    start_time: Optional[datetime] = Query(None, description="Start time filter"),
    end_time: Optional[datetime] = Query(None, description="End time filter"),
    sort_by: str = Query("timestamp", description="Field to sort by"),
    sort_order: str = Query("desc", description="Sort order (asc or desc)")
):
    """Get paginated log entries with filtering."""
    db = get_db()
    
    try:
        # Build filter
        filter_query = {}
        
        if service_name:
            filter_query["service_name"] = service_name
        
        if log_level:
            filter_query["log_level"] = log_level
        
        # Time range filter
        time_filter = {}
        if start_time:
            time_filter["$gte"] = start_time
        if end_time:
            time_filter["$lte"] = end_time
        
        if time_filter:
            filter_query["timestamp"] = time_filter
        
        # Calculate skip
        skip = (page - 1) * page_size
        
        # Determine sort order
        sort_order_val = -1 if sort_order.lower() == "desc" else 1
        
        # Get total count
        total = db["log_entries"].count_documents(filter_query)
        
        # Get paginated data
        cursor = db["log_entries"].find(
            filter_query,
            skip=skip,
            limit=page_size,
            sort=[(sort_by, sort_order_val)]
        )
        
        # Convert documents to dictionaries and handle ObjectId
        logs = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            logs.append(doc)
        
        # Calculate total pages
        total_pages = (total + page_size - 1) // page_size
        
        return PaginatedResponse(
            data=logs,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching logs: {str(e)}")


@app.get("/api/anomalies", response_model=PaginatedResponse)
async def get_anomalies(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=1000, description="Page size"),
    service_name: Optional[str] = Query(None, description="Filter by service name"),
    detection_method: Optional[str] = Query(None, description="Filter by detection method"),
    severity: Optional[str] = Query(None, description="Filter by severity (high, medium, low)"),
    start_time: Optional[datetime] = Query(None, description="Start time filter"),
    end_time: Optional[datetime] = Query(None, description="End time filter"),
    sort_by: str = Query("timestamp", description="Field to sort by"),
    sort_order: str = Query("desc", description="Sort order (asc or desc)")
):
    """Get paginated anomaly detection results with filtering."""
    db = get_db()
    
    try:
        # Build filter - only anomalies
        filter_query = {"is_anomaly": True}
        
        if service_name:
            filter_query["service_name"] = service_name
        
        if detection_method:
            filter_query["detection_method"] = detection_method
        
        if severity:
            # For severity, we need to check rule_violations or use a separate field
            # This is a simplified implementation
            pass
        
        # Time range filter
        time_filter = {}
        if start_time:
            time_filter["$gte"] = start_time
        if end_time:
            time_filter["$lte"] = end_time
        
        if time_filter:
            filter_query["timestamp"] = time_filter
        
        # Calculate skip
        skip = (page - 1) * page_size
        
        # Determine sort order
        sort_order_val = -1 if sort_order.lower() == "desc" else 1
        
        # Get total count
        total = db["anomaly_results"].count_documents(filter_query)
        
        # Get paginated data
        cursor = db["anomaly_results"].find(
            filter_query,
            skip=skip,
            limit=page_size,
            sort=[(sort_by, sort_order_val)]
        )
        
        # Convert documents to dictionaries and handle ObjectId
        anomalies = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            anomalies.append(doc)
        
        # Calculate total pages
        total_pages = (total + page_size - 1) // page_size
        
        return PaginatedResponse(
            data=anomalies,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching anomalies: {str(e)}")


@app.post("/api/model/retrain", response_model=RetrainResponse)
async def retrain_model(
    request: RetrainRequest,
    detectors: tuple = Depends(get_detectors)
):
    """
    Retrain the anomaly detection model with new data.
    
    Creates a new model version and persists metadata.
    """
    current_model_detector, rule_engine, current_hybrid_detector = detectors
    db = get_db()
    
    try:
        start_time = datetime.utcnow()
        
        print(f"Starting model retraining with {request.training_hours} hours of data...")
        
        # Calculate time range for training data
        cutoff_time = datetime.utcnow() - timedelta(hours=request.training_hours)
        
        # Get window features for training
        window_filter = {"window_start": {"$gte": cutoff_time}}
        windows_cursor = db["window_features"].find(window_filter)
        
        training_features = []
        for doc in windows_cursor:
            try:
                window_feature = WindowFeatures(**doc)
                training_features.append(window_feature)
            except Exception as e:
                print(f"Error parsing window feature: {e}")
                continue
        
        if not training_features:
            raise HTTPException(
                status_code=400, 
                detail=f"No training data found for the last {request.training_hours} hours"
            )
        
        print(f"Found {len(training_features)} windows for training")
        
        # Create labels for training (in production, these would come from labeled data)
        # For now, we'll use a simple heuristic based on error rate and latency
        training_labels = []
        for wf in training_features:
            is_anomaly = (
                wf.error_rate > 0.25 or
                wf.p95_response_time_ms > 1500 or
                (wf.request_count < 5 and wf.error_rate > 0.1)
            )
            training_labels.append(is_anomaly)
        
        # Create new model detector with specified parameters
        new_model_detector = IsolationForestAnomalyDetector(
            contamination=request.contamination,
            borderline_threshold=request.borderline_threshold,
            persistence_window_count=request.persistence_window_count
        )
        
        # Train the model
        success = new_model_detector.train(training_features, training_labels)
        
        if not success:
            raise HTTPException(status_code=500, detail="Model training failed")
        
        # Generate new version
        latest_version_doc = db["model_metadata"].find_one(
            sort=[("created_at", -1)]
        )
        
        if latest_version_doc:
            latest_version = latest_version_doc["version"]
            # Increment version (simple increment for demo)
            try:
                version_parts = list(map(int, latest_version.split(".")))
                version_parts[-1] += 1
                new_version = ".".join(map(str, version_parts))
            except:
                new_version = f"{latest_version}.1"
        else:
            new_version = "1.0.0"
        
        # Add suffix if provided
        if request.version_suffix:
            new_version = f"{new_version}-{request.version_suffix}"
        
        # Save model metadata
        model_id = new_model_detector.save_model_metadata(db, version=new_version)
        
        # Update global model detector
        global model_detector, hybrid_detector
        model_detector = new_model_detector
        
        # Update hybrid detector with new model
        hybrid_detector = HybridAnomalyDetector(
            model_detector=model_detector,
            rule_engine=rule_engine,
            voting_strategy="weighted"
        )
        
        # Calculate training time
        training_time = (datetime.utcnow() - start_time).total_seconds()
        
        # Get performance metrics
        performance_metrics = {
            "precision": new_model_detector.precision or 0,
            "recall": new_model_detector.recall or 0,
            "f1_score": new_model_detector.f1_score_val or 0,
            "false_positive_rate": new_model_detector.false_positive_rate or 0,
            "training_windows": len(training_features),
            "anomaly_ratio": sum(training_labels) / len(training_labels)
        }
        
        print(f"Model retraining complete. Version: {new_version}, Time: {training_time:.2f}s")
        
        return RetrainResponse(
            success=True,
            model_version=new_version,
            training_windows=len(training_features),
            performance_metrics=performance_metrics,
            training_time_seconds=training_time,
            message=f"Model retrained successfully with version {new_version}"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during model retraining: {str(e)}")


@app.get("/api/model/versions", response_model=List[Dict[str, Any]])
async def get_model_versions(limit: int = Query(10, ge=1, le=100)):
    """Get list of model versions with metadata."""
    db = get_db()
    
    try:
        cursor = db["model_metadata"].find(
            {},
            sort=[("created_at", -1)],
            limit=limit
        )
        
        versions = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            versions.append(doc)
        
        return versions
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching model versions: {str(e)}")


@app.get("/api/rules", response_model=List[Dict[str, Any]])
async def get_rules(enabled_only: bool = Query(False, description="Only return enabled rules")):
    """Get detection rules."""
    db = get_db()
    
    try:
        filter_query = {}
        if enabled_only:
            filter_query["enabled"] = True
        
        cursor = db["detection_rules"].find(filter_query, sort=[("rule_name", 1)])
        
        rules = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            rules.append(doc)
        
        return rules
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching rules: {str(e)}")


@app.get("/api/metrics/window")
async def get_window_metrics(
    service_name: Optional[str] = Query(None, description="Service name filter"),
    hours: int = Query(24, ge=1, le=168, description="Hours of data to include")
):
    """Get window metrics for charting."""
    db = get_db()
    
    try:
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        filter_query = {"window_start": {"$gte": cutoff_time}}
        if service_name:
            filter_query["service_name"] = service_name
        
        # Get window features for charting
        cursor = db["window_features"].find(
            filter_query,
            sort=[("window_start", 1)],
            projection={
                "window_start": 1,
                "request_count": 1,
                "error_rate": 1,
                "avg_response_time_ms": 1,
                "p95_response_time_ms": 1,
                "service_name": 1
            }
        )
        
        windows = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            windows.append(doc)
        
        return windows
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching window metrics: {str(e)}")


@app.get("/api/performance")
async def get_performance_metrics(
    hours: int = Query(24, ge=1, le=168, description="Hours of data to include")
):
    """Get system performance metrics including latency breakdown."""
    db = get_db()
    
    try:
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Get latency statistics from anomaly results
        latency_pipeline = [
            {"$match": {
                "timestamp": {"$gte": cutoff_time},
                "$or": [
                    {"detection_latency_ms": {"$exists": True}},
                    {"end_to_end_latency_ms": {"$exists": True}}
                ]
            }},
            {"$group": {
                "_id": None,
                "avg_detection_latency": {"$avg": "$detection_latency_ms"},
                "avg_end_to_end_latency": {"$avg": "$end_to_end_latency_ms"},
                "p95_detection_latency": {"$percentile": {
                    "input": "$detection_latency_ms",
                    "p": [0.95],
                    "method": "approximate"
                }},
                "p95_end_to_end_latency": {"$percentile": {
                    "input": "$end_to_end_latency_ms",
                    "p": [0.95],
                    "method": "approximate"
                }},
                "sample_count": {"$sum": 1}
            }}
        ]
        
        latency_result = list(db["anomaly_results"].aggregate(latency_pipeline))
        
        # Get throughput statistics
        throughput_pipeline = [
            {"$match": {"timestamp": {"$gte": cutoff_time}}},
            {"$group": {
                "_id": {"$dateToString": {"format": "%Y-%m-%dT%H:00:00", "date": "$timestamp"}},
                "count": {"$sum": 1}
            }},
            {"$group": {
                "_id": None,
                "avg_per_hour": {"$avg": "$count"},
                "max_per_hour": {"$max": "$count"},
                "min_per_hour": {"$min": "$count"}
            }}
        ]
        
        throughput_result = list(db["log_entries"].aggregate(throughput_pipeline))
        
        # Get detection method breakdown
        detection_method_pipeline = [
            {"$match": {"timestamp": {"$gte": cutoff_time}, "is_anomaly": True}},
            {"$group": {
                "_id": "$detection_method",
                "count": {"$sum": 1},
                "avg_confidence": {"$avg": "$confidence"}
            }}
        ]
        
        detection_method_result = list(db["anomaly_results"].aggregate(detection_method_pipeline))
        
        # Get error rate statistics
        error_pipeline = [
            {"$match": {"timestamp": {"$gte": cutoff_time}}},
            {"$group": {
                "_id": None,
                "total_logs": {"$sum": 1},
                "error_logs": {"$sum": {"$cond": [{"$eq": ["$log_level", "ERROR"]}, 1, 0]}},
                "avg_response_time": {"$avg": "$response_time_ms"}
            }}
        ]
        
        error_result = list(db["log_entries"].aggregate(error_pipeline))
        
        # Compile results
        latency_stats = latency_result[0] if latency_result else {}
        throughput_stats = throughput_result[0] if throughput_result else {}
        error_stats = error_result[0] if error_result else {}
        
        detection_methods = {}
        for method in detection_method_result:
            detection_methods[method["_id"]] = {
                "count": method["count"],
                "avg_confidence": method["avg_confidence"]
            }
        
        error_rate = 0
        if error_stats.get("total_logs", 0) > 0:
            error_rate = error_stats.get("error_logs", 0) / error_stats.get("total_logs", 1)
        
        return {
            "latency_metrics": {
                "avg_detection_latency_ms": latency_stats.get("avg_detection_latency"),
                "avg_end_to_end_latency_ms": latency_stats.get("avg_end_to_end_latency"),
                "p95_detection_latency_ms": latency_stats.get("p95_detection_latency", [0])[0] if latency_stats.get("p95_detection_latency") else None,
                "p95_end_to_end_latency_ms": latency_stats.get("p95_end_to_end_latency", [0])[0] if latency_stats.get("p95_end_to_end_latency") else None,
                "sample_count": latency_stats.get("sample_count", 0)
            },
            "throughput_metrics": {
                "avg_logs_per_hour": throughput_stats.get("avg_per_hour", 0),
                "max_logs_per_hour": throughput_stats.get("max_per_hour", 0),
                "min_logs_per_hour": throughput_stats.get("min_per_hour", 0)
            },
            "error_metrics": {
                "total_logs": error_stats.get("total_logs", 0),
                "error_logs": error_stats.get("error_logs", 0),
                "error_rate": error_rate,
                "avg_response_time_ms": error_stats.get("avg_response_time", 0)
            },
            "detection_methods": detection_methods,
            "time_range": {
                "start": cutoff_time.isoformat(),
                "end": datetime.utcnow().isoformat(),
                "hours": hours
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching performance metrics: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)