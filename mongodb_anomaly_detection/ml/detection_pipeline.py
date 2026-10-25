"""
Batch detection pipeline.

Turns stored log entries into rolling windows, persists them to MongoDB,
trains the Isolation Forest when no model exists yet, and runs hybrid
detection over every window so results land in `anomaly_results`.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional

from models.log_schema import LogEntry, WindowFeatures
from ml.window_feature_extractor import WindowFeatureExtractor
from ml.isolation_forest_model import IsolationForestAnomalyDetector
from ml.hybrid_detector import HybridAnomalyDetector


def heuristic_label(wf: WindowFeatures) -> bool:
    """Synthetic label used for training metrics (same heuristic as /api/model/retrain)."""
    return (
        wf.error_rate > 0.25 or
        wf.p95_response_time_ms > 1500 or
        (wf.request_count < 5 and wf.error_rate > 0.1)
    )


def window_to_document(wf: WindowFeatures) -> Dict[str, Any]:
    """Convert WindowFeatures to a MongoDB document (BSON needs string dict keys)."""
    doc = wf.dict(by_alias=True)
    doc["status_code_distribution"] = {
        str(code): count for code, count in wf.status_code_distribution.items()
    }
    return doc


def build_windows(db, extractor: WindowFeatureExtractor, service_name: str,
                  min_requests: int) -> List[WindowFeatures]:
    """Extract rolling windows for one service, skipping windows with too little traffic."""
    cursor = db["log_entries"].find({"service_name": service_name}).sort("timestamp", 1)

    logs = []
    for doc in cursor:
        try:
            logs.append(LogEntry(**doc))
        except Exception as e:
            print(f"Error parsing log entry: {e}")

    if not logs:
        return []

    # Windows that run past the newest log are still filling up; analysing
    # them would report low traffic at the end of the data
    last_log_time = max(log.timestamp for log in logs)
    windows = extractor.extract_from_logs(logs)
    return [
        wf for wf in windows
        if wf.request_count >= min_requests and wf.window_end <= last_log_time
    ]


def train_model(db, windows: List[WindowFeatures],
                model_detector: IsolationForestAnomalyDetector) -> str:
    """Train the Isolation Forest on the given windows and save it as a new model version."""
    labels = [heuristic_label(wf) for wf in windows]
    model_detector.train(windows, labels)

    latest = db["model_metadata"].find_one(sort=[("created_at", -1)])
    if latest:
        try:
            parts = list(map(int, latest["version"].split(".")))
            parts[-1] += 1
            version = ".".join(map(str, parts))
        except ValueError:
            version = f"{latest['version']}.1"
    else:
        version = "1.0.0"

    model_detector.save_model_metadata(db, version=version)
    return version


def run_detection_pipeline(db,
                           hybrid_detector: HybridAnomalyDetector,
                           extractor: Optional[WindowFeatureExtractor] = None,
                           services: Optional[List[str]] = None,
                           retrain: bool = False,
                           min_requests: Optional[int] = None) -> Dict[str, Any]:
    """
    Rebuild windows and detection results from the logs stored in MongoDB.

    Existing windows and detection results for the processed services are
    replaced, so the pipeline can be re-run safely.

    Args:
        db: MongoDB database instance
        hybrid_detector: Detector whose model/rule engine are used
        extractor: Window feature extractor (default 5 min windows, 1 min slide)
        services: Services to process (default: every service with logs)
        retrain: Train a new model version even if one is already loaded
        min_requests: Minimum requests for a window to be analysed
                      (default: one per minute of window, as in real-time detection)

    Returns:
        Summary of what was processed and detected
    """
    start_time = datetime.utcnow()
    extractor = extractor or WindowFeatureExtractor(window_size_minutes=5, slide_minutes=1)
    if min_requests is None:
        min_requests = extractor.window_size_minutes
    if services is None:
        services = sorted(db["log_entries"].distinct("service_name"))

    rule_engine = hybrid_detector.rule_engine
    model_detector = hybrid_detector.model_detector

    # Persist the rule set so the dashboard and /api/rules show what is evaluated
    if db["detection_rules"].count_documents({}) == 0:
        rule_engine.save_rules_to_db(db)

    # 1. Rolling windows per service -> window_features collection
    windows_by_service: Dict[str, List[WindowFeatures]] = {}
    for service in services:
        windows = build_windows(db, extractor, service, min_requests)
        windows_by_service[service] = windows

        db["window_features"].delete_many({"service_name": service})
        if windows:
            db["window_features"].insert_many([window_to_document(wf) for wf in windows])

    all_windows = [wf for ws in windows_by_service.values() for wf in ws]
    if not all_windows:
        return {
            "success": False,
            "message": (
                f"No window had at least {min_requests} requests; "
                "there is not enough log traffic to analyse"
            ),
            "services": services,
            "windows": 0,
        }

    # 2. Train the model if there is none yet (or a retrain was requested)
    model_version = None
    if retrain or model_detector.model is None:
        model_version = train_model(db, all_windows, model_detector)

    # 3. Hybrid detection over every window, oldest first
    hybrid_detector.clear_recent_alerts()
    per_service = {}
    for service, windows in windows_by_service.items():
        db["anomaly_results"].delete_many({"service_name": service})

        previous_windows: List[WindowFeatures] = []
        previous_results: List[Dict[str, Any]] = []
        documents = []
        anomalies = 0

        for wf in windows:
            result = hybrid_detector.detect_anomaly(
                window_features=wf,
                previous_results=previous_results,
                previous_windows=previous_windows,
                track_latency=True
            )
            documents.append(hybrid_detector.build_result_document(result))
            if result["final_is_anomaly"]:
                anomalies += 1

            previous_windows = (previous_windows + [wf])[-10:]
            previous_results = (previous_results + [{"is_borderline": result["model_borderline"]}])[-10:]

        if documents:
            db["anomaly_results"].insert_many(documents)

        per_service[service] = {"windows": len(windows), "anomalies": anomalies}

    total_anomalies = sum(s["anomalies"] for s in per_service.values())
    return {
        "success": True,
        "message": f"Analysed {len(all_windows)} windows, {total_anomalies} anomalies detected",
        "services": per_service,
        "windows": len(all_windows),
        "anomalies": total_anomalies,
        "rules": len(rule_engine.get_rules_for_service()),
        "model_version": model_version,
        "detection_counts": dict(hybrid_detector.detection_counts),
        "processing_time_seconds": (datetime.utcnow() - start_time).total_seconds(),
    }
