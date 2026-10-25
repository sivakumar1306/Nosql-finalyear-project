#!/usr/bin/env python3
"""
Run the anomaly detection pipeline over the logs stored in MongoDB.

Builds rolling windows, saves the detection rules, trains the Isolation
Forest (first run or --retrain) and stores a detection result per window,
so the dashboard shows windows, rules, model versions and anomalies.

Usage:
    python run_detection.py                 # analyse the logs already in MongoDB
    python run_detection.py --generate      # replace logs with demo traffic + incidents, then analyse
    python run_detection.py --retrain       # also train a new model version
"""

import argparse
import os
import random
import sys
from datetime import datetime, timedelta

# Add the project root to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "mongodb_anomaly_detection"))

from config.database import init_database, get_db
from models.log_schema import LogEntry
from ml.window_feature_extractor import WindowFeatureExtractor
from ml.isolation_forest_model import IsolationForestAnomalyDetector
from ml.hybrid_detector import HybridAnomalyDetector
from ml.detection_pipeline import run_detection_pipeline
from rules.rule_engine import RuleEngine


SERVICES = ["auth-service", "payment-service", "user-service"]
ENDPOINTS = {
    "auth-service": ["/api/login", "/api/logout", "/api/token/refresh"],
    "payment-service": ["/api/payment", "/api/payment/status", "/api/refund"],
    "user-service": ["/api/users", "/api/users/profile", "/api/users/settings"],
}

# Injected incidents: (service, scenario, minutes before now it starts, duration in minutes)
INCIDENTS = [
    ("payment-service", "latency_spike", 300, 15),
    ("auth-service", "gradual_degradation", 210, 30),
    ("auth-service", "error_burst", 120, 10),
    ("user-service", "traffic_drop", 60, 15),
]


def active_incident(service, minutes_ago):
    """Return (scenario, progress 0-1) if an incident covers this minute."""
    for inc_service, scenario, start, duration in INCIDENTS:
        if inc_service == service and start - duration < minutes_ago <= start:
            return scenario, (start - minutes_ago) / duration
    return None, 0.0


def generate_demo_logs(db, hours=6, requests_per_minute=8, seed=42):
    """Replace stored logs with realistic traffic for the last `hours`, including incidents."""
    random.seed(seed)
    now = datetime.utcnow()
    logs = []

    for service in SERVICES:
        for minutes_ago in range(hours * 60, 0, -1):
            scenario, progress = active_incident(service, minutes_ago)

            rate = requests_per_minute
            if scenario == "traffic_drop":
                rate = 1
            count = max(0, int(random.gauss(rate, rate * 0.15)))

            for _ in range(count):
                latency = random.lognormvariate(4.9, 0.45)  # median ~135 ms
                error_probability = 0.02

                if scenario == "latency_spike":
                    latency = random.uniform(1800, 5000)
                elif scenario == "gradual_degradation":
                    latency *= 1 + 9 * progress  # creeps up to ~10x
                    error_probability = 0.02 + 0.10 * progress
                elif scenario == "error_burst":
                    error_probability = 0.45

                is_error = random.random() < error_probability
                log = LogEntry(
                    timestamp=now - timedelta(minutes=minutes_ago, seconds=random.uniform(0, 60)),
                    service_name=service,
                    log_level="ERROR" if is_error else random.choice(["INFO", "INFO", "INFO", "DEBUG", "WARNING"]),
                    message="Request failed" if is_error else "Request completed",
                    endpoint=random.choice(ENDPOINTS[service]),
                    http_method=random.choice(["GET", "GET", "POST", "PUT"]),
                    status_code=random.choice([500, 502, 503]) if is_error else random.choice([200, 200, 200, 201, 404]),
                    response_time_ms=round(latency, 1),
                    request_size_bytes=random.randint(200, 2000),
                    response_size_bytes=random.randint(500, 8000),
                    metadata={"demo": True, "scenario": scenario or "normal"},
                )
                logs.append(log.dict(by_alias=True))

    for name in ["log_entries", "window_features", "anomaly_results", "model_metadata", "detection_rules"]:
        db[name].delete_many({})
    db["fs.files"].delete_many({})
    db["fs.chunks"].delete_many({})

    db["log_entries"].insert_many(logs)
    return len(logs)


def report_incidents(db):
    """Print whether each injected incident was detected."""
    print("\nInjected incidents:")
    now = datetime.utcnow()
    for service, scenario, start, duration in INCIDENTS:
        incident_start = now - timedelta(minutes=start)
        incident_end = incident_start + timedelta(minutes=duration)
        hits = list(db["anomaly_results"].find({
            "service_name": service,
            "is_anomaly": True,
            "window_start": {"$lt": incident_end},
            "window_end": {"$gt": incident_start},
        }))
        methods = sorted({h["detection_method"] for h in hits})
        status = f"DETECTED ({len(hits)} alerts, {', '.join(methods)})" if hits else "missed"
        print(f"  {service:16} {scenario:20} {status}")


def main():
    parser = argparse.ArgumentParser(description="Run anomaly detection over stored logs")
    parser.add_argument("--generate", action="store_true",
                        help="Replace all data with 6 hours of demo traffic containing injected incidents")
    parser.add_argument("--retrain", action="store_true",
                        help="Train a new model version even if one exists")
    parser.add_argument("--service", help="Only process this service")
    args = parser.parse_args()

    if not init_database():
        print("Could not connect to MongoDB. Is it running on localhost:27017?")
        return 1
    db = get_db()

    if args.generate:
        count = generate_demo_logs(db)
        print(f"Generated {count} demo log entries for {', '.join(SERVICES)}")

    model_detector = IsolationForestAnomalyDetector()
    metadata = model_detector.load_model_metadata(db)
    if metadata and not args.retrain:
        model_detector.load_model_from_metadata(db, metadata)

    rule_engine = RuleEngine(WindowFeatureExtractor())
    rule_engine.load_rules_from_db(db)

    hybrid_detector = HybridAnomalyDetector(
        model_detector=model_detector,
        rule_engine=rule_engine,
        voting_strategy="weighted"
    )

    summary = run_detection_pipeline(
        db,
        hybrid_detector,
        services=[args.service] if args.service else None,
        retrain=args.retrain
    )

    print(f"\n{summary['message']}")
    if not summary["success"]:
        print("Tip: run with --generate to load demo traffic.")
        return 1

    for service, stats in summary["services"].items():
        print(f"  {service:16} {stats['windows']:5} windows  {stats['anomalies']:4} anomalies")
    print(f"Rules active: {summary['rules']}")
    if summary["model_version"]:
        print(f"Trained model version: {summary['model_version']}")
    print(f"Detection methods: {summary['detection_counts']}")
    print(f"Processing time: {summary['processing_time_seconds']:.1f}s")

    if args.generate:
        report_incidents(db)

    print("\nRestart the backend (python run_backend.py) so it loads the new model, then refresh the dashboard.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
