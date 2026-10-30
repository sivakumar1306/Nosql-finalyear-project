#!/usr/bin/env python3
"""
Check that the AI incident investigator finds the true root cause of a
cascading failure (user-service -> auth-service -> payment-service).

Each run generates demo traffic with a different random seed (different
background noise), adds the cascading failure, runs real-time detection on the
three services and investigates from the payment-service anomaly. The data-driven
part is evaluated (no LLM needed). Existing data in MongoDB is replaced.

    python evaluation/investigation_eval.py --runs 5
"""

import argparse
import contextlib
import io
import os
import sys

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "mongodb_anomaly_detection"))

import run_detection
from api.main import detect_recent_window
from config.database import init_database, get_db
from ml.detection_pipeline import run_detection_pipeline
from ml.hybrid_detector import HybridAnomalyDetector
from ml.incident_investigator import investigate
from ml.incident_simulator import simulate_cascading_failure, CASCADE_STEPS
from ml.isolation_forest_model import IsolationForestAnomalyDetector
from ml.window_feature_extractor import WindowFeatureExtractor
from rules.rule_engine import RuleEngine

TRUE_ROOT = CASCADE_STEPS[0][0]
TRUE_ORDER = [service for service, _ in CASCADE_STEPS]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runs", type=int, default=5)
    args = parser.parse_args()

    if not init_database():
        print("Could not connect to MongoDB on localhost:27017")
        return 1
    db = get_db()

    correct_root = correct_order = 0
    for seed in range(1, args.runs + 1):
        with contextlib.redirect_stdout(io.StringIO()):
            run_detection.generate_demo_logs(db, seed=seed)
            rule_engine = RuleEngine(WindowFeatureExtractor())
            rule_engine.load_rules_from_db(db)
            hybrid = HybridAnomalyDetector(IsolationForestAnomalyDetector(), rule_engine, "weighted")
            run_detection_pipeline(db, hybrid)
            simulate_cascading_failure(db, seed=seed)
            for service in TRUE_ORDER:
                detect_recent_window(db, service, hybrid)

        seed_anomaly = db["anomaly_results"].find_one(
            {"is_anomaly": True, "service_name": TRUE_ORDER[-1]}, sort=[("metadata.detected_at", -1)])
        report = investigate(db, seed_anomaly, use_llm=False)
        top = report["hypotheses"][0]
        order = [s["service"] for s in report["affected_services"]]
        correct_root += top["service"] == TRUE_ROOT
        correct_order += order == TRUE_ORDER
        print(f"run {seed}: root cause = {top['service']} ({top['confidence']:.0%}), "
              f"onset order = {' -> '.join(order)}")

    print(f"\nCorrect root cause: {correct_root}/{args.runs}; correct failure order: {correct_order}/{args.runs}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
