#!/usr/bin/env python3
"""
Compare our detectors (rule engine, Isolation Forest, hybrid) with Random Forest,
Local Outlier Factor and One-Class SVM on labelled demo data.

Each run generates 6 hours of demo traffic with 4 injected incidents into the
anomaly_detection database (existing data is replaced), runs the system's
detection pipeline, and labels every window from the generator's scenario tags.

Unsupervised methods (ours, LOF, One-Class SVM) are fit on the unlabelled windows
they monitor. Random Forest is supervised: it is trained on the labelled windows
of the OTHER runs and tested on the held-out run.

Experiment A: Random Forest sees labelled examples of every incident type.
Experiment B: one incident type is removed from Random Forest's training data
              (a new, never-seen failure type); recall is measured on that type.

    python evaluation/model_comparison.py            # needs MongoDB on localhost
"""

import argparse
import contextlib
import io
import os
import sys
import time
from collections import Counter

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "mongodb_anomaly_detection"))

import run_detection
from config.database import init_database, get_db
from ml.detection_pipeline import run_detection_pipeline
from ml.hybrid_detector import HybridAnomalyDetector
from ml.isolation_forest_model import IsolationForestAnomalyDetector
from ml.window_feature_extractor import WindowFeatureExtractor
from rules.rule_engine import RuleEngine

SCENARIOS = ["latency_spike", "gradual_degradation", "error_burst", "traffic_drop"]


def build_run(db, seed):
    """Generate one labelled run and return per-window features, labels and our predictions."""
    with contextlib.redirect_stdout(io.StringIO()):
        run_detection.generate_demo_logs(db, seed=seed)
        rule_engine = RuleEngine(WindowFeatureExtractor())
        rule_engine.load_rules_from_db(db)
        hybrid = HybridAnomalyDetector(IsolationForestAnomalyDetector(), rule_engine, "weighted")
        start = time.perf_counter()
        run_detection_pipeline(db, hybrid)
        pipeline_s = time.perf_counter() - start

    results = {(r["service_name"], r["window_start"]): r for r in db["anomaly_results"].find()}
    rows = []
    for window in db["window_features"].find().sort([("service_name", 1), ("window_start", 1)]):
        key = (window["service_name"], window["window_start"])
        scenarios = Counter(doc["metadata"]["scenario"] for doc in db["log_entries"].find(
            {"service_name": key[0], "timestamp": {"$gte": window["window_start"], "$lt": window["window_end"]},
             "metadata.scenario": {"$ne": "normal"}},
            projection={"metadata.scenario": 1}))
        result = results[key]
        rows.append({
            "features": window["feature_vector"],
            "label": int(bool(scenarios)),
            "scenario": scenarios.most_common(1)[0][0] if scenarios else "normal",
            "rules": int(result["metadata"]["rule_confidence"] > 0),
            "isolation_forest": int((result["isolation_forest_score"] or 0) >= 0.5),
            "hybrid": int(result["is_anomaly"] or result["detection_method"] == "duplicate_suppressed"),
        })
    return pd.DataFrame(rows), pipeline_s


def scores(y_true, y_pred):
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    return tp, fp, fn, tn


def summarize(tp, fp, fn, tn):
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / max(tp + fp + fn + tn, 1)
    return precision, recall, f1, accuracy, fp / max(fp + tn, 1)


def unsupervised_baselines(X):
    """LOF and One-Class SVM fit on the same unlabelled windows they score."""
    Xs = StandardScaler().fit_transform(X)
    lof = (LocalOutlierFactor(n_neighbors=20, contamination=0.1).fit_predict(Xs) == -1).astype(int)
    ocsvm = (OneClassSVM(nu=0.1, gamma="scale").fit(Xs).predict(Xs) == -1).astype(int)
    return lof, ocsvm


def random_forest(train, test):
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    start = time.perf_counter()
    model.fit(np.stack(train["features"]), train["label"])
    train_s = time.perf_counter() - start
    return model.predict(np.stack(test["features"])), train_s


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3, 4, 5])
    parser.add_argument("--output", default=os.path.join(project_root, "evaluation", "results"))
    args = parser.parse_args()

    if not init_database():
        print("Could not connect to MongoDB on localhost:27017")
        return 1
    db = get_db()

    runs, pipeline_times = {}, []
    for seed in args.seeds:
        runs[seed], seconds = build_run(db, seed)
        pipeline_times.append(seconds)
        print(f"run {seed}: {len(runs[seed])} windows, {runs[seed]['label'].sum()} anomalous")

    # Experiment A: all incident types known to Random Forest
    totals = {name: np.zeros(4, dtype=int) for name in
              ["Rules only (ours)", "Isolation Forest (ours)", "Hybrid rules + IF (ours)",
               "Random Forest (supervised)", "Local Outlier Factor", "One-Class SVM"]}
    rf_train_times = []
    for seed, test in runs.items():
        train = pd.concat([run for s, run in runs.items() if s != seed])
        rf_pred, rf_s = random_forest(train, test)
        rf_train_times.append(rf_s)
        lof, ocsvm = unsupervised_baselines(np.stack(test["features"]))
        for name, pred in [("Rules only (ours)", test["rules"]), ("Isolation Forest (ours)", test["isolation_forest"]),
                           ("Hybrid rules + IF (ours)", test["hybrid"]), ("Random Forest (supervised)", rf_pred),
                           ("Local Outlier Factor", lof), ("One-Class SVM", ocsvm)]:
            totals[name] += scores(test["label"], pred)

    labelled = sum(len(r) for r in runs.values()) - len(next(iter(runs.values())))
    table_a = []
    for name, (tp, fp, fn, tn) in totals.items():
        p, r, f1, acc, fpr = summarize(tp, fp, fn, tn)
        table_a.append({"model": name, "needs_labels": "yes" if "Random Forest" in name else "no",
                        "precision": p, "recall": r, "f1": f1, "accuracy": acc,
                        "false_positive_rate": fpr, "false_alarms": fp})
    table_a = pd.DataFrame(table_a)

    # Experiment B: one incident type never seen by Random Forest
    table_b = []
    for held_out in SCENARIOS:
        caught = {"Random Forest (supervised)": [0, 0], "Isolation Forest (ours)": [0, 0],
                  "Hybrid rules + IF (ours)": [0, 0], "Rules only (ours)": [0, 0]}
        rf_overall = np.zeros(4, dtype=int)
        for seed, test in runs.items():
            train = pd.concat([run for s, run in runs.items() if s != seed])
            train = train[train["scenario"] != held_out]
            rf_pred, _ = random_forest(train, test)
            rf_overall += scores(test["label"], rf_pred)
            target = (test["scenario"] == held_out).to_numpy()
            for name, pred in [("Random Forest (supervised)", rf_pred),
                               ("Isolation Forest (ours)", test["isolation_forest"].to_numpy()),
                               ("Hybrid rules + IF (ours)", test["hybrid"].to_numpy()),
                               ("Rules only (ours)", test["rules"].to_numpy())]:
                caught[name][0] += int(np.asarray(pred)[target].sum())
                caught[name][1] += int(target.sum())
        row = {"unseen_incident_type": held_out}
        for name, (hit, total) in caught.items():
            row[f"recall: {name}"] = hit / total if total else 0.0
        row["Random Forest overall F1"] = summarize(*rf_overall)[2]
        table_b.append(row)
    table_b = pd.DataFrame(table_b)

    os.makedirs(args.output, exist_ok=True)
    table_a.to_csv(os.path.join(args.output, "model_comparison_known.csv"), index=False)
    table_b.to_csv(os.path.join(args.output, "model_comparison_unseen.csv"), index=False)

    fmt = lambda v: f"{v:.3f}"
    print("\nExperiment A: all incident types known (Random Forest trained on labelled runs)")
    print(table_a.to_string(index=False, float_format=fmt))
    print("\nExperiment B: recall on an incident type Random Forest never saw in training")
    print(table_b.to_string(index=False, float_format=fmt))
    print(f"\nLabelled windows Random Forest needs per test run: {labelled}; ours needs 0")
    print(f"Random Forest training: {np.mean(rf_train_times):.2f} s; "
          f"our pipeline (windows + IF training + detection): {np.mean(pipeline_times):.1f} s per run")
    return 0


if __name__ == "__main__":
    sys.exit(main())
