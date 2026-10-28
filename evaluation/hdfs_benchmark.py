#!/usr/bin/env python3
"""
Benchmark our hybrid detector on the public HDFS log dataset.

Uses the loglizer toolkit (He et al., ISSRE 2016) for the data, the split and
the classical baselines, so every method is evaluated on exactly the same
train/test data:

    git clone https://github.com/logpai/loglizer
    python evaluation/hdfs_benchmark.py --loglizer path/to/loglizer

Setup (same as loglizer's HDFS benchmark): one sample per HDFS block, event
count vectors, 50/50 split with anomalies spread evenly ("uniform").

Our detector is the system's own code (RuleEngine, IsolationForestAnomalyDetector,
HybridAnomalyDetector). HDFS has no latency or time windows, so the latency and
traffic rules do not apply; error events are found from the template text
("exception", "interrupted"), never from the labels. Nothing is tuned on the test
set: the Isolation Forest uses the same contamination (0.03) as loglizer's.
"""

import argparse
import os
import re
import sys
import time
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(project_root, "mongodb_anomaly_detection"))

from models.log_schema import DetectionRule, WindowFeatures
from ml.isolation_forest_model import IsolationForestAnomalyDetector
from ml.hybrid_detector import HybridAnomalyDetector
from rules.rule_engine import RuleEngine
import contextlib
import io

ERROR_TEMPLATE = re.compile(r"exception|interrupted|error|fail", re.IGNORECASE)
NOT_APPLICABLE_RULES = {"low_traffic", "sudden_traffic_drop", "sudden_error_spike",
                        "high_latency_p95", "high_latency_p99"}

# Published results on the full HDFS dataset, for context only (different data size
# and splits than this benchmark, so not directly comparable)
REPORTED = [
    ("DeepLog (Du et al., CCS 2017)", "LSTM, reported in paper", 0.96),
    ("LogBERT (Guo et al., 2021)", "BERT, as reported by LAnoBERT 2022", 0.823),
    ("DeepLog reproduction (2026)", "independent re-run", 0.851),
]


def prf(y_true, y_pred):
    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1, fp


def build_rule_engine():
    """The system's rule engine, restricted to rules that apply to HDFS sessions."""
    engine = RuleEngine()
    for rule in list(engine.rules):
        if rule.rule_name in NOT_APPLICABLE_RULES:
            engine.disable_rule(rule.rule_name)
    engine.add_rule(DetectionRule(
        rule_name="exception_in_session",
        description="Block contains an exception or interruption event",
        condition_type="threshold",
        metric="error_count",
        operator=">",
        threshold=0,
        severity="high",
        alert_message_template="{value:.0f} error events for {service_name}",
    ))
    return engine


def to_windows(event_sequences, count_matrix, error_events):
    """One WindowFeatures per HDFS block, with the event count vector as features."""
    start = datetime(2008, 11, 9)
    windows = []
    for i, (sequence, counts) in enumerate(zip(event_sequences, count_matrix)):
        errors = sum(1 for event in sequence if event in error_events)
        windows.append(WindowFeatures(
            window_start=start + timedelta(minutes=i),
            window_end=start + timedelta(minutes=i + 1),
            service_name="hdfs",
            request_count=len(sequence),
            error_count=errors,
            error_rate=errors / max(len(sequence), 1),
            feature_vector=[float(c) for c in counts],
        ))
    return windows


def score_windows(hybrid, windows):
    """
    Rule, model and hybrid decisions for many independent windows at once.

    Same logic as HybridAnomalyDetector.detect_anomaly for windows without
    history (no persistence or duplicate suppression), but the Isolation Forest
    scores all windows in one batch instead of one call per window.
    """
    model = hybrid.model_detector
    X = model.scaler.transform(np.array([w.feature_vector for w in windows]))
    model_is = model.model.predict(X) == -1
    scores = np.array([model._normalize_score(d) for d in model.model.decision_function(X)])

    rule_pred, model_pred, hybrid_pred = [], [], []
    for window, is_anomaly, score in zip(windows, model_is, scores):
        violations = hybrid.rule_engine.evaluate_window(window, [])
        rule_conf = hybrid._calculate_rule_confidence(violations)
        final, _ = hybrid._combine_detections(bool(violations), rule_conf, bool(is_anomaly), float(score))
        rule_pred.append(int(bool(violations)))
        model_pred.append(int(is_anomaly))
        hybrid_pred.append(int(final))
    return np.array(rule_pred), np.array(model_pred), np.array(hybrid_pred)


def make_features(fe_fit, sequences, mode):
    counts = fe_fit(sequences)
    if mode == "counts+ratios":
        # Add each event's share of the block, so missing/extra events stand out
        counts = np.hstack([counts, counts / np.maximum(counts.sum(axis=1, keepdims=True), 1)])
    return counts


def train_hybrid(train_windows, contamination, voting):
    model = IsolationForestAnomalyDetector(contamination=contamination)
    with contextlib.redirect_stdout(io.StringIO()):
        model.train(train_windows)  # unsupervised: labels are not used
    return HybridAnomalyDetector(model, build_rule_engine(), voting_strategy=voting)


def select_on_validation(preprocessing, x_tr, y_train, error_events):
    """Pick features, contamination and voting on a validation part of the training data."""
    rng = np.random.RandomState(7)
    pos = rng.permutation(np.where(y_train == 1)[0])
    neg = rng.permutation(np.where(y_train == 0)[0])
    fit_idx = np.r_[pos[:len(pos) // 2], neg[:len(neg) // 2]]
    val_idx = np.r_[pos[len(pos) // 2:], neg[len(neg) // 2:]]

    trials = []
    for mode in ["counts", "counts+ratios"]:
        fe = preprocessing.FeatureExtractor()
        fit_windows = to_windows(x_tr[fit_idx], make_features(fe.fit_transform, x_tr[fit_idx], mode), error_events)
        val_windows = to_windows(x_tr[val_idx], make_features(fe.transform, x_tr[val_idx], mode), error_events)
        for contamination in [0.02, 0.03, 0.04, 0.05, 0.06, 0.08, 0.10]:
            for voting in ["weighted", "union"]:
                hybrid = train_hybrid(fit_windows, contamination, voting)
                _, _, predictions = score_windows(hybrid, val_windows)
                p, r, f1, _ = prf(y_train[val_idx], predictions)
                trials.append({"features": mode, "contamination": contamination, "voting": voting,
                               "val_precision": p, "val_recall": r, "val_f1": f1})
    trials = pd.DataFrame(trials).sort_values("val_f1", ascending=False, kind="stable")
    return trials.iloc[0].to_dict(), trials


def run_baselines(models, dataloader_module, preprocessing, x_tr, y_train, x_te, y_test):
    results = []
    configs = {
        "PCA": lambda fe: (fe.fit_transform(x_tr, term_weighting="tf-idf", normalization="zero-mean"),
                           models.PCA(), False),
        "Invariant Mining": lambda fe: (fe.fit_transform(x_tr), models.InvariantsMiner(epsilon=0.5), False),
        "Log Clustering": lambda fe: (fe.fit_transform(x_tr, term_weighting="tf-idf"),
                                      models.LogClustering(max_dist=0.3, anomaly_threshold=0.3), True),
        "Isolation Forest (plain)": lambda fe: (fe.fit_transform(x_tr),
                                                models.IsolationForest(random_state=2019, max_samples=0.9999,
                                                                       contamination=0.03, n_jobs=4), False),
    }
    for name, make in configs.items():
        fe = preprocessing.FeatureExtractor()
        x_train, model, normal_only = make(fe)
        start = time.perf_counter()
        model.fit(x_train[y_train == 0, :] if normal_only else x_train)
        fit_s = time.perf_counter() - start
        x_test = fe.transform(x_te)
        start = time.perf_counter()
        y_pred = np.asarray(model.predict(x_test))
        predict_ms = (time.perf_counter() - start) * 1000 / len(y_test)
        p, r, f1, fp = prf(y_test, y_pred)
        results.append({"method": name, "type": "unsupervised baseline (loglizer)",
                        "precision": p, "recall": r, "f1": f1, "false_positives": fp,
                        "train_s": fit_s, "detect_ms": predict_ms, "explains": "No"})
    return results


def run_ours(preprocessing, x_tr, x_te, y_test, error_events, features, contamination, voting, label):
    fe = preprocessing.FeatureExtractor()
    train_windows = to_windows(x_tr, make_features(fe.fit_transform, x_tr, features), error_events)
    test_windows = to_windows(x_te, make_features(fe.transform, x_te, features), error_events)

    start = time.perf_counter()
    hybrid = train_hybrid(train_windows, contamination, voting)
    train_s = time.perf_counter() - start

    rule_pred, model_pred, hybrid_pred = score_windows(hybrid, test_windows)

    # Real-time latency: the system's detect_anomaly on one window at a time
    sample = test_windows[:300]
    start = time.perf_counter()
    for window in sample:
        hybrid.clear_recent_alerts()
        hybrid.detect_anomaly(window, previous_results=[], previous_windows=[])
    detect_ms = (time.perf_counter() - start) * 1000 / len(sample)

    results = []
    for name, predictions in [("rules only", rule_pred), ("Isolation Forest only", model_pred),
                              ("hybrid (rules + IF)", hybrid_pred)]:
        p, r, f1, fp = prf(y_test, predictions)
        results.append({"method": f"Ours [{label}]: {name}", "type": "ours", "precision": p, "recall": r,
                        "f1": f1, "false_positives": fp,
                        "train_s": 0.0 if name == "rules only" else train_s,
                        "detect_ms": detect_ms, "explains": "Yes (rules + evidence)"})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--loglizer", required=True, help="Path to a clone of github.com/logpai/loglizer")
    parser.add_argument("--output", default=os.path.join(project_root, "evaluation", "results"))
    args = parser.parse_args()

    sys.path.insert(0, os.path.abspath(args.loglizer))
    from loglizer import dataloader, preprocessing
    import loglizer.models as models

    data_dir = os.path.join(args.loglizer, "data", "HDFS")
    log_file = os.path.join(data_dir, "HDFS_100k.log_structured.csv")
    label_file = os.path.join(data_dir, "anomaly_label.csv")

    np.random.seed(2019)
    (x_tr, y_train), (x_te, y_test) = dataloader.load_HDFS(
        log_file, label_file=label_file, window="session", train_ratio=0.5, split_type="uniform")
    templates = (pd.read_csv(log_file, usecols=["EventId", "EventTemplate"])
                 .drop_duplicates("EventId").set_index("EventId")["EventTemplate"].to_dict())

    error_events = sorted(e for e, template in templates.items() if ERROR_TEMPLATE.search(template))

    results = run_baselines(models, dataloader, preprocessing, x_tr, y_train, x_te, y_test)
    # 1) Defaults, same contamination as loglizer's Isolation Forest
    results += run_ours(preprocessing, x_tr, x_te, y_test, error_events,
                        "counts", 0.03, "weighted", "defaults")
    # 2) Settings chosen on a validation split of the training data; test set used once
    best, trials = select_on_validation(preprocessing, x_tr, y_train, error_events)
    results += run_ours(preprocessing, x_tr, x_te, y_test, error_events,
                        best["features"], best["contamination"], best["voting"], "validation-calibrated")

    table = pd.DataFrame(results)
    os.makedirs(args.output, exist_ok=True)
    table.to_csv(os.path.join(args.output, "hdfs_benchmark.csv"), index=False)
    trials.to_csv(os.path.join(args.output, "hdfs_validation_trials.csv"), index=False)

    print("\n" + "=" * 100)
    print(f"HDFS benchmark: {len(y_train)} train blocks ({int(y_train.sum())} anomalous), "
          f"{len(y_test)} test blocks ({int(y_test.sum())} anomalous)")
    print(f"Error events (from template text): {', '.join(error_events)}")
    print(f"Chosen on validation (training data only): features={best['features']}, "
          f"contamination={best['contamination']}, voting={best['voting']} (val F1 {best['val_f1']:.3f})")
    print("=" * 100)
    print(table.to_string(index=False, float_format=lambda v: f"{v:.3f}"))
    print("\nReported on the FULL HDFS dataset (different size/split, context only):")
    for name, note, f1 in REPORTED:
        print(f"  {name:32} F1 {f1:.3f}  ({note})")


if __name__ == "__main__":
    main()
