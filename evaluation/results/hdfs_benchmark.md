# HDFS public benchmark

Reproduce: `git clone https://github.com/logpai/loglizer` then
`python evaluation/hdfs_benchmark.py --loglizer path/to/loglizer` (about 30 s on a laptop).

## Setup
- **Data:** HDFS_100k sample from loglizer (He et al., ISSRE 2016): 104,815 log lines,
  7,940 HDFS blocks, one sample per block, event-count vectors.
- **Split:** loglizer's benchmark split: 50/50, anomalies spread evenly
  (3,969 train blocks / 156 anomalous; 3,971 test blocks / 157 anomalous).
- **Baselines:** loglizer's own implementations and default settings, run on the same split.
- **Ours:** the system's own `RuleEngine`, `IsolationForestAnomalyDetector` and
  `HybridAnomalyDetector`. HDFS has no latency or time windows, so latency/traffic rules
  are off; error events are found from the template text (`exception`, `interrupted`),
  never from labels. Unsupervised: labels are not used for training.
- **No test-set tuning:** settings were either loglizer's defaults (contamination 0.03) or
  chosen on a validation split of the training data. The test set was used once per setting.

## Results (test set)

| Method | Precision | Recall | F1 | False positives (of 3,814 normal) |
|---|---|---|---|---|
| PCA | 0.966 | 0.363 | 0.528 | 2 |
| Invariant Mining | 0.967 | 0.561 | **0.710** | 3 |
| Log Clustering | 0.967 | 0.561 | **0.710** | 3 |
| Isolation Forest (plain, loglizer) | 0.986 | 0.439 | 0.608 | 1 |
| Ours: rules only | **1.000** | 0.236 | 0.381 | **0** |
| Ours: Isolation Forest only | 0.986 | 0.433 | 0.602 | 1 |
| Ours: hybrid (rules + IF) | 0.986 | 0.433 | 0.602 | 1 |

Validation-calibrated settings (features, contamination 0.02–0.10, weighted/union voting)
gave identical test results, so they are not repeated here (see `hdfs_validation_trials.csv`).

Reported on the **full** HDFS dataset (11M lines; different size and split, context only):
DeepLog F1 0.96 (paper), 0.85 (independent reproduction); LogBERT F1 0.82.

## Findings
1. **All methods are near-perfectly precise** (0.97–1.00). Our exception rule has 0 false
   positives; the hybrid has 1 false positive in 3,814 normal blocks.
2. **Recall is capped by the data, not the model:** 69 of 157 anomalous test blocks (44%) have
   an event-count vector identical to a normal training block, so no count-based method can
   exceed recall 0.561. Invariant Mining and Log Clustering reach this ceiling; Isolation Forest
   (ours and loglizer's) reaches 0.43.
3. **Our hybrid adds no recall on HDFS:** every block caught by the exception rule is already
   caught by the Isolation Forest. On our microservice data (latency, error rate, traffic), the
   hybrid does help: F1 0.85 vs 0.81 rules-only and 0.75 model-only over 3 datasets.
4. We tested whether mined invariant rules would help the hybrid; on the validation split they
   added nothing, so they were not adopted (choosing them after seeing test results would be
   test-set tuning).

## Honest summary
On HDFS, our detector matches the standard Isolation Forest baseline (F1 0.60 vs 0.61) with
near-perfect precision, but is below Invariant Mining and Log Clustering (0.71), which hit the
dataset's recall ceiling. Deep sequence models (DeepLog, LogBERT) report higher F1 on the full
dataset because event order carries information that counts do not. Our system's contribution is
not a higher HDFS score but real-time, explainable detection of performance anomalies
(latency/errors/traffic) with evidence-backed AI incident investigation.

Detection time: baselines are timed as one batch; ours (about 14 ms) is the real-time path,
one window at a time through `detect_anomaly`, so the columns are not directly comparable.
