import sys, pandas as pd, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
out, res = sys.argv[1], sys.argv[2]
plt.rcParams.update({"font.family": "serif", "font.serif": ["DejaVu Serif"], "font.size": 9})

# Fig: Experiment A
a = pd.read_csv(f"{res}/model_comparison_known.csv")
names = {"Rules only (ours)": "Rules\n(ours)", "Isolation Forest (ours)": "IF\n(ours)",
         "Hybrid rules + IF (ours)": "Hybrid\n(ours)", "Random Forest (supervised)": "Random\nForest*",
         "Local Outlier Factor": "LOF", "One-Class SVM": "OC-SVM"}
a["short"] = a["model"].map(names)
fig, ax = plt.subplots(figsize=(3.5, 2.3), dpi=300)
x = range(len(a)); wd = 0.26
for i, (col, lab, c) in enumerate([("precision", "Precision", "#4C72B0"), ("recall", "Recall", "#DD8452"), ("f1", "F1", "#55A868")]):
    ax.bar([k + (i - 1) * wd for k in x], a[col], wd, label=lab, color=c)
ax.set_xticks(list(x)); ax.set_xticklabels(a["short"], fontsize=7)
ax.set_ylim(0, 1.05); ax.set_ylabel("Score"); ax.legend(fontsize=7, ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.18), frameon=False)
ax.grid(axis="y", alpha=0.3); ax.set_axisbelow(True)
fig.tight_layout(); fig.savefig(f"{out}/fig_known.png"); plt.close(fig)

# Fig: Experiment B
b = pd.read_csv(f"{res}/model_comparison_unseen.csv")
types = {"latency_spike": "Latency\nspike", "gradual_degradation": "Gradual\nslowdown", "error_burst": "Error\nburst", "traffic_drop": "Traffic\ndrop"}
fig, ax = plt.subplots(figsize=(3.5, 2.2), dpi=300)
x = range(len(b)); wd = 0.26
for i, (col, lab, c) in enumerate([("recall: Random Forest (supervised)", "Random Forest*", "#C44E52"),
                                   ("recall: Isolation Forest (ours)", "IF (ours)", "#4C72B0"),
                                   ("recall: Hybrid rules + IF (ours)", "Hybrid (ours)", "#55A868")]):
    ax.bar([k + (i - 1) * wd for k in x], b[col], wd, label=lab, color=c)
    for k, v in zip(x, b[col]):
        if v == 0:
            ax.text(k + (i - 1) * wd, 0.02, "0.00", ha="center", va="bottom", fontsize=6, color=c, rotation=90)
ax.set_xticks(list(x)); ax.set_xticklabels([types[t] for t in b["unseen_incident_type"]], fontsize=7)
ax.set_ylim(0, 1.05); ax.set_ylabel("Recall on unseen type")
ax.legend(fontsize=7, ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.18), frameon=False)
ax.grid(axis="y", alpha=0.3); ax.set_axisbelow(True)
fig.tight_layout(); fig.savefig(f"{out}/fig_unseen.png"); plt.close(fig)

# Fig: architecture
fig, ax = plt.subplots(figsize=(3.5, 3.6), dpi=300); ax.set_xlim(0, 10); ax.set_ylim(0, 11); ax.axis("off")
def box(x, y, w, h, text, color):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.05,rounding_size=0.2", fc=color, ec="#333", lw=0.8))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=6.5)
def arrow(x1, y1, x2, y2):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1), arrowprops=dict(arrowstyle="->", lw=0.8, color="#333"))
box(0.3, 9.6, 9.4, 1.0, "Microservice logs (auth, payment, user)\nREST ingestion: /api/logs, /api/logs/batch", "#E8EEF7")
box(0.3, 7.9, 9.4, 1.1, "MongoDB: log_entries, window_features, anomaly_results,\ndetection_rules, model_metadata + GridFS, incident_reports", "#FFF2CC")
box(0.3, 6.3, 9.4, 1.0, "Sliding windows (5 min, 1 min step) -> 19 features", "#E2F0D9")
box(0.3, 4.6, 4.4, 1.1, "Rule engine (7 rules)\nrule confidence", "#FBE5D6")
box(5.3, 4.6, 4.4, 1.1, "Isolation Forest (100 trees)\nmodel confidence", "#FBE5D6")
box(1.6, 3.0, 6.8, 1.0, "Hybrid fusion: 0.4 x rule + 0.6 x model >= 0.5", "#DEEBF7")
box(0.3, 1.3, 4.4, 1.1, "AI incident investigator\n(onset, evidence, root cause)", "#EADCF2")
box(5.3, 1.3, 4.4, 1.1, "Local LLM (Ollama)\ncitation + safety checks", "#EADCF2")
box(1.6, 0.0, 6.8, 0.8, "FastAPI REST API -> React dashboard", "#E8EEF7")
for (x1, y1, x2, y2) in [(5, 9.6, 5, 9.0), (5, 7.9, 5, 7.3), (2.5, 6.3, 2.5, 5.7), (7.5, 6.3, 7.5, 5.7),
                         (2.5, 4.6, 4, 4.0), (7.5, 4.6, 6, 4.0), (5, 3.0, 2.5, 2.4), (4.7, 1.85, 5.3, 1.85), (2.5, 1.3, 3.5, 0.8)]:
    arrow(x1, y1, x2, y2)
fig.tight_layout(); fig.savefig(f"{out}/fig_architecture.png"); plt.close(fig)
print("charts ok")
