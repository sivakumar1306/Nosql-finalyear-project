# Real-Time Log Anomaly Detection with MongoDB and AI Incident Investigation

A NoSQL-based system that collects microservice logs in MongoDB, detects anomalies in real time
with a hybrid of rules and an Isolation Forest model, shows them on a React dashboard, and uses a
local LLM (Ollama) to investigate incidents across services with evidence-backed reports.

```
Logs ─► MongoDB ─► 5-min sliding windows ─► Rule engine ─┐
                                          └► Isolation Forest ─┴► Hybrid vote ─► anomaly_results
                                                                                     │
           AI incident investigator (correlation + timeline + root cause + Ollama) ◄─┤
                                                     FastAPI REST API ─► React dashboard
```

## Features

**Detection**
- Logs are grouped into 5-minute windows that slide every minute; each window gets 19 features
  (request count, error rate, average/P95/P99/max latency, request sizes, HTTP method and status-code counts).
- **Rule engine** with 7 rules: error rate above 10% / 25%, P95 latency above 1 s, P99 above 2 s,
  low traffic, sudden traffic drop, sudden error spike. Rules are stored in MongoDB.
- **Isolation Forest** (unsupervised) with borderline persistence: slightly unusual windows raise
  an alert only if they stay unusual for 3 windows in a row.
- **Hybrid decision:** `0.4 × rule confidence + 0.6 × model confidence ≥ 0.5`, with duplicate alert
  suppression. Falls back to rules alone until a model is trained.
- Real-time detection on log ingestion (single and batch), plus a pipeline that processes all stored logs.

**AI incident investigator**
- Starting from one anomaly, it collects the anomalies of all services within ±15 minutes,
  rebuilds a per-minute timeline from the raw logs, and finds which service degraded first
  (sustained for at least 2 minutes, so one noisy minute is ignored).
- Ranks root-cause hypotheses with confidence, using timing, the service dependency map, and error
  messages that name other services.
- Every finding points to numbered evidence (`E1`, `E2`, …) taken from MongoDB records.
- A local LLM (Ollama) writes the report and must cite that evidence. The backend checks every
  citation, lists unsupported sentences, and flags state-changing suggestions (restart, delete,
  roll back, …) as requiring human approval. **The investigator only reads data; nothing is executed.**
- Works without Ollama too: the timeline, hypotheses, evidence and steps are computed from data.
- Reports are stored in the `incident_reports` collection.

**Dashboard (React + Material-UI)**
- System cards (logs, anomalies, services, active rules), per-service metrics, response-time and
  error-rate trend charts, anomaly and log tables, time-range filter, 30-second auto-refresh.
- Anomaly details (eye icon): window, final/rule/model confidence, and each violated rule with its
  value, threshold and severity.
- **Investigate with AI** button: hypotheses, timeline, AI report with citation checks, recommended
  read-only steps and the evidence table.
- **Simulate cascading failure** button (flask icon): user-service's database slows down, then
  auth-service and payment-service fail calling it.

## MongoDB design

Database `anomaly_detection` on `mongodb://localhost:27017`:

| Collection | Contents |
|---|---|
| `log_entries` | Raw logs (timestamp, service, level, endpoint, status, response time, free-form `metadata`) |
| `window_features` | One document per 5-minute window per service, with the 19-value feature vector |
| `anomaly_results` | Detection result per window: rule/model/hybrid scores, violated rules with details |
| `detection_rules` | The rule definitions (thresholds, severity, message templates) |
| `model_metadata` | Model versions, parameters and training metrics |
| `fs.files`, `fs.chunks` | **GridFS**: the trained Isolation Forest itself |
| `incident_reports` | AI investigation reports |

- Compound indexes on `(service_name, timestamp)` and `(window_start, service_name)` for the dashboard queries.
- **TTL indexes** delete old data automatically: logs after 30 days, windows after 90, results after 180.
- Aggregation pipelines compute averages, P95 (`$percentile`), error counts and per-minute timelines in the database.
- A text index on log messages.

## Requirements

- Python 3.10+ (`pip install -r requirements.txt`; on Python 3.13 install the same packages without the version pins)
- Node.js 16+
- **MongoDB 7.0+** (uses `$percentile`), running on port 27017
- Optional: [Ollama](https://ollama.com) with a model such as `llama3.2` for the AI report

## Setup (once)

```bash
pip install -r requirements.txt

cd log-dashboard
npm install --legacy-peer-deps
npm i ajv@8 --legacy-peer-deps     # fixes a known create-react-app start error
```

For the AI report: `ollama pull llama3.2` (check your models with `ollama list`).

## Running

Use two terminals and keep both open.

**Terminal 1: backend** (from the project root)
```bash
python run_detection.py --generate   # demo data with 4 injected incidents + detection
python run_backend.py                 # API on http://localhost:8000
```
`--generate` replaces all data with 6 hours of demo traffic; run it shortly before a demo so the
data is inside the dashboard's time range. Use `python run_detection.py` (without `--generate`) to
analyse logs already in MongoDB. Restart the backend after re-running detection so it loads the new model.

**Terminal 2: dashboard**
```bash
cd log-dashboard
npm start                             # http://localhost:3000
```

| URL | |
|---|---|
| http://localhost:3000 | Dashboard |
| http://localhost:8000/docs | Interactive API documentation |

### Ollama settings (optional)
Environment variables for the backend: `OLLAMA_MODEL` (default `llama3.2`), `OLLAMA_URL`
(default `http://localhost:11434`), `OLLAMA_TIMEOUT_SECONDS` (default 180). PowerShell example:
`$env:OLLAMA_MODEL="mistral:latest"` before `python run_backend.py`.

## Demo

1. **Detection overview:** the dashboard shows the 4 injected incidents (payment latency spike,
   auth gradual slowdown, auth error burst, user traffic drop); `run_detection.py --generate`
   prints which were detected.
2. **Live detection:** in http://localhost:8000/docs, send a batch of failing logs to
   `POST /api/logs/batch` (for example 10 `ERROR` logs with `"response_time_ms": 4000` for
   `payment-service`). The response shows `"anomalies_detected": 1` and the anomaly appears on
   the dashboard. The same service can be re-triggered after 5 minutes (duplicate suppression).
3. **Explanation:** click the eye icon on an anomaly to see which rules fired and the scores.
4. **AI investigation:** click the flask icon, open the newest anomaly, click **Investigate with AI**.
   Expected root cause: *Cascading failure originating in user-service*.

## Results (demo data)

- All 4 injected incidents detected.
- Window-level evaluation over 3 randomly generated datasets (3,165 windows):

| Detector | Precision | Recall | F1 | False alarms |
|---|---|---|---|---|
| Rules only | 0.89 | 0.74 | 0.81 | 20 |
| Isolation Forest only | 0.64 | 0.90 | 0.75 | 115 |
| **Hybrid** | **0.93** | **0.78** | **0.85** | **13** |

- Detection takes about 15–25 ms per window; training takes under a second on a laptop CPU.
- The cascading-failure investigation ranked user-service as the root cause (97–99% confidence)
  in 5 out of 5 runs with different background data.

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | Database, model and rules status |
| `GET /api/summary?time_range=24h` | System-wide statistics |
| `GET /api/services`, `GET /api/services/{name}` | Services and per-service metrics |
| `GET /api/logs`, `GET /api/anomalies` | Paginated logs and anomalies with filters |
| `POST /api/logs`, `POST /api/logs/batch` | Ingest logs (runs real-time detection) |
| `POST /api/detection/run` | Build windows and run detection over stored logs |
| `POST /api/model/retrain`, `GET /api/model/versions` | Retrain and list model versions |
| `GET /api/rules` | Detection rules |
| `GET /api/metrics/window` | Window metrics for charts |
| `POST /api/incidents/investigate?anomaly_id=...` | AI incident investigation |
| `GET /api/incidents`, `GET /api/incidents/{id}` | Stored incident reports |
| `POST /api/simulate/cascading-failure` | Simulate a cascading failure |

## Project structure

```
├── run_backend.py               # start the API
├── run_detection.py             # demo data (--generate) + detection pipeline
├── requirements.txt
├── mongodb_anomaly_detection/
│   ├── api/main.py              # FastAPI endpoints
│   ├── config/database.py       # MongoDB connection, GridFS
│   ├── models/                  # schemas and index definitions
│   ├── rules/rule_engine.py     # the 7 detection rules
│   └── ml/
│       ├── window_feature_extractor.py
│       ├── isolation_forest_model.py
│       ├── hybrid_detector.py
│       ├── detection_pipeline.py
│       ├── incident_investigator.py   # AI incident investigation
│       └── incident_simulator.py      # cascading-failure simulation
├── evaluation/                  # evaluation scripts
└── log-dashboard/               # React dashboard
    └── src/{components,contexts,pages,services}
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'config'` | Start the backend with `python run_backend.py` from the project root, not `main.py` inside `api/` |
| `error while attempting to bind on address ... 8000` | An old backend is running: `netstat -ano \| findstr :8000`, then `taskkill /PID <pid> /F` |
| `Something is already running on port 3000` | Stop the old dashboard the same way (`:3000`) and run `npm start` again |
| `'react-scripts' is not recognized` | Run the dashboard setup commands above |
| Dashboard shows zeros or "Unable to Load Dashboard" | Data is older than the time range or the backend is down: re-run `run_detection.py --generate` and restart the backend |
| AI report "unavailable" | Start Ollama, and check the model name with `ollama list` |

## Limitations and future work

- Evaluation uses generated data with injected incidents.
- The dashboard polls every 30 seconds (no WebSocket push).
- No authentication on the API.
- Small local models may omit citations; the report highlights such sentences.
- Future: incident history and dependency-graph views, alert acknowledgement and feedback,
  webhook notifications, Docker deployment.
