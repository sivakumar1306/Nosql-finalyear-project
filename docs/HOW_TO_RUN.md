---
title: "Log Anomaly Detection System: How to Run"
subtitle: "G Sivakumar (23BCE1834), Afzal Ahamed A (23BCE1353). Guide: Manjula V, SCOPE, VIT Chennai"
---

# 1. Requirements

| Software | Version | Check with |
|---|---|---|
| Python | 3.10 or newer | `python --version` |
| Node.js | 16 or newer | `node --version` |
| MongoDB | 7.0 or newer, on port 27017 | `net start MongoDB` (as Administrator) |
| Ollama (optional, for the AI report) | any, with `llama3.2` | `ollama list` |

Source code: <https://github.com/sivakumar1306/Nosql-finalyear-project>

# 2. One-time setup

Open PowerShell in the project folder and run:

```
pip install -r requirements.txt
cd log-dashboard
npm install --legacy-peer-deps
npm i ajv@8 --legacy-peer-deps
cd ..
ollama pull llama3.2
```

# 3. Start the system (two windows)

Start **MongoDB** and **Ollama** first (Ollama: Start menu, then check <http://localhost:11434>).

**Window 1: backend** (in the project folder):

```
python run_detection.py --generate
python run_backend.py
```

The first command loads 6 hours of demo traffic with 4 incidents and runs detection. Wait for
`Uvicorn running on http://0.0.0.0:8000` and keep the window open.

**Window 2: dashboard**:

```
cd log-dashboard
npm start
```

| Open | What it is |
|---|---|
| <http://localhost:3000> | Dashboard |
| <http://localhost:8000/docs> | API page (to inject logs) |

# 4. Demo

1. **Dashboard:** pick a service in the sidebar to see its metrics, charts and anomalies.
2. **Inject failing logs:** on <http://localhost:8000/docs> open **POST /api/logs/batch**, click
   **Try it out**, paste 10 logs like the one below (same service), and click **Execute**. The
   response shows `"anomalies_detected": 1`.

   ```
   {"service_name":"payment-service","log_level":"ERROR","message":"Payment gateway timeout",
    "endpoint":"/api/payment","http_method":"POST","status_code":504,"response_time_ms":4200}
   ```

3. **Explain an alert:** refresh the dashboard and click the **eye icon** on the new anomaly to see
   the scores and the rules that fired.
4. **AI investigation:** click the **flask icon** (simulates a cascading failure), open the newest
   anomaly, then click **Investigate with AI**. Expected root cause: user-service.
5. **Model comparison (optional):** `python evaluation/model_comparison.py` (replaces the data).

# 5. Stop

Press **Ctrl+C** in both windows.

# 6. Common problems

| Problem | Fix |
|---|---|
| `Failed to connect to MongoDB` | Run `net start MongoDB` as Administrator |
| Port 8000 or 3000 already in use | `netstat -ano | findstr :8000`, then `taskkill /PID <number> /F` |
| `No module named 'config'` | Start the backend with `python run_backend.py` from the project folder |
| `'react-scripts' is not recognized` | Repeat the one-time setup in `log-dashboard` |
| Dashboard shows zeros | Data is old: rerun `python run_detection.py --generate`, restart the backend |
| `"anomalies_detected": 0` | Same service tested within 5 minutes; wait or use another service |
| AI report unavailable | Start Ollama; check the model name with `ollama list` |
