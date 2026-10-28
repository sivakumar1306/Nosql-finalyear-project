# Quick Start

Full documentation: [README.md](README.md)

## 1. Prerequisites
- Python 3.10+ (`python --version`)
- Node.js 16+ (`node --version`)
- MongoDB 7.0+ running on port 27017 (Windows: `net start MongoDB` as Administrator if it is stopped)
- Optional: Ollama with a model (`ollama list`) for the AI incident report

## 2. Install (once)
```bash
pip install -r requirements.txt
cd log-dashboard
npm install --legacy-peer-deps
npm i ajv@8 --legacy-peer-deps
```

## 3. Run (two terminals)

**Terminal 1: backend**, from the project root:
```bash
python run_detection.py --generate
python run_backend.py
```

**Terminal 2: dashboard**:
```bash
cd log-dashboard
npm start
```

## 4. Open
- Dashboard: http://localhost:3000
- API documentation: http://localhost:8000/docs

## 5. Try it
1. Pick a service in the sidebar and look at the metrics, charts and anomalies.
2. Click the eye icon on an anomaly to see why it was flagged.
3. Click the flask icon to simulate a cascading failure, open the newest anomaly and click **Investigate with AI**.
