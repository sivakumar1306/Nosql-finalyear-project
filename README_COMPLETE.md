# Real-Time Log Monitoring and Anomaly Detection System

A comprehensive system for monitoring system logs, detecting anomalies using machine learning (Isolation Forest), and visualizing results through a React dashboard.

## 🚀 Features

### Backend (FastAPI + MongoDB)
- **Real-time anomaly detection** using Isolation Forest with borderline persistence
- **Rolling window feature extraction** for request count, error rate, and latency statistics
- **Hybrid detection** combining rule-based and model-based approaches
- **REST API** with comprehensive endpoints
- **MongoDB persistence** with optimized indexes
- **Model versioning** and metadata tracking
- **Data leakage prevention** in evaluation

### Frontend (React Dashboard)
- **Real-time monitoring** with auto-refresh capability
- **Service performance charts** for response time and error rate trends
- **Anomaly detection visualization** with rule/model/hybrid classifications
- **Filtering and pagination** for logs and anomalies
- **Service-specific metrics** and detailed views
- **Loading, empty, and error states**
- **Responsive design** with Material-UI components

## 📁 Project Structure

```
nosql-logbased-anomalydetection/
├── mongodb_anomaly_detection/     # Backend Python code
│   ├── api/                       # FastAPI application
│   ├── config/                    # Database configuration
│   ├── ml/                        # Machine learning components
│   ├── models/                    # MongoDB schemas
│   ├── rules/                     # Rule-based detection
│   ├── utils/                     # Utility functions
│   └── evaluation/                # Evaluation scripts
├── log-dashboard/                 # React frontend
│   ├── public/                    # Static assets
│   └── src/                       # React source code
│       ├── components/            # Reusable components
│       ├── contexts/              # React contexts
│       ├── pages/                 # Page components
│       └── services/              # API service layer
└── tests/                         # Test files
```

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.8+
- Node.js 16+
- MongoDB 5.0+
- Windows/Linux/MacOS

### 1. Backend Setup

```bash
# Navigate to project directory
cd e:\nosqlrealproject\nosql-logbased-anomalydetection

# Install Python dependencies
pip install -r requirements.txt

# Start MongoDB (if not already running)
# On Windows with MongoDB installed as service:
net start MongoDB

# Or using mongod directly:
mongod --dbpath "C:\data\db" --port 27017

# Start the backend API
cd mongodb_anomaly_detection\api
python main.py
```

The backend will start on `http://localhost:8000`

### 2. Frontend Setup

```bash
# Navigate to dashboard directory
cd e:\nosqlrealproject\nosql-logbased-anomalydetection\log-dashboard

# Install Node.js dependencies
npm install

# Start React development server
npm start
```

The frontend will start on `http://localhost:3000`

## 🔧 Configuration

### MongoDB Connection
Update the connection string in `mongodb_anomaly_detection/config/database.py` if MongoDB is not running locally on default port:

```python
# Default connection string
connection_string = "mongodb://localhost:27017/"
```

### Backend API Configuration
Environment variables can be set in `.env` file:
```
MONGODB_URI=mongodb://localhost:27017/
DATABASE_NAME=anomaly_detection
API_PORT=8000
```

### Frontend Configuration
Update API URL in `log-dashboard/src/services/api.js` if backend is running on different host/port:

```javascript
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
```

## 📊 API Endpoints

### Core Endpoints
- `GET /api/summary` - System-wide statistics with filtering
- `GET /api/services` - List of all monitored services
- `GET /api/services/{service_name}` - Detailed service metrics
- `GET /api/logs` - Paginated log entries with filters
- `GET /api/anomalies` - Paginated anomaly results
- `POST /api/model/retrain` - Retrain anomaly detection model
- `GET /api/model/versions` - List model versions
- `GET /api/rules` - List detection rules
- `GET /api/metrics/window` - Window metrics for charts
- `POST /api/detection/run` - Build windows and run detection over stored logs

### AI Incident Investigation
- `POST /api/incidents/investigate?anomaly_id=...` - Investigate the incident around an anomaly
- `GET /api/incidents` - List stored incident reports
- `GET /api/incidents/{id}` - Get one incident report
- `POST /api/simulate/cascading-failure` - Simulate user-service → auth-service → payment-service failure

## 🤖 AI Incident Investigator (Ollama)

Starting from one anomaly, the investigator correlates anomalies of all services
within ±15 minutes, rebuilds a per-minute timeline from the raw logs, ranks
root-cause hypotheses using the service dependency map, and collects numbered
evidence (E1, E2, ...) from MongoDB. A local LLM writes the incident report and
must cite that evidence; the backend checks every citation, lists unsupported
statements, and flags state-changing suggestions (restart, delete, ...) as
requiring human approval. The investigator only reads data and never executes
actions. Reports are stored in the `incident_reports` collection.

Setup:
```bash
ollama pull llama3.2      # or any model you have
ollama serve              # usually already running
```
Optional environment variables for the backend: `OLLAMA_URL` (default
`http://localhost:11434`), `OLLAMA_MODEL` (default `llama3.2`),
`OLLAMA_TIMEOUT_SECONDS` (default 180). Without Ollama, the data-driven part of
the report (timeline, hypotheses, evidence, steps) still works.

In the dashboard: click the flask icon to simulate a cascading failure, open an
anomaly with the eye icon, then click **Investigate with AI**.

## 🧪 Testing

### Backend Tests
```bash
cd mongodb_anomaly_detection\api
python test_api.py
```

### End-to-End Evaluation
```bash
cd mongodb_anomaly_detection\evaluation
python end_to_end_evaluation.py
```

### Frontend Tests
```bash
cd log-dashboard
npm test
```

## 🎯 Key Features Implementation Status

### ✅ Fully Implemented
1. **MongoDB Schemas & Indexes** - Optimized for query performance
2. **Rolling Window Features** - Request count, error rate, latency statistics
3. **Isolation Forest Model** - With borderline persistence
4. **Rule-Based Detection** - Threshold, rate change, and pattern rules
5. **Hybrid Detection** - Rule-only, model-only, and hybrid baselines
6. **REST API Endpoints** - All required endpoints with pagination/filtering
7. **React Dashboard** - Charts, tables, filters, real-time updates
8. **Evaluation Framework** - Comprehensive metrics with data leakage prevention

### 🔄 Partially Implemented
1. **Real-time WebSocket updates** - Currently using polling
2. **Advanced pattern matching rules** - Basic threshold rules implemented
3. **Production deployment** - Development setup complete

## 📈 Performance Metrics

The system tracks and reports:
- **Precision, Recall, F1 Score** - Model performance
- **False Positive Rate** - Detection accuracy
- **Per-scenario Recall** - Detection by anomaly type
- **Detection Latency** - End-to-end processing time
- **Throughput** - Logs/windows processed per second
- **Data Leakage Prevention** - Strict train/test separation

## 🐛 Known Limitations

1. **Synthetic Training Data** - Current implementation uses synthetic labels for training
2. **WebSocket Not Implemented** - Real-time updates use polling (30s intervals)
3. **Pattern Rule Complexity** - Pattern matching rules are simplified
4. **No Authentication** - API endpoints are unprotected (for development)
5. **Memory Usage** - Large datasets may require optimization for production

## 🔄 Future Improvements

1. **Real WebSocket Integration** - For true real-time updates
2. **Advanced Anomaly Scenarios** - More complex anomaly patterns
3. **Authentication & Authorization** - Secure API endpoints
4. **Docker Containerization** - Easy deployment
5. **Kubernetes Deployment** - Scalable production deployment
6. **Advanced Visualization** - More chart types and drill-down capabilities
7. **Alerting System** - Email/Slack notifications for anomalies
8. **Multi-tenant Support** - Support for multiple organizations

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Built with [FastAPI](https://fastapi.tiangolo.com/) and [React](https://reactjs.org/)
- Uses [Scikit-learn](https://scikit-learn.org/) for machine learning
- Charts powered by [Recharts](https://recharts.org/)
- UI components from [Material-UI](https://mui.com/)
- Database powered by [MongoDB](https://www.mongodb.com/)

## 📞 Support

For issues, questions, or feature requests:
1. Check existing documentation
2. Review closed issues
3. Open a new issue with detailed description
4. Provide reproduction steps for bugs