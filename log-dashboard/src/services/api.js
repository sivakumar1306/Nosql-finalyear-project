import axios from 'axios';

// API configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
const API_TIMEOUT = 30000; // 30 seconds

// Create axios instance with default config
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: API_TIMEOUT,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for adding auth tokens if needed
api.interceptors.request.use(
  (config) => {
    // You can add authentication tokens here if needed
    // const token = localStorage.getItem('token');
    // if (token) {
    //   config.headers.Authorization = `Bearer ${token}`;
    // }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response) {
      // Server responded with error status
      console.error('API Error:', error.response.status, error.response.data);
    } else if (error.request) {
      // Request made but no response
      console.error('Network Error:', error.request);
    } else {
      // Something else happened
      console.error('Error:', error.message);
    }
    return Promise.reject(error);
  }
);

// API endpoints
export const apiService = {
  // Health check
  healthCheck: () => api.get('/api/health'),

  // Summary statistics
  getSummary: (timeRange) =>
    api.get('/api/summary', { params: { time_range: timeRange } }),

  // Services
  getServices: () => api.get('/api/services'),
  getServiceDetails: (serviceName, timeRange) =>
    api.get(`/api/services/${serviceName}`, { params: { time_range: timeRange } }),

  // Logs
  getLogs: (params) => api.get('/api/logs', { params }),

  // Anomalies
  getAnomalies: (params) => api.get('/api/anomalies', { params }),

  // Incident investigation (the local LLM can take a while on CPU)
  investigateIncident: (anomalyId, useLlm = true) =>
    api.post('/api/incidents/investigate', null, {
      params: { anomaly_id: anomalyId, use_llm: useLlm },
      timeout: 240000,
    }),
  getIncidents: (limit = 20) => api.get('/api/incidents', { params: { limit } }),
  simulateCascadingFailure: () => api.post('/api/simulate/cascading-failure'),

  // Model
  getModelVersions: (limit = 10) =>
    api.get('/api/model/versions', { params: { limit } }),
  retrainModel: (data) => api.post('/api/model/retrain', data),

  // Rules
  getRules: (enabledOnly = false) =>
    api.get('/api/rules', { params: { enabled_only: enabledOnly } }),

  // Window metrics for charts
  getWindowMetrics: (serviceName, hours = 24) =>
    api.get('/api/metrics/window', { params: { service_name: serviceName, hours } }),

  // Real-time updates (WebSocket simulation - using polling for now)
  subscribeToUpdates: (callback, interval = 10000) => {
    const intervalId = setInterval(async () => {
      try {
        const startTime = Date.now();
        const summary = await api.get('/api/summary');
        const anomalies = await api.get('/api/anomalies', { params: { page_size: 5 } });
        const dashboardLatency = Date.now() - startTime;

        callback({
          summary: summary.data,
          recentAnomalies: anomalies.data.data,
          dashboardLatency
        });
      } catch (error) {
        console.error('Error in real-time update:', error);
      }
    }, interval);

    return () => clearInterval(intervalId);
  },

  // Performance monitoring endpoint
  getPerformanceMetrics: () => api.get('/api/performance'),

  // Log ingestion with latency tracking
  ingestLogWithTracking: async (logData) => {
    const startTime = Date.now();
    try {
      const response = await api.post('/api/logs', logData);
      const endToEndLatency = Date.now() - startTime;
      return {
        ...response.data,
        dashboardLatency: endToEndLatency
      };
    } catch (error) {
      const endToEndLatency = Date.now() - startTime;
      throw {
        error,
        dashboardLatency: endToEndLatency
      };
    }
  },

  // Batch log ingestion with tracking
  ingestLogsBatchWithTracking: async (logsData) => {
    const startTime = Date.now();
    try {
      const response = await api.post('/api/logs/batch', logsData);
      const endToEndLatency = Date.now() - startTime;
      return {
        ...response.data,
        dashboardLatency: endToEndLatency
      };
    } catch (error) {
      const endToEndLatency = Date.now() - startTime;
      throw {
        error,
        dashboardLatency: endToEndLatency
      };
    }
  },
};

export default api;