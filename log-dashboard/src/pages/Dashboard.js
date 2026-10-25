import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  Card,
  CardContent,
  Divider,
  Chip,
  LinearProgress,
  IconButton,
  Tooltip,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Button,
  CircularProgress,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import TimelineIcon from '@mui/icons-material/Timeline';
import WarningIcon from '@mui/icons-material/Warning';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import InfoIcon from '@mui/icons-material/Info';
import { useAnomaly } from '../contexts/AnomalyContext';
import { useSnackbar } from 'notistack';
import AnomalyTable from '../components/AnomalyTable';
import LogTable from '../components/LogTable';
import ResponseTimeChart from '../components/ResponseTimeChart';
import ErrorRateChart from '../components/ErrorRateChart';
import ServiceMetrics from '../components/ServiceMetrics';

const Dashboard = () => {
  const {
    summary,
    serviceDetails,
    logs,
    anomalies,
    loading,
    filters,
    updateFilters,
    refreshAll,
    selectedService,
  } = useAnomaly();
  
  const { enqueueSnackbar } = useSnackbar();
  const [autoRefresh, setAutoRefresh] = useState(false);
  
  // Toggle auto-refresh
  useEffect(() => {
    let intervalId;
    
    if (autoRefresh) {
      intervalId = setInterval(() => {
        refreshAll();
        enqueueSnackbar('Data refreshed automatically', { variant: 'info', autoHideDuration: 2000 });
      }, 30000); // 30 seconds
    }
    
    return () => {
      if (intervalId) {
        clearInterval(intervalId);
      }
    };
  }, [autoRefresh, refreshAll, enqueueSnackbar]);
  
  const handleTimeRangeChange = (event) => {
    updateFilters({ timeRange: event.target.value });
  };
  
  const handleRefresh = () => {
    refreshAll();
    enqueueSnackbar('Data refreshed', { variant: 'success' });
  };
  
  const toggleAutoRefresh = () => {
    setAutoRefresh(!autoRefresh);
    enqueueSnackbar(
      autoRefresh ? 'Auto-refresh disabled' : 'Auto-refresh enabled (30s)',
      { variant: 'info' }
    );
  };
  
  // Loading state
  if (loading.summary && !summary) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80vh' }}>
        <CircularProgress />
        <Typography variant="body1" sx={{ ml: 2 }}>
          Loading dashboard...
        </Typography>
      </Box>
    );
  }
  
  // Error state
  if (!summary) {
    return (
      <Box sx={{ textAlign: 'center', mt: 8 }}>
        <ErrorIcon sx={{ fontSize: 64, color: 'error.main', mb: 2 }} />
        <Typography variant="h5" gutterBottom>
          Unable to Load Dashboard
        </Typography>
        <Typography variant="body1" color="text.secondary" paragraph>
          There was an error connecting to the backend API.
        </Typography>
        <Button variant="contained" onClick={handleRefresh}>
          Try Again
        </Button>
      </Box>
    );
  }
  
  // Empty state
  if (summary.total_logs === 0) {
    return (
      <Box sx={{ textAlign: 'center', mt: 8 }}>
        <InfoIcon sx={{ fontSize: 64, color: 'info.main', mb: 2 }} />
        <Typography variant="h5" gutterBottom>
          No Data Available
        </Typography>
        <Typography variant="body1" color="text.secondary" paragraph>
          Start by ingesting some log data to see anomaly detection in action.
        </Typography>
      </Box>
    );
  }
  
  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Box>
            <Typography variant="h4" gutterBottom>
              Anomaly Detection Dashboard
            </Typography>
            <Typography variant="body1" color="text.secondary">
              {selectedService 
                ? `Monitoring: ${selectedService}`
                : 'Select a service to view detailed metrics'
              }
            </Typography>
          </Box>
          
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
            <FormControl size="small" sx={{ minWidth: 120 }}>
              <InputLabel>Time Range</InputLabel>
              <Select
                value={filters.timeRange}
                label="Time Range"
                onChange={handleTimeRangeChange}
                disabled={loading.summary}
              >
                <MenuItem value="1h">Last Hour</MenuItem>
                <MenuItem value="6h">Last 6 Hours</MenuItem>
                <MenuItem value="24h">Last 24 Hours</MenuItem>
                <MenuItem value="7d">Last 7 Days</MenuItem>
              </Select>
            </FormControl>
            
            <Tooltip title="Refresh data">
              <IconButton onClick={handleRefresh} disabled={loading.summary}>
                <RefreshIcon />
              </IconButton>
            </Tooltip>
            
            <Tooltip title={autoRefresh ? "Disable auto-refresh" : "Enable auto-refresh (30s)"}>
              <IconButton 
                onClick={toggleAutoRefresh} 
                color={autoRefresh ? "primary" : "default"}
              >
                <TimelineIcon />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>
        
        {loading.summary && <LinearProgress sx={{ mb: 2 }} />}
      </Box>
      
      {/* Summary Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {/* Total Logs */}
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom variant="overline">
                Total Logs
              </Typography>
              <Typography variant="h4">
                {summary.total_logs.toLocaleString()}
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                <CheckCircleIcon fontSize="small" color="success" sx={{ mr: 0.5 }} />
                <Typography variant="body2" color="text.secondary">
                  System Active
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        {/* Anomalies */}
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom variant="overline">
                Anomalies Detected
              </Typography>
              <Typography variant="h4">
                {summary.total_anomalies.toLocaleString()}
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                <Chip
                  label={`${(summary.anomaly_rate * 100).toFixed(1)}%`}
                  size="small"
                  color={summary.anomaly_rate > 0.05 ? 'error' : 'success'}
                  variant="outlined"
                />
                <Typography variant="body2" color="text.secondary" sx={{ ml: 1 }}>
                  anomaly rate
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        {/* Recent Anomalies */}
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom variant="overline">
                Recent Anomalies
              </Typography>
              <Typography variant="h4">
                {summary.recent_anomalies.toLocaleString()}
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                <WarningIcon fontSize="small" color="warning" sx={{ mr: 0.5 }} />
                <Typography variant="body2" color="text.secondary">
                  Last 24 hours
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        {/* Services */}
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="text.secondary" gutterBottom variant="overline">
                Monitored Services
              </Typography>
              <Typography variant="h4">
                {summary.services.length}
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                <Typography variant="body2" color="text.secondary">
                  {summary.active_rules} active rules
                </Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
      
      {/* Service Selection and Metrics */}
      {selectedService && (
        <>
          <ServiceMetrics />
          
          {/* Charts Row */}
          <Grid container spacing={3} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, height: '100%' }}>
                <Typography variant="h6" gutterBottom>
                  Response Time Trend
                </Typography>
                <ResponseTimeChart />
              </Paper>
            </Grid>
            
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, height: '100%' }}>
                <Typography variant="h6" gutterBottom>
                  Error Rate Trend
                </Typography>
                <ErrorRateChart />
              </Paper>
            </Grid>
          </Grid>
        </>
      )}
      
      {/* Tables Row */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2, height: '100%' }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">
                Recent Anomalies
              </Typography>
              <Chip
                label={`${anomalies?.total || 0} total`}
                size="small"
                color="primary"
                variant="outlined"
              />
            </Box>
            <Divider sx={{ mb: 2 }} />
            <AnomalyTable />
          </Paper>
        </Grid>
        
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2, height: '100%' }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">
                Recent Logs
              </Typography>
              <Chip
                label={`${logs?.total || 0} total`}
                size="small"
                color="primary"
                variant="outlined"
              />
            </Box>
            <Divider sx={{ mb: 2 }} />
            <LogTable />
          </Paper>
        </Grid>
      </Grid>
      
      {/* Auto-refresh indicator */}
      {autoRefresh && (
        <Box sx={{ position: 'fixed', bottom: 16, right: 16, display: 'flex', alignItems: 'center' }}>
          <CircularProgress size={16} sx={{ mr: 1 }} />
          <Typography variant="caption" color="text.secondary">
            Auto-refresh enabled
          </Typography>
        </Box>
      )}
    </Box>
  );
};

export default Dashboard;