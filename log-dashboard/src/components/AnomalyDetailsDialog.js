import React from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Grid,
  Chip,
  Typography,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
} from '@mui/material';
import { format } from 'date-fns';

const METHOD_DESCRIPTIONS = {
  hybrid_both: 'Both the rule engine and the Isolation Forest model flagged this window.',
  rule_only: 'One or more detection rules were violated; the model score alone was not anomalous.',
  model_only: 'No rule threshold was crossed, but the Isolation Forest found this window unusual.',
  hybrid: 'The weighted combination of rule and model confidence crossed the anomaly threshold.',
  borderline_persistence: 'The model score stayed borderline for several consecutive windows.',
};

const formatTimestamp = (timestamp) => {
  try {
    return format(new Date(timestamp), 'MMM d, HH:mm:ss');
  } catch (error) {
    return 'Invalid date';
  }
};

// Show a rule metric in its natural unit
const formatMetric = (metric, value) => {
  if (value === null || value === undefined) return '-';
  if (metric === 'error_rate') return `${(value * 100).toFixed(1)}%`;
  if (metric.includes('response_time')) return `${Math.round(value)} ms`;
  if (metric === 'request_count') return Math.round(value).toString();
  return Number(value).toFixed(2);
};

const formatThreshold = (violation) => {
  if (violation.condition_type === 'rate_change') {
    return `${violation.operator} ${violation.threshold}x previous`;
  }
  return `${violation.operator} ${formatMetric(violation.metric, violation.threshold)}`;
};

const severityColor = (severity) => {
  if (severity === 'critical') return 'error';
  if (severity === 'high') return 'warning';
  if (severity === 'medium') return 'info';
  return 'default';
};

const ScoreItem = ({ label, value }) => (
  <Grid item xs={6} sm={3}>
    <Typography variant="caption" color="text.secondary">
      {label}
    </Typography>
    <Typography variant="h6">
      {value === null || value === undefined ? '-' : Number(value).toFixed(2)}
    </Typography>
  </Grid>
);

const AnomalyDetailsDialog = ({ anomaly, onClose }) => {
  if (!anomaly) return null;

  const metadata = anomaly.metadata || {};
  const violations = metadata.rule_violation_details || [];

  return (
    <Dialog open={Boolean(anomaly)} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h6">
            Anomaly in {anomaly.service_name}
          </Typography>
          <Chip label={anomaly.detection_method} size="small" color="primary" variant="outlined" />
        </Box>
      </DialogTitle>

      <DialogContent dividers>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          {METHOD_DESCRIPTIONS[anomaly.detection_method] || 'Flagged by the hybrid detector.'}
        </Typography>

        <Typography variant="subtitle2" sx={{ mt: 2 }}>
          Window
        </Typography>
        <Typography variant="body2">
          {anomaly.window_start ? formatTimestamp(anomaly.window_start) : '-'}
          {' to '}
          {anomaly.window_end ? formatTimestamp(anomaly.window_end) : '-'}
        </Typography>

        <Divider sx={{ my: 2 }} />

        <Typography variant="subtitle2" gutterBottom>
          Scores
        </Typography>
        <Grid container spacing={2}>
          <ScoreItem label="Final confidence" value={anomaly.confidence} />
          <ScoreItem label="Rule confidence (x0.4)" value={metadata.rule_confidence} />
          <ScoreItem label="Model confidence (x0.6)" value={metadata.model_confidence} />
          <ScoreItem label="Isolation Forest score" value={anomaly.isolation_forest_score} />
        </Grid>
        {anomaly.detection_latency_ms !== null && anomaly.detection_latency_ms !== undefined && (
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
            Detection latency: {anomaly.detection_latency_ms.toFixed(1)} ms
          </Typography>
        )}

        <Divider sx={{ my: 2 }} />

        <Typography variant="subtitle2" gutterBottom>
          Rule violations ({violations.length})
        </Typography>
        {violations.length === 0 ? (
          <Typography variant="body2" color="text.secondary">
            No rule thresholds were crossed for this window.
          </Typography>
        ) : (
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Rule</TableCell>
                  <TableCell>Value</TableCell>
                  <TableCell>Threshold</TableCell>
                  <TableCell>Severity</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {violations.map((violation) => (
                  <TableRow key={violation.rule_name}>
                    <TableCell>
                      <Typography variant="body2" fontWeight="medium">
                        {violation.rule_name}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {violation.alert_message || violation.rule_description}
                      </Typography>
                    </TableCell>
                    <TableCell>{formatMetric(violation.metric, violation.metric_value)}</TableCell>
                    <TableCell>{formatThreshold(violation)}</TableCell>
                    <TableCell>
                      <Chip
                        label={violation.severity}
                        size="small"
                        color={severityColor(violation.severity)}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
};

export default AnomalyDetailsDialog;
