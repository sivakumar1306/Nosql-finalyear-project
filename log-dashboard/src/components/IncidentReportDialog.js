import React, { useEffect, useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Chip,
  Typography,
  Divider,
  Alert,
  LinearProgress,
  CircularProgress,
  Paper,
  Tooltip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material';
import { format } from 'date-fns';
import { apiService } from '../services/api';

const severityColor = (severity) => {
  if (severity === 'critical') return 'error';
  if (severity === 'high') return 'warning';
  return 'info';
};

const formatTime = (timestamp) => {
  try {
    return format(new Date(timestamp), 'HH:mm:ss');
  } catch (error) {
    return '-';
  }
};

const EvidenceChips = ({ ids, evidenceById }) => (
  <Box component="span" sx={{ ml: 1 }}>
    {(ids || []).map((id) => (
      <Tooltip key={id} title={evidenceById[id]?.description || ''}>
        <Chip label={id} size="small" variant="outlined" sx={{ mr: 0.5, height: 20, fontSize: 11 }} />
      </Tooltip>
    ))}
  </Box>
);

const Section = ({ title, children }) => (
  <Box sx={{ mt: 3 }}>
    <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
      {title}
    </Typography>
    {children}
  </Box>
);

const IncidentReportDialog = ({ anomalyId, open, onClose }) => {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!open || !anomalyId) return;
    setReport(null);
    setError(null);
    setLoading(true);
    apiService.investigateIncident(anomalyId)
      .then((response) => setReport(response.data))
      .catch((err) => setError(err.response?.data?.detail || err.message))
      .finally(() => setLoading(false));
  }, [open, anomalyId]);

  const evidenceById = Object.fromEntries((report?.evidence || []).map((e) => [e.id, e]));
  const llm = report?.llm;
  const validation = llm?.validation;

  return (
    <Dialog open={open} onClose={onClose} maxWidth="lg" fullWidth>
      <DialogTitle>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h6">AI Incident Investigation</Typography>
          {report && (
            <Box>
              <Chip label={report.severity.toUpperCase()} color={severityColor(report.severity)} size="small" sx={{ mr: 1 }} />
              {report.affected_services.map((s) => (
                <Chip key={s.service} label={s.service} size="small" variant="outlined" sx={{ mr: 0.5 }} />
              ))}
            </Box>
          )}
        </Box>
      </DialogTitle>

      <DialogContent dividers>
        {loading && (
          <Box sx={{ display: 'flex', alignItems: 'center', py: 6, justifyContent: 'center' }}>
            <CircularProgress size={28} />
            <Typography variant="body2" sx={{ ml: 2 }}>
              Correlating anomalies across services, reading logs and asking the local LLM...
            </Typography>
          </Box>
        )}

        {error && <Alert severity="error">Investigation failed: {error}</Alert>}

        {report && (
          <>
            <Alert severity="info" sx={{ mb: 1 }}>
              Read-only investigation: every step below is a suggestion for an engineer. No action is executed automatically.
            </Alert>

            <Section title="Root-cause hypotheses">
              {report.hypotheses.map((h, index) => (
                <Paper key={h.title} variant="outlined" sx={{ p: 1.5, mb: 1 }}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Typography variant="body2" fontWeight={index === 0 ? 'bold' : 'medium'}>
                      {index + 1}. {h.title}
                    </Typography>
                    <Typography variant="body2" fontWeight="bold">
                      {(h.confidence * 100).toFixed(0)}%
                    </Typography>
                  </Box>
                  <LinearProgress
                    variant="determinate"
                    value={h.confidence * 100}
                    color={index === 0 ? 'error' : 'primary'}
                    sx={{ my: 0.5, height: 6, borderRadius: 3 }}
                  />
                  <Typography variant="caption" color="text.secondary">
                    Because {h.reasoning}.
                  </Typography>
                  <EvidenceChips ids={h.evidence} evidenceById={evidenceById} />
                </Paper>
              ))}
            </Section>

            <Section title="Incident timeline">
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableBody>
                    {report.timeline.map((t, index) => (
                      <TableRow key={index}>
                        <TableCell sx={{ width: 90 }}>{formatTime(t.time)}</TableCell>
                        <TableCell sx={{ width: 140 }}>
                          <Typography variant="body2" fontWeight="medium">{t.service}</Typography>
                        </TableCell>
                        <TableCell>
                          {t.event}
                          <EvidenceChips ids={t.evidence} evidenceById={evidenceById} />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Section>

            <Section title={`AI report${llm?.used ? ` (${llm.model} via Ollama)` : ''}`}>
              {llm?.used ? (
                <>
                  <Paper variant="outlined" sx={{ p: 2, whiteSpace: 'pre-wrap', fontSize: 14 }}>
                    {llm.narrative}
                  </Paper>
                  {validation?.grounded && validation.uncited_statements.length === 0 && (
                    <Alert severity="success" sx={{ mt: 1 }}>
                      Every statement cites real evidence ({validation.cited_evidence.join(', ')}).
                    </Alert>
                  )}
                  {validation?.unknown_citations.length > 0 && (
                    <Alert severity="warning" sx={{ mt: 1 }}>
                      The model cited evidence that does not exist: {validation.unknown_citations.join(', ')}. Treat those claims as unverified.
                    </Alert>
                  )}
                  {validation?.uncited_statements.length > 0 && (
                    <Alert severity="warning" sx={{ mt: 1 }}>
                      Not backed by evidence: {validation.uncited_statements.map((s) => `"${s}"`).join(' ')}
                    </Alert>
                  )}
                  {validation?.requires_human_approval && (
                    <Alert severity="error" sx={{ mt: 1 }}>
                      The report mentions state-changing actions ({validation.destructive_actions_flagged.join(', ')}). These require human approval and were not executed.
                    </Alert>
                  )}
                </>
              ) : (
                <Alert severity="warning">
                  The LLM report is unavailable ({llm?.error || 'not requested'}). The data-driven analysis on this page is still complete.
                </Alert>
              )}
            </Section>

            <Section title="Recommended troubleshooting steps">
              {report.recommended_steps.map((step, index) => (
                <Typography key={index} variant="body2" component="div" sx={{ mb: 1 }}>
                  {index + 1}. {step.action}
                  <EvidenceChips ids={step.evidence} evidenceById={evidenceById} />
                </Typography>
              ))}
            </Section>

            <Divider sx={{ mt: 3 }} />

            <Section title={`Evidence (${report.evidence.length})`}>
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>ID</TableCell>
                      <TableCell>Service</TableCell>
                      <TableCell>Type</TableCell>
                      <TableCell>Finding</TableCell>
                      <TableCell>Source</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {report.evidence.map((e) => (
                      <TableRow key={e.id}>
                        <TableCell>{e.id}</TableCell>
                        <TableCell>{e.service}</TableCell>
                        <TableCell>{e.type}</TableCell>
                        <TableCell>{e.description}</TableCell>
                        <TableCell>
                          <Typography variant="caption" color="text.secondary">
                            {e.source.collection}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Section>
          </>
        )}
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
};

export default IncidentReportDialog;
