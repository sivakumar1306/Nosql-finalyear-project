import React, { useState } from 'react';
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  IconButton,
  Tooltip,
  Box,
  Typography,
  CircularProgress,
  Paper,
} from '@mui/material';
import VisibilityIcon from '@mui/icons-material/Visibility';
import WarningIcon from '@mui/icons-material/Warning';
import { useAnomaly } from '../contexts/AnomalyContext';
import { format } from 'date-fns';
import AnomalyDetailsDialog from './AnomalyDetailsDialog';

const AnomalyTable = () => {
  const { anomalies, loading } = useAnomaly();
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(5);
  const [selectedAnomaly, setSelectedAnomaly] = useState(null);
  
  if (loading.anomalies) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 300 }}>
        <CircularProgress />
        <Typography variant="body2" sx={{ ml: 2 }}>
          Loading anomalies...
        </Typography>
      </Box>
    );
  }
  
  const data = anomalies?.data || [];
  const total = anomalies?.total || 0;
  
  if (data.length === 0) {
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: 300 }}>
        <WarningIcon sx={{ fontSize: 48, color: 'warning.main', mb: 2 }} />
        <Typography variant="body1" gutterBottom>
          No Anomalies Detected
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Good news! No anomalies found in the selected time range.
        </Typography>
      </Box>
    );
  }
  
  const handleChangePage = (event, newPage) => {
    setPage(newPage);
  };
  
  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };
  
  // Format timestamp
  const formatTimestamp = (timestamp) => {
    try {
      return format(new Date(timestamp), 'MMM d, HH:mm:ss');
    } catch (error) {
      return 'Invalid date';
    }
  };
  
  // Get severity color based on detection method and confidence
  const getSeverityColor = (detectionMethod, confidence) => {
    if (detectionMethod.includes('critical') || confidence > 0.9) return 'error';
    if (detectionMethod.includes('high') || confidence > 0.7) return 'warning';
    if (detectionMethod.includes('medium') || confidence > 0.5) return 'info';
    return 'default';
  };
  
  // Get detection method label
  const getDetectionMethodLabel = (method) => {
    const methodMap = {
      'rule_only': 'Rule Only',
      'model_only': 'Model Only',
      'hybrid': 'Hybrid',
      'hybrid_both': 'Hybrid (Both)',
      'borderline_persistence': 'Borderline Persistence',
    };
    return methodMap[method] || method;
  };
  
  // Paginate data
  const paginatedData = data.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage);
  
  return (
    <Box>
      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Time</TableCell>
              <TableCell>Service</TableCell>
              <TableCell>Detection Method</TableCell>
              <TableCell>Confidence</TableCell>
              <TableCell>Severity</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {paginatedData.map((row, index) => (
              <TableRow key={row._id || index} hover>
                <TableCell>
                  <Typography variant="body2">
                    {formatTimestamp(row.timestamp)}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" fontWeight="medium">
                    {row.service_name}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Chip
                    label={getDetectionMethodLabel(row.detection_method)}
                    size="small"
                    color={
                      row.detection_method.includes('rule') ? 'primary' :
                      row.detection_method.includes('model') ? 'secondary' :
                      row.detection_method.includes('hybrid') ? 'success' : 'default'
                    }
                    variant="outlined"
                  />
                </TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    <Box 
                      sx={{ 
                        width: '100%', 
                        maxWidth: 60, 
                        height: 6, 
                        backgroundColor: '#e0e0e0',
                        borderRadius: 3,
                        overflow: 'hidden',
                        mr: 1
                      }}
                    >
                      <Box 
                        sx={{ 
                          height: '100%', 
                          width: `${(row.confidence || 0) * 100}%`,
                          backgroundColor: 
                            (row.confidence || 0) > 0.8 ? '#f44336' :
                            (row.confidence || 0) > 0.6 ? '#ff9800' :
                            (row.confidence || 0) > 0.4 ? '#2196f3' : '#4caf50'
                        }}
                      />
                    </Box>
                    <Typography variant="caption">
                      {(row.confidence || 0).toFixed(2)}
                    </Typography>
                  </Box>
                </TableCell>
                <TableCell>
                  <Chip
                    label={row.detection_method.includes('critical') ? 'Critical' :
                           row.detection_method.includes('high') ? 'High' :
                           row.detection_method.includes('medium') ? 'Medium' : 'Low'}
                    size="small"
                    color={getSeverityColor(row.detection_method, row.confidence || 0)}
                  />
                </TableCell>
                <TableCell align="right">
                  <Tooltip title="View details">
                    <IconButton size="small" onClick={() => setSelectedAnomaly(row)}>
                      <VisibilityIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
      
      <TablePagination
        rowsPerPageOptions={[5, 10, 25]}
        component="div"
        count={total}
        rowsPerPage={rowsPerPage}
        page={page}
        onPageChange={handleChangePage}
        onRowsPerPageChange={handleChangeRowsPerPage}
        labelRowsPerPage="Rows per page:"
        labelDisplayedRows={({ from, to, count }) => `${from}-${to} of ${count}`}
      />
      
      {/* Summary row */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mt: 2, p: 1, bgcolor: 'grey.50', borderRadius: 1 }}>
        <Typography variant="caption" color="text.secondary">
          Showing {paginatedData.length} of {total} anomalies
        </Typography>
        {total > 0 && (
          <Typography variant="caption" color="text.secondary">
            Average confidence: {(data.reduce((sum, row) => sum + (row.confidence || 0), 0) / data.length).toFixed(2)}
          </Typography>
        )}
      </Box>

      <AnomalyDetailsDialog
        anomaly={selectedAnomaly}
        onClose={() => setSelectedAnomaly(null)}
      />
    </Box>
  );
};

export default AnomalyTable;