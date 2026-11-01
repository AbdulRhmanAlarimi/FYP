import {
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material'
import type { Alert } from '../api/types'
import { SeverityChip } from './SeverityChip'
import { SourceChip } from './SourceChip'

type Props = {
  alerts: Alert[]
  onSelect: (alert: Alert) => void
}

function formatWhen(alert: Alert): string {
  return alert.timestamp || alert.created_at
}

export function AlertsTable({ alerts, onSelect }: Props) {
  if (alerts.length === 0) {
    return (
      <Paper variant="outlined" sx={{ p: 4, textAlign: 'center' }}>
        <Typography color="text.secondary">
          No alerts yet. RASP threats appear when the emulator posts risky events;
          ML alerts can be posted later to POST /api/alerts.
        </Typography>
      </Paper>
    )
  }

  return (
    <TableContainer component={Paper} variant="outlined">
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>ID</TableCell>
            <TableCell>Source</TableCell>
            <TableCell>Severity</TableCell>
            <TableCell>Title</TableCell>
            <TableCell>Event</TableCell>
            <TableCell>Status</TableCell>
            <TableCell>When</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {alerts.map((alert) => (
            <TableRow
              key={alert.id}
              hover
              sx={{ cursor: 'pointer' }}
              onClick={() => onSelect(alert)}
            >
              <TableCell>{alert.id}</TableCell>
              <TableCell>
                <SourceChip source={alert.source} />
              </TableCell>
              <TableCell>
                <SeverityChip severity={alert.severity} />
              </TableCell>
              <TableCell>{alert.title}</TableCell>
              <TableCell>{alert.event_type ?? '—'}</TableCell>
              <TableCell>{alert.status}</TableCell>
              <TableCell>{formatWhen(alert)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  )
}
