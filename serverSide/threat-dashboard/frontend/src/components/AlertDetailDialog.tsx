import {
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Stack,
  Typography,
} from '@mui/material'
import type { Alert } from '../api/types'
import { SeverityChip } from './SeverityChip'
import { SourceChip } from './SourceChip'

type Props = {
  alert: Alert | null
  open: boolean
  onClose: () => void
  onAck: (alert: Alert) => void
  busy?: boolean
}

export function AlertDetailDialog({ alert, open, onClose, onAck, busy }: Props) {
  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle>{alert?.title ?? 'Alert'}</DialogTitle>
      <DialogContent dividers>
        {alert && (
          <Stack spacing={2}>
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
              <SourceChip source={alert.source} />
              <SeverityChip severity={alert.severity} />
              <Typography variant="body2" color="text.secondary" sx={{ alignSelf: 'center' }}>
                status: {alert.status}
              </Typography>
            </Box>
            <Typography variant="body2">
              <strong>Event:</strong> {alert.event_id ?? '—'} / {alert.event_type ?? '—'}
            </Typography>
            <Typography variant="body2">
              <strong>Component:</strong> {alert.component ?? '—'}
            </Typography>
            <Typography variant="body2">
              <strong>Timestamp:</strong> {alert.timestamp ?? alert.created_at}
            </Typography>
            <Typography variant="body2">
              <strong>Reason:</strong> {alert.reason ?? '—'}
            </Typography>
            <Box>
              <Typography variant="subtitle2" gutterBottom>
                Payload
              </Typography>
              <Box
                component="pre"
                sx={{
                  m: 0,
                  p: 1.5,
                  borderRadius: 1,
                  bgcolor: 'action.hover',
                  overflow: 'auto',
                  fontSize: 12,
                }}
              >
                {JSON.stringify(alert.payload, null, 2)}
              </Box>
            </Box>
          </Stack>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
        {alert && alert.status === 'open' && (
          <Button
            variant="contained"
            disabled={busy}
            onClick={() => onAck(alert)}
          >
            Acknowledge
          </Button>
        )}
      </DialogActions>
    </Dialog>
  )
}
