import { Alert, Typography } from '@mui/material'

/** Placeholder page — alerts table wired in the next step. */
export function AlertsPage() {
  return (
    <>
      <Typography variant="h4" gutterBottom>
        Alerts
      </Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
        Threats from RASP rules and future ML detections.
      </Typography>
      <Alert severity="info">Dashboard shell is ready. Alert list comes next.</Alert>
    </>
  )
}
