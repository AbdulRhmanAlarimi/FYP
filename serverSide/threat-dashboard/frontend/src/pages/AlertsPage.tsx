import RefreshIcon from '@mui/icons-material/Refresh'
import {
  Alert as MuiAlert,
  Box,
  CircularProgress,
  IconButton,
  Stack,
  Typography,
} from '@mui/material'
import { useCallback, useEffect, useState } from 'react'
import { fetchAlerts, updateAlertStatus } from '../api/client'
import type { Alert, AlertFilters } from '../api/types'
import { AlertDetailDialog } from '../components/AlertDetailDialog'
import { AlertFiltersBar } from '../components/AlertFilters'
import { AlertsTable } from '../components/AlertsTable'

export function AlertsPage() {
  const [filters, setFilters] = useState<AlertFilters>({ status: 'open' })
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<Alert | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await fetchAlerts(filters)
      setAlerts(data.items)
      setTotal(data.total)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load alerts')
    } finally {
      setLoading(false)
    }
  }, [filters])

  useEffect(() => {
    void load()
  }, [load])

  const handleAck = async (alert: Alert) => {
    setBusy(true)
    try {
      const updated = await updateAlertStatus(alert.id, 'acked')
      setSelected(updated)
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to acknowledge alert')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Stack direction="row" sx={{ mb: 1, alignItems: 'center', justifyContent: 'space-between' }}>
        <Box>
          <Typography variant="h4" gutterBottom>
            Alerts
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Threats from RASP rules and future ML detections ({total} matching).
          </Typography>
        </Box>
        <IconButton aria-label="Refresh alerts" onClick={() => void load()} disabled={loading}>
          <RefreshIcon />
        </IconButton>
      </Stack>

      <AlertFiltersBar value={filters} onChange={setFilters} />

      {error && (
        <MuiAlert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </MuiAlert>
      )}

      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 6 }}>
          <CircularProgress />
        </Box>
      ) : (
        <AlertsTable alerts={alerts} onSelect={setSelected} />
      )}

      <AlertDetailDialog
        alert={selected}
        open={selected !== null}
        onClose={() => setSelected(null)}
        onAck={handleAck}
        busy={busy}
      />
    </>
  )
}
