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
import { fetchAlertStats, fetchAlerts, updateAlertStatus } from '../api/client'
import type { Alert, AlertFilters, AlertStats } from '../api/types'
import { AlertDetailDialog } from '../components/AlertDetailDialog'
import { AlertFiltersBar } from '../components/AlertFilters'
import { AlertsTable } from '../components/AlertsTable'
import { DashboardCharts } from '../components/DashboardCharts'
import { StatCards } from '../components/StatCards'

export function AlertsPage() {
  const [filters, setFilters] = useState<AlertFilters>({ status: 'open' })
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [stats, setStats] = useState<AlertStats | null>(null)
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<Alert | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [alertData, statsData] = await Promise.all([
        fetchAlerts(filters),
        fetchAlertStats(14),
      ])
      setAlerts(alertData.items)
      setTotal(alertData.total)
      setStats(statsData)
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
            Security Operations
          </Typography>
          <Typography variant="body1" color="text.secondary">
            SIEM-style overview of RASP and ML threats ({total} matching current filters).
          </Typography>
        </Box>
        <IconButton aria-label="Refresh alerts" onClick={() => void load()} disabled={loading}>
          <RefreshIcon />
        </IconButton>
      </Stack>

      {error && (
        <MuiAlert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </MuiAlert>
      )}

      {loading && !stats ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 6 }}>
          <CircularProgress />
        </Box>
      ) : (
        <>
          {stats && (
            <>
              <StatCards stats={stats} />
              <DashboardCharts stats={stats} />
            </>
          )}

          <Typography variant="h5" sx={{ mb: 1 }}>
            Alert feed
          </Typography>
          <AlertFiltersBar value={filters} onChange={setFilters} />

          {loading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
              <CircularProgress size={28} />
            </Box>
          ) : (
            <AlertsTable alerts={alerts} onSelect={setSelected} />
          )}
        </>
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
