import type { Alert, AlertFilters, AlertListResponse, AlertStatus } from './types'

const API_BASE = import.meta.env.VITE_API_BASE ?? ''

function buildQuery(filters: AlertFilters, limit = 50, offset = 0): string {
  const params = new URLSearchParams()
  params.set('limit', String(limit))
  params.set('offset', String(offset))
  if (filters.source) params.set('source', filters.source)
  if (filters.severity) params.set('severity', filters.severity)
  if (filters.status) params.set('status', filters.status)
  return params.toString()
}

export async function fetchAlerts(
  filters: AlertFilters = {},
  limit = 50,
  offset = 0,
): Promise<AlertListResponse> {
  const query = buildQuery(filters, limit, offset)
  const res = await fetch(`${API_BASE}/api/alerts?${query}`)
  if (!res.ok) {
    throw new Error(`Failed to load alerts (${res.status})`)
  }
  return res.json()
}

export async function fetchAlert(id: number): Promise<Alert> {
  const res = await fetch(`${API_BASE}/api/alerts/${id}`)
  if (!res.ok) {
    throw new Error(`Failed to load alert (${res.status})`)
  }
  return res.json()
}

export async function updateAlertStatus(id: number, status: AlertStatus): Promise<Alert> {
  const res = await fetch(`${API_BASE}/api/alerts/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  })
  if (!res.ok) {
    throw new Error(`Failed to update alert (${res.status})`)
  }
  return res.json()
}
