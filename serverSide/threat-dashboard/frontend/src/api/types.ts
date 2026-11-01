export type AlertSource = 'rasp' | 'ml'
export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical'
export type AlertStatus = 'open' | 'acked'

export type Alert = {
  id: number
  source: AlertSource
  severity: AlertSeverity
  title: string
  event_id: string | null
  event_type: string | null
  component: string | null
  timestamp: string | null
  payload: Record<string, unknown>
  status: AlertStatus
  reason: string | null
  created_at: string
}

export type AlertListResponse = {
  items: Alert[]
  total: number
  limit: number
  offset: number
}

export type AlertFilters = {
  source?: AlertSource | ''
  severity?: AlertSeverity | ''
  status?: AlertStatus | ''
}
