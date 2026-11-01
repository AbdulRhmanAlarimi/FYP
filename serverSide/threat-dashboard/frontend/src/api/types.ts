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

export type NamedCount = {
  name: string
  count: number
}

export type TimelinePoint = {
  date: string
  count: number
}

export type AlertStats = {
  total: number
  open: number
  acked: number
  critical_open: number
  by_severity: NamedCount[]
  by_source: NamedCount[]
  by_status: NamedCount[]
  top_event_types: NamedCount[]
  timeline: TimelinePoint[]
}
