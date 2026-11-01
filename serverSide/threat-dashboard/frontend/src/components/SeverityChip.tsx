import { Chip } from '@mui/material'
import type { AlertSeverity } from '../api/types'

const COLOR: Record<AlertSeverity, 'default' | 'success' | 'warning' | 'error' | 'info'> = {
  low: 'info',
  medium: 'warning',
  high: 'error',
  critical: 'error',
}

type Props = {
  severity: AlertSeverity
}

export function SeverityChip({ severity }: Props) {
  return (
    <Chip
      size="small"
      label={severity}
      color={COLOR[severity]}
      variant={severity === 'critical' ? 'filled' : 'outlined'}
    />
  )
}
