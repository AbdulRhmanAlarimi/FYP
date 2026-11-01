import ErrorOutlinedIcon from '@mui/icons-material/ErrorOutlined'
import MarkEmailReadIcon from '@mui/icons-material/MarkEmailRead'
import NotificationAddIcon from '@mui/icons-material/NotificationAdd'
import WarningAmberIcon from '@mui/icons-material/WarningAmber'
import { Box, Card, CardContent, Typography } from '@mui/material'
import type { AlertStats } from '../api/types'

type Props = {
  stats: AlertStats
}

const CARDS = [
  {
    key: 'total',
    label: 'Total alerts',
    icon: NotificationAddIcon,
    color: 'primary.main',
    value: (s: AlertStats) => s.total,
  },
  {
    key: 'open',
    label: 'Open',
    icon: WarningAmberIcon,
    color: 'warning.main',
    value: (s: AlertStats) => s.open,
  },
  {
    key: 'critical',
    label: 'Critical open',
    icon: ErrorOutlinedIcon,
    color: 'error.main',
    value: (s: AlertStats) => s.critical_open,
  },
  {
    key: 'acked',
    label: 'Acknowledged',
    icon: MarkEmailReadIcon,
    color: 'success.main',
    value: (s: AlertStats) => s.acked,
  },
] as const

export function StatCards({ stats }: Props) {
  return (
    <Box
      sx={{
        display: 'grid',
        gap: 2,
        mb: 2,
        gridTemplateColumns: {
          xs: '1fr',
          sm: '1fr 1fr',
          md: 'repeat(4, 1fr)',
        },
      }}
    >
      {CARDS.map((card) => {
        const Icon = card.icon
        return (
          <Card key={card.key} variant="outlined">
            <CardContent sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Box sx={{ color: card.color, display: 'flex' }}>
                <Icon fontSize="large" />
              </Box>
              <Box>
                <Typography variant="body2" color="text.secondary">
                  {card.label}
                </Typography>
                <Typography variant="h4">{card.value(stats)}</Typography>
              </Box>
            </CardContent>
          </Card>
        )
      })}
    </Box>
  )
}
