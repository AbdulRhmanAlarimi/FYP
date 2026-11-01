import { Chip } from '@mui/material'
import type { AlertSource } from '../api/types'

type Props = {
  source: AlertSource
}

export function SourceChip({ source }: Props) {
  return (
    <Chip
      size="small"
      label={source.toUpperCase()}
      color={source === 'rasp' ? 'primary' : 'secondary'}
      variant="outlined"
    />
  )
}
