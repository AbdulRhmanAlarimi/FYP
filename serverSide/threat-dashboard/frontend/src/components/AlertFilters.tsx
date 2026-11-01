import {
  Box,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  type SelectChangeEvent,
} from '@mui/material'
import type { AlertFilters as Filters, AlertSeverity, AlertSource, AlertStatus } from '../api/types'

type Props = {
  value: Filters
  onChange: (next: Filters) => void
}

export function AlertFiltersBar({ value, onChange }: Props) {
  const handle =
    (key: keyof Filters) => (event: SelectChangeEvent) => {
      onChange({ ...value, [key]: event.target.value })
    }

  return (
    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, mb: 2 }}>
      <FormControl size="small" sx={{ minWidth: 140 }}>
        <InputLabel id="filter-source">Source</InputLabel>
        <Select
          labelId="filter-source"
          label="Source"
          value={value.source ?? ''}
          onChange={handle('source')}
        >
          <MenuItem value="">All</MenuItem>
          <MenuItem value={'rasp' satisfies AlertSource}>RASP</MenuItem>
          <MenuItem value={'ml' satisfies AlertSource}>ML</MenuItem>
        </Select>
      </FormControl>

      <FormControl size="small" sx={{ minWidth: 140 }}>
        <InputLabel id="filter-severity">Severity</InputLabel>
        <Select
          labelId="filter-severity"
          label="Severity"
          value={value.severity ?? ''}
          onChange={handle('severity')}
        >
          <MenuItem value="">All</MenuItem>
          {(['low', 'medium', 'high', 'critical'] as AlertSeverity[]).map((s) => (
            <MenuItem key={s} value={s}>
              {s}
            </MenuItem>
          ))}
        </Select>
      </FormControl>

      <FormControl size="small" sx={{ minWidth: 140 }}>
        <InputLabel id="filter-status">Status</InputLabel>
        <Select
          labelId="filter-status"
          label="Status"
          value={value.status ?? ''}
          onChange={handle('status')}
        >
          <MenuItem value="">All</MenuItem>
          {(['open', 'acked'] as AlertStatus[]).map((s) => (
            <MenuItem key={s} value={s}>
              {s}
            </MenuItem>
          ))}
        </Select>
      </FormControl>
    </Box>
  )
}
