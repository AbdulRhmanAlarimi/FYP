import { Box, Card, CardContent, Typography, useTheme } from '@mui/material'
import { BarChart } from '@mui/x-charts/BarChart'
import { LineChart } from '@mui/x-charts/LineChart'
import { PieChart } from '@mui/x-charts/PieChart'
import type { ReactNode } from 'react'
import type { AlertStats } from '../api/types'

type Props = {
  stats: AlertStats
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'] as const

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#d32f2f',
  high: '#f57c00',
  medium: '#fbc02d',
  low: '#0288d1',
}

const SOURCE_COLORS: Record<string, string> = {
  rasp: '#1565c0',
  ml: '#ad1457',
}

function ChartCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card variant="outlined" sx={{ height: '100%' }}>
      <CardContent>
        <Typography variant="subtitle1" gutterBottom>
          {title}
        </Typography>
        {children}
      </CardContent>
    </Card>
  )
}

function EmptyChart({ label }: { label: string }) {
  return (
    <Box sx={{ height: 260, display: 'grid', placeItems: 'center' }}>
      <Typography color="text.secondary">{label}</Typography>
    </Box>
  )
}

export function DashboardCharts({ stats }: Props) {
  const theme = useTheme()
  const axisColor = theme.palette.text.secondary

  const severityMap = Object.fromEntries(stats.by_severity.map((x) => [x.name, x.count]))
  const severityData = SEVERITY_ORDER.filter((name) => (severityMap[name] ?? 0) > 0).map(
    (name, id) => ({
      id,
      label: name,
      value: severityMap[name] ?? 0,
      color: SEVERITY_COLORS[name],
    }),
  )

  const sourceData = stats.by_source.map((item, id) => ({
    id,
    label: item.name.toUpperCase(),
    value: item.count,
    color: SOURCE_COLORS[item.name] ?? theme.palette.primary.main,
  }))

  const eventLabels = stats.top_event_types.map((x) => x.name || 'unknown')
  const eventCounts = stats.top_event_types.map((x) => x.count)

  const timelineLabels = stats.timeline.map((p) => p.date.slice(5))
  const timelineCounts = stats.timeline.map((p) => p.count)
  const hasTimeline = timelineCounts.some((n) => n > 0)

  return (
    <Box
      sx={{
        display: 'grid',
        gap: 2,
        mb: 3,
        gridTemplateColumns: { xs: '1fr', md: '1fr 1fr' },
      }}
    >
      <Box sx={{ gridColumn: { xs: '1', md: '1 / -1' } }}>
        <ChartCard title="Alert volume over time">
          {hasTimeline ? (
            <LineChart
              height={280}
              xAxis={[{ data: timelineLabels, scaleType: 'point', tickLabelStyle: { fill: axisColor } }]}
              yAxis={[{ tickLabelStyle: { fill: axisColor }, min: 0 }]}
              series={[
                {
                  data: timelineCounts,
                  label: 'Alerts',
                  color: theme.palette.primary.main,
                  area: true,
                  showMark: true,
                },
              ]}
              margin={{ left: 40, right: 16, top: 24, bottom: 40 }}
            />
          ) : (
            <EmptyChart label="No alerts in this window yet" />
          )}
        </ChartCard>
      </Box>

      <ChartCard title="Severity distribution">
        {severityData.length > 0 ? (
          <PieChart
            height={280}
            series={[
              {
                data: severityData,
                innerRadius: 55,
                outerRadius: 100,
                paddingAngle: 2,
                cornerRadius: 4,
                highlightScope: { fade: 'global', highlight: 'item' },
              },
            ]}
          />
        ) : (
          <EmptyChart label="No severity data yet" />
        )}
      </ChartCard>

      <ChartCard title="Source breakdown (RASP vs ML)">
        {sourceData.length > 0 ? (
          <PieChart
            height={280}
            series={[
              {
                data: sourceData,
                innerRadius: 55,
                outerRadius: 100,
                paddingAngle: 2,
                cornerRadius: 4,
              },
            ]}
          />
        ) : (
          <EmptyChart label="No source data yet" />
        )}
      </ChartCard>

      <Box sx={{ gridColumn: { xs: '1', md: '1 / -1' } }}>
        <ChartCard title="Top event types">
          {eventLabels.length > 0 ? (
            <BarChart
              height={300}
              layout="horizontal"
              yAxis={[
                {
                  data: eventLabels,
                  scaleType: 'band',
                  tickLabelStyle: { fill: axisColor, fontSize: 11 },
                  width: 180,
                },
              ]}
              xAxis={[{ tickLabelStyle: { fill: axisColor }, min: 0 }]}
              series={[
                {
                  data: eventCounts,
                  label: 'Count',
                  color: theme.palette.secondary.main,
                },
              ]}
              margin={{ left: 16, right: 24, top: 16, bottom: 32 }}
            />
          ) : (
            <EmptyChart label="No event types yet" />
          )}
        </ChartCard>
      </Box>
    </Box>
  )
}
