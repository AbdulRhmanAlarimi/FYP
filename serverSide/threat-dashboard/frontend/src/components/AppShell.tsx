import SecurityIcon from '@mui/icons-material/Security'
import { AppBar, Box, Container, Toolbar, Typography } from '@mui/material'
import type { ReactNode } from 'react'

type Props = {
  children: ReactNode
}

export function AppShell({ children }: Props) {
  return (
    <Box sx={{ minHeight: '100vh', bgcolor: 'background.default' }}>
      <AppBar position="sticky" elevation={0} color="transparent" sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Toolbar>
          <SecurityIcon sx={{ mr: 1.5, color: 'primary.main' }} />
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            Threat Alert Dashboard
          </Typography>
          <Typography variant="body2" color="text.secondary">
            RASP + ML
          </Typography>
        </Toolbar>
      </AppBar>
      <Container maxWidth="xl" sx={{ py: 3 }}>
        {children}
      </Container>
    </Box>
  )
}
