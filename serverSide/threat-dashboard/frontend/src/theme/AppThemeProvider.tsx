import { CssBaseline, ThemeProvider, createTheme } from '@mui/material'
import useMediaQuery from '@mui/material/useMediaQuery'
import { useMemo, type ReactNode } from 'react'

type Props = {
  children: ReactNode
}

export function AppThemeProvider({ children }: Props) {
  const prefersDark = useMediaQuery('(prefers-color-scheme: dark)')

  const theme = useMemo(
    () =>
      createTheme({
        palette: {
          mode: prefersDark ? 'dark' : 'light',
          primary: {
            main: prefersDark ? '#90caf9' : '#1565c0',
          },
          secondary: {
            main: prefersDark ? '#f48fb1' : '#c62828',
          },
          background: {
            default: prefersDark ? '#0f1419' : '#f5f7fa',
            paper: prefersDark ? '#1a1f26' : '#ffffff',
          },
        },
        typography: {
          fontFamily: '"IBM Plex Sans", "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
          h4: { fontWeight: 600 },
          h6: { fontWeight: 600 },
        },
        shape: { borderRadius: 10 },
      }),
    [prefersDark],
  )

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      {children}
    </ThemeProvider>
  )
}
