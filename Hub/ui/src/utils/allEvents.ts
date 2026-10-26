import { api } from '../api/client'
import type { EventPayload } from '../stores/Events/events'

// Active and archived events together, newest first. Pages that analyse
// history (scans, honeytoken use) must not depend on the archive toggle.
export const fetchAllEvents = async (): Promise<EventPayload[]> => {
  const [active, archived] = await Promise.all(
    ['false', 'true'].map(a => api.get(`/api/v2/events?archived=${a}`).then(r => r.json() as Promise<EventPayload[]>))
  )
  return [...active, ...archived].sort((a, b) => (a.timestamp < b.timestamp ? 1 : a.timestamp > b.timestamp ? -1 : 0))
}

export const formatDateTime = (ts: string): string => {
  if (!ts) return '–'
  return new Intl.DateTimeFormat('default', {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false
  }).format(new Date(ts))
}
