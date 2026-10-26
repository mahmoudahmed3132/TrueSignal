import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { api } from '../../api/client'

// Activity profile of one event source across all events (GET /api/v2/sources).
export interface SourceProfile {
  source: string
  events: number
  decoys: number
  firstSeen: string
  lastSeen: string
  isIp: boolean
  internal: boolean
  whitelisted: boolean
  knownScanner: boolean
}

// Triage labels an analyst filters on. Derived from the profile, so they
// reflect all stored events and the current source lists.
export type SourceLabel = 'repeat' | 'single' | 'multiDecoy' | 'internal' | 'external' | 'whitelisted' | 'scanner'

export const SOURCE_LABELS: { id: SourceLabel; text: string; hint: string }[] = [
  { id: 'multiDecoy', text: 'Multi-decoy', hint: 'Touched two or more decoys' },
  { id: 'repeat', text: 'Repeat source', hint: 'Two or more events' },
  { id: 'single', text: 'Single touch', hint: 'Exactly one event' },
  { id: 'internal', text: 'Internal', hint: 'Private, loopback or link-local address' },
  { id: 'external', text: 'External', hint: 'Public address' },
  { id: 'whitelisted', text: 'Whitelisted', hint: 'On the whitelist now' },
  { id: 'scanner', text: 'Known scanner', hint: 'On the known-scanner list now' }
]

export const labelsOf = (p: SourceProfile | undefined): Set<SourceLabel> => {
  const out = new Set<SourceLabel>()
  if (!p) return out
  out.add(p.events > 1 ? 'repeat' : 'single')
  if (p.decoys > 1) out.add('multiDecoy')
  if (p.isIp) out.add(p.internal ? 'internal' : 'external')
  if (p.whitelisted) out.add('whitelisted')
  if (p.knownScanner) out.add('scanner')
  return out
}

export const useSourcesStore = defineStore('sources', () => {
  const profiles = ref<SourceProfile[]>([])
  const bySource = computed(() => new Map(profiles.value.map(p => [p.source, p])))
  let timer: ReturnType<typeof setTimeout> | null = null

  const fetchSources = async (): Promise<void> => {
    try {
      const res = await api.get('/api/v2/sources')
      profiles.value = ((await res.json()).sources || []) as SourceProfile[]
    } catch (e) {
      console.error('Sources fetch failed:', e)
    }
  }

  // Events arrive in bursts over the WebSocket; refresh once they settle.
  const scheduleRefresh = (): void => {
    if (timer) clearTimeout(timer)
    timer = setTimeout(fetchSources, 1500)
  }

  return { profiles, bySource, fetchSources, scheduleRefresh }
})
