import { defineStore } from 'pinia'
import { ref, readonly } from 'vue'
import { api } from '../../api/client'

export type SiemProtocol = 'tcp' | 'udp' | 'tls' | 'elastic' | 'logscale' | ''

// Represents the exact JSON schema returned by GET /api/v2/config
export interface ConfigApiResponse {
  hubEndpoint: string
  registryUrl: string
  autoArchiveDays: number
  autoPurgeDays: number
  autoPurgeHeartbeatsDays: number
  updateCheckIntervalHours: number
  webhookType: string
  webhookUrl: string
  webhookEvents: string[]
  siemAddress: string
  siemProtocol: SiemProtocol
  siemFormat: 'rfc5424' | 'ecs'
  siemTokenSet: boolean
  whitelistedSources: string
}

// Represents the internal reactive state used by Vue components
export interface ConfigState {
  isLoaded: boolean
  hubEndpoint: string
  registryUrl: string
  autoArchiveDays: number
  autoPurgeDays: number
  autoPurgeHeartbeatsDays: number
  updateCheckIntervalHours: number
  webhookType: string
  webhookUrl: string
  webhookEvents: string[]
  siemAddress: string
  siemProtocol: SiemProtocol
  siemFormat: 'rfc5424' | 'ecs'
  siemTokenSet: boolean
  whitelistedSources: string
}

export const useConfigStore = defineStore('config', () => {
  const state = ref<ConfigState>({
    isLoaded: false,
    hubEndpoint: '',
    registryUrl: '',
    autoArchiveDays: 0,
    autoPurgeDays: 0,
    autoPurgeHeartbeatsDays: 0,
    updateCheckIntervalHours: 24,
    webhookType: 'ntfy',
    webhookUrl: '',
    webhookEvents: [],
    siemAddress: '',
    siemProtocol: 'tcp',
    siemFormat: 'rfc5424',
    siemTokenSet: false,
    whitelistedSources: ''
  })

  const fetchConfig = async (): Promise<void> => {
    try {
      const res = await api.get('/api/v2/config')
      const data = (await res.json()) as ConfigApiResponse
      
      state.value.hubEndpoint = data.hubEndpoint || window.location.origin
      state.value.registryUrl = data.registryUrl || ''
      state.value.autoArchiveDays = data.autoArchiveDays != null ? data.autoArchiveDays : 0
      state.value.autoPurgeDays = data.autoPurgeDays != null ? data.autoPurgeDays : 0
      state.value.autoPurgeHeartbeatsDays = data.autoPurgeHeartbeatsDays != null ? data.autoPurgeHeartbeatsDays : 0
      state.value.updateCheckIntervalHours = data.updateCheckIntervalHours != null ? data.updateCheckIntervalHours : 24
      state.value.webhookType = data.webhookType || 'ntfy'
      state.value.webhookUrl = data.webhookUrl || ''
      
      if (data.webhookEvents && data.webhookEvents.length > 0) {
        state.value.webhookEvents = data.webhookEvents
      } else {
        state.value.webhookEvents = ['critical', 'high', 'medium', 'low', 'info']
      }
      state.value.siemAddress = data.siemAddress || ''
      state.value.siemProtocol = data.siemProtocol || 'tcp'
      state.value.siemFormat = data.siemFormat || 'rfc5424'
      state.value.siemTokenSet = !!data.siemTokenSet
      state.value.whitelistedSources = data.whitelistedSources || ''
      
      state.value.isLoaded = true
    } catch (error) {
      console.error('Failed to load config', error)
    }
  }

  // siemToken is write-only: it is sent but never kept in state; only
  // siemTokenSet reflects whether one is stored. Omit it to keep the stored
  // token, send '' to clear it.
  type ConfigUpdate = Partial<Omit<ConfigState, 'isLoaded' | 'siemTokenSet'>> & { siemToken?: string }

  const patchConfig = async (updates: ConfigUpdate): Promise<boolean> => {
    try {
      await api.patch('/api/v2/config', updates)

      const { siemToken, ...rest } = updates
      Object.assign(state.value, rest)
      if (siemToken !== undefined) {
        state.value.siemTokenSet = siemToken !== ''
      }
      return true
    } catch (error) {
      console.error('Config patch network error:', error)
      return false
    }
  }

  return {
    config: readonly(state), 
    fetchConfig,
    patchConfig
  }
})