import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '../../api/client'
import { useAppStore } from '../System/app'
import { useFleetStore } from '../Fleet/fleet'

export interface DecoyTypeStat {
  sensorId: string
  events: number
  uniqueSources: number
  deployed: number
  touched: number
}

export interface InsightsProjection {
  timeframe: string
  events: number
  criticalEvents: number
  uniqueSources: number
  decoysDeployed: number
  decoysTouched: number
  decoyTypesDeployed: number
  honeytokensTotal: number
  honeytokensUsed: number
  techniquesObserved: number
  byType: DecoyTypeStat[]
}

export type InsightsTimeframe = '24H' | '7D' | '30D' | 'All'

export const useInsightsStore = defineStore('insights', () => {
  const projection = ref<InsightsProjection | null>(null)
  const timeframe = ref<InsightsTimeframe>('All')
  const isFetching = ref(false)
  let abortController: AbortController | null = null

  const fetchInsights = async (): Promise<void> => {
    const appStore = useAppStore()
    const fleetStore = useFleetStore()
    if (abortController) abortController.abort()
    abortController = new AbortController()

    try {
      isFetching.value = true
      const params = new URLSearchParams({
        timeframe: timeframe.value === 'All' ? 'alltime' : timeframe.value,
        archived: appStore.viewingArchive ? 'true' : 'false'
      })
      if (fleetStore.selectedNode?.id) params.append('nodeId', fleetStore.selectedNode.id)
      if (fleetStore.selectedSensor?.sensorId) params.append('sensorId', fleetStore.selectedSensor.sensorId)

      const res = await api.get(`/api/v2/insights?${params.toString()}`, { signal: abortController.signal })
      projection.value = (await res.json()) as InsightsProjection
    } catch (e: any) {
      if (e.name !== 'AbortError') console.error('Insights fetch failed:', e)
    } finally {
      isFetching.value = false
    }
  }

  const setTimeframe = (tf: InsightsTimeframe): void => {
    timeframe.value = tf
    fetchInsights()
  }

  return { projection, timeframe, isFetching, fetchInsights, setTimeframe }
})
