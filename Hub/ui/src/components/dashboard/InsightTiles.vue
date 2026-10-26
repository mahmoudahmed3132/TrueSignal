<script setup lang="ts">
import { computed, onMounted, onUnmounted, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useInsightsStore } from '../../stores/Insights/insights'
import type { InsightsTimeframe } from '../../stores/Insights/insights'
import { useFleetStore } from '../../stores/Fleet/fleet'
import { useEventsStore } from '../../stores/Events/events'
import { useAppStore } from '../../stores/System/app'
import BaseTimeFilter from '../ui/forms/BaseTimeFilter.vue'

const insightsStore = useInsightsStore()
const fleetStore = useFleetStore()
const eventsStore = useEventsStore()
const appStore = useAppStore()

const { projection, timeframe } = storeToRefs(insightsStore)

const tiles = computed(() => {
    const p = projection.value
    return [
        {
            label: 'Decoys touched',
            value: p ? `${p.decoysTouched} / ${p.decoysDeployed}` : '–',
            hint: p ? `${p.decoyTypesDeployed} decoy types deployed` : '',
            alert: (p?.decoysTouched || 0) > 0
        },
        {
            label: 'Attacker sources',
            value: p ? String(p.uniqueSources) : '–',
            hint: p ? `${p.events} interactions` : '',
            alert: (p?.uniqueSources || 0) > 0
        },
        {
            label: 'Critical interactions',
            value: p ? String(p.criticalEvents) : '–',
            hint: 'Logins and honeytoken use',
            alert: (p?.criticalEvents || 0) > 0
        },
        {
            label: 'Honeytokens used',
            value: p ? `${p.honeytokensUsed} / ${p.honeytokensTotal}` : '–',
            hint: 'All time',
            alert: (p?.honeytokensUsed || 0) > 0
        }
    ]
})

// New events arrive over the WebSocket in bursts; refresh once they settle.
let refreshTimer: ReturnType<typeof setTimeout> | null = null
const scheduleRefresh = () => {
    if (refreshTimer) clearTimeout(refreshTimer)
    refreshTimer = setTimeout(() => insightsStore.fetchInsights(), 1500)
}

watch(
    () => [fleetStore.selectedNode?.id, fleetStore.selectedSensor?.sensorId, appStore.viewingArchive],
    () => insightsStore.fetchInsights()
)
watch(() => eventsStore.events[0]?.id, scheduleRefresh)
watch(() => fleetStore.nodes.length, scheduleRefresh)

onMounted(() => insightsStore.fetchInsights())
onUnmounted(() => { if (refreshTimer) clearTimeout(refreshTimer) })
</script>

<template>
    <section aria-labelledby="coverage-heading" class="flex flex-col gap-3">
        <div class="flex flex-wrap items-center justify-between gap-3">
            <h2 id="coverage-heading" class="text-base font-medium text-text-h">Decoy coverage</h2>
            <BaseTimeFilter
                :model-value="timeframe"
                :options="['24H', '7D', '30D', 'All']"
                @update:model-value="insightsStore.setTimeframe($event as InsightsTimeframe)"
            />
        </div>
        <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
            <div v-for="t in tiles" :key="t.label"
                 class="bg-bg-surface border border-border-default rounded-lg shadow-sm p-4 sm:p-5 flex flex-col gap-1 min-w-0">
                <span class="text-sm text-text-m">{{ t.label }}</span>
                <span class="text-2xl font-mono leading-tight truncate"
                      :class="t.alert ? 'text-critical' : 'text-text-h'">{{ t.value }}</span>
                <span class="text-xs text-text-l truncate">{{ t.hint }}</span>
            </div>
        </div>
    </section>
</template>
