<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch, nextTick } from 'vue'
import { storeToRefs } from 'pinia'
import Chart from 'chart.js/auto'
import { useInsightsStore } from '../../stores/Insights/insights'
import type { DecoyTypeStat } from '../../stores/Insights/insights'
import { useFleetStore } from '../../stores/Fleet/fleet'
import { getComputedRgb, injectAlpha } from '../../utils/theme'
import { baseTooltipConfig, applyChartTheme } from '../../utils/chartConfig'
import { decoyName, shortDecoyName } from '../../utils/decoyNames'
import BaseWidget from '../ui/layout/BaseWidget.vue'

// One measure per chart (events, or unique attacker sources), one bar per
// decoy type, so both stay on a single honest axis.
const props = defineProps<{
    metric: 'events' | 'uniqueSources'
    title: string
    subtitle: string
}>()

const insightsStore = useInsightsStore()
const fleetStore = useFleetStore()
const { projection } = storeToRefs(insightsStore)
const { manifests } = storeToRefs(fleetStore)

const chartCanvas = ref<HTMLCanvasElement | null>(null)
let chartInstance: any = null
let themeObserver: MutationObserver | null = null

const rows = computed<DecoyTypeStat[]>(() => {
    const list = [...(projection.value?.byType || [])]
    list.sort((a, b) => (b[props.metric] - a[props.metric]) || a.sensorId.localeCompare(b.sensorId))
    return list
})
// Header total: an attacker who hit several decoy types is one source, so
// sources come from the projection's overall count, not the per-type sum.
const total = computed(() => props.metric === 'uniqueSources'
    ? (projection.value?.uniqueSources || 0)
    : (projection.value?.events || 0))
const isEmpty = computed(() => rows.value.length === 0)

const applyColors = () => {
    if (!chartInstance) return
    const bar = getComputedRgb('--primary-main')
    const ds = chartInstance.data.datasets[0]
    ds.backgroundColor = bar
    ds.hoverBackgroundColor = injectAlpha(bar, 0.8)
    const tick = getComputedRgb('--text-m')
    const grid = injectAlpha(getComputedRgb('--border-default'), 0.6)
    chartInstance.options.scales.x.ticks.color = tick
    chartInstance.options.scales.y.ticks.color = tick
    chartInstance.options.scales.x.grid.color = grid
    applyChartTheme(chartInstance)
}

const updateData = () => {
    if (!chartInstance) return
    chartInstance.data.labels = rows.value.map(r => shortDecoyName(r.sensorId, manifests.value))
    // null, not 0: a zero would still draw a rounded sliver at the baseline.
    chartInstance.data.datasets[0].data = rows.value.map(r => r[props.metric] || null)
    chartInstance.update()
}

onMounted(async () => {
    await nextTick()
    if (!chartCanvas.value) return
    chartInstance = new Chart(chartCanvas.value, {
        type: 'bar',
        data: { labels: [], datasets: [{ data: [], borderRadius: 4, borderSkipped: 'start', barThickness: 14, maxBarThickness: 14 }] },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            scales: {
                x: {
                    beginAtZero: true,
                    border: { display: false },
                    grid: { drawTicks: false },
                    ticks: { precision: 0, maxTicksLimit: 5, padding: 6, font: { size: 10, family: "'IBM Plex Mono', ui-monospace, monospace" } }
                },
                y: {
                    border: { display: false },
                    grid: { display: false },
                    ticks: { autoSkip: false, font: { size: 11 } }
                }
            },
            plugins: {
                legend: { display: false },
                // The dashboard's doughnut glow would redraw empty bars.
                ...({ neonGlow: false } as any),
                tooltip: {
                    ...(baseTooltipConfig as any),
                    callbacks: {
                        title: (items: any[]) => decoyName(rows.value[items[0].dataIndex].sensorId, manifests.value),
                        label: (ctx: any) => {
                            const unit = props.metric === 'events' ? 'interactions' : 'attacker sources'
                            return `${ctx.parsed.x ?? 0} ${unit}`
                        },
                        afterLabel: (ctx: any) => {
                            const r = rows.value[ctx.dataIndex]
                            return r.deployed > 0 ? `${r.touched} of ${r.deployed} deployed touched` : 'No longer deployed'
                        }
                    }
                }
            }
        }
    })
    applyColors()
    updateData()

    themeObserver = new MutationObserver((mutations) => {
        if (mutations.some(m => m.attributeName === 'class')) setTimeout(applyColors, 50)
    })
    themeObserver.observe(document.documentElement, { attributes: true })
})

watch([rows, manifests], updateData)

onUnmounted(() => {
    if (chartInstance) chartInstance.destroy()
    if (themeObserver) themeObserver.disconnect()
})
</script>

<template>
    <BaseWidget>
        <template #header>
            <div class="shrink-0">
                <h3 class="text-base font-medium text-text-h">{{ title }}</h3>
                <p class="text-sm text-text-m mt-1">
                    <span class="font-mono" :class="total > 0 ? 'text-critical' : 'text-success-main'">{{ total }}</span>
                    {{ subtitle }}
                </p>
            </div>
        </template>

        <div class="flex-1 relative mt-3 mb-4 min-h-0 w-full">
            <div v-if="isEmpty" class="absolute inset-0 flex items-center justify-center text-base text-text-m z-10">
                No decoys deployed yet
            </div>
            <canvas ref="chartCanvas" role="img" :aria-label="`${title}: ${rows.map(r => `${decoyName(r.sensorId, manifests)} ${r[metric]}`).join(', ')}`"></canvas>
        </div>
    </BaseWidget>
</template>
