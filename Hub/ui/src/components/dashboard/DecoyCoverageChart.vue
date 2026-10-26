<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch, nextTick } from 'vue'
import { storeToRefs } from 'pinia'
import Chart from 'chart.js/auto'
import { useInsightsStore } from '../../stores/Insights/insights'
import { getComputedRgb } from '../../utils/theme'
import { baseTooltipConfig, applyChartTheme } from '../../utils/chartConfig'
import BaseWidget from '../ui/layout/BaseWidget.vue'
import BaseLegend from '../ui/feedback/BaseLegend.vue'

// Deployed decoys split into touched (any attacker interaction in the
// timeframe) and untouched.
const insightsStore = useInsightsStore()
const { projection } = storeToRefs(insightsStore)

const chartCanvas = ref<HTMLCanvasElement | null>(null)
let chartInstance: any = null
let themeObserver: MutationObserver | null = null

const touched = computed(() => projection.value?.decoysTouched || 0)
const untouched = computed(() => Math.max((projection.value?.decoysDeployed || 0) - touched.value, 0))
const deployed = computed(() => projection.value?.decoysDeployed || 0)

const applyColors = () => {
    if (!chartInstance) return
    chartInstance.data.datasets[0].backgroundColor = [getComputedRgb('--sev-critical'), getComputedRgb('--sev-info')]
    chartInstance.data.datasets[0].borderColor = getComputedRgb('--bg-surface')
    applyChartTheme(chartInstance)
}

const updateData = () => {
    if (!chartInstance) return
    chartInstance.data.datasets[0].data = [touched.value, untouched.value]
    chartInstance.update()
}

onMounted(async () => {
    await nextTick()
    if (!chartCanvas.value) return
    chartInstance = new Chart(chartCanvas.value, {
        type: 'doughnut',
        data: { labels: ['Touched', 'Untouched'], datasets: [{ data: [0, 0], borderWidth: 2, borderRadius: 2 }] },
        options: {
            cutout: '78%',
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            plugins: {
                legend: { display: false },
                tooltip: { ...(baseTooltipConfig as any) }
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

watch([touched, untouched], updateData)

onUnmounted(() => {
    if (chartInstance) chartInstance.destroy()
    if (themeObserver) themeObserver.disconnect()
})

const legendItems = computed(() => [
    { label: `Touched ${touched.value}`, colorClass: 'bg-critical' },
    { label: `Untouched ${untouched.value}`, colorClass: 'bg-info' }
])
</script>

<template>
    <BaseWidget>
        <template #header>
            <div class="shrink-0">
                <h3 class="text-base font-medium text-text-h">Decoy Coverage</h3>
                <p class="text-sm text-text-m mt-1">Deployed decoys an attacker interacted with</p>
            </div>
        </template>

        <div class="flex-1 relative mt-2 min-h-0 w-full">
            <canvas ref="chartCanvas" role="img" :aria-label="`${touched} of ${deployed} decoys touched`"></canvas>
            <div class="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span class="text-3xl font-mono leading-none" :class="touched > 0 ? 'text-critical' : 'text-success-main'">
                    {{ deployed > 0 ? Math.round((touched / deployed) * 100) : 0 }}%
                </span>
                <span class="text-sm text-text-m mt-1 leading-none">of {{ deployed }} touched</span>
            </div>
        </div>

        <template #footer>
            <BaseLegend :items="legendItems" />
        </template>
    </BaseWidget>
</template>
