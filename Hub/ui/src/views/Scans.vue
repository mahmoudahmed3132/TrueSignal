<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch, nextTick } from 'vue'
import { storeToRefs } from 'pinia'
import Chart from 'chart.js/auto'
import { useFleetStore } from '../stores/Fleet/fleet'
import { fetchAllEvents, formatDateTime } from '../utils/allEvents'
import type { EventPayload } from '../stores/Events/events'
import { getComputedRgb, injectAlpha } from '../utils/theme'
import { baseTooltipConfig, applyChartTheme } from '../utils/chartConfig'
import PageHeader from '../components/ui/layout/PageHeader.vue'
import BaseWidget from '../components/ui/layout/BaseWidget.vue'

// Scans the decoys detected: port scans (Network Scan Detector) and ICMP
// probes (ICMP Canary). Detection only: TrueSignal never scans.
const PORT_SCAN = 'network_scan_detected'
const ICMP = 'icmp_scan_received'

const fleetStore = useFleetStore()
const { nodes } = storeToRefs(fleetStore)
const nodeAlias = (id: string) => nodes.value.find(n => n.id === id)?.alias || id

const events = ref<EventPayload[]>([])
const loading = ref(true)
const loadError = ref('')
const kind = ref<'all' | 'port' | 'icmp'>('all')
const search = ref('')

onMounted(async () => {
    try {
        events.value = await fetchAllEvents()
    } catch (e: any) {
        loadError.value = e?.message || 'Failed to load events'
    } finally {
        loading.value = false
    }
})

const scans = computed(() => events.value.filter(e => e.eventTrigger === PORT_SCAN || e.eventTrigger === ICMP))
const portScans = computed(() => scans.value.filter(e => e.eventTrigger === PORT_SCAN))
const scanSources = computed(() => new Set(scans.value.map(e => e.source)))

// A source that scanned and also interacted with a decoy service: the
// recon-then-access pattern worth triaging first.
const scannedThenTouched = computed(() => {
    const touched = new Set(events.value
        .filter(e => e.eventTrigger !== PORT_SCAN && e.eventTrigger !== ICMP && !e.eventTrigger.startsWith('sensor_'))
        .map(e => e.source))
    return new Set([...scanSources.value].filter(s => touched.has(s)))
})

const ports = (e: EventPayload): string[] => {
    const p = e.details?.ports_hit
    return Array.isArray(p) ? p.map(String).filter(x => /^\d+$/.test(x)) : []
}

const topPorts = computed(() => {
    const counts = new Map<string, number>()
    for (const e of portScans.value) for (const p of new Set(ports(e))) counts.set(p, (counts.get(p) || 0) + 1)
    return [...counts.entries()].sort((a, b) => (b[1] - a[1]) || (Number(a[0]) - Number(b[0]))).slice(0, 10)
})

const rows = computed(() => {
    const q = search.value.trim().toLowerCase()
    return scans.value.filter(e => {
        if (kind.value === 'port' && e.eventTrigger !== PORT_SCAN) return false
        if (kind.value === 'icmp' && e.eventTrigger !== ICMP) return false
        if (!q) return true
        return [e.source, nodeAlias(e.nodeId), JSON.stringify(e.details || {})].join(' ').toLowerCase().includes(q)
    })
})

const tiles = computed(() => [
    { label: 'Port scans', value: portScans.value.length },
    { label: 'ICMP probes', value: scans.value.length - portScans.value.length },
    { label: 'Scanning sources', value: scanSources.value.size },
    { label: 'Scanned, then touched a decoy', value: scannedThenTouched.value.size, alert: true }
])

// --- Most probed ports chart (single series, one axis) ---
const chartCanvas = ref<HTMLCanvasElement | null>(null)
let chart: any = null
let themeObserver: MutationObserver | null = null

const paint = () => {
    if (!chart) return
    const bar = getComputedRgb('--primary-main')
    chart.data.datasets[0].backgroundColor = bar
    chart.data.datasets[0].hoverBackgroundColor = injectAlpha(bar, 0.8)
    chart.options.scales.x.ticks.color = getComputedRgb('--text-m')
    chart.options.scales.y.ticks.color = getComputedRgb('--text-m')
    chart.options.scales.x.grid.color = injectAlpha(getComputedRgb('--border-default'), 0.6)
    applyChartTheme(chart)
}

const updateChart = () => {
    if (!chart) return
    chart.data.labels = topPorts.value.map(([p]) => p)
    chart.data.datasets[0].data = topPorts.value.map(([, n]) => n)
    chart.update()
}

onMounted(async () => {
    await nextTick()
    if (!chartCanvas.value) return
    chart = new Chart(chartCanvas.value, {
        type: 'bar',
        data: { labels: [], datasets: [{ data: [], borderRadius: 4, borderSkipped: 'start', barThickness: 14 }] },
        options: {
            indexAxis: 'y', responsive: true, maintainAspectRatio: false, animation: false,
            scales: {
                x: { beginAtZero: true, border: { display: false }, grid: { drawTicks: false }, ticks: { precision: 0, maxTicksLimit: 5, padding: 6, font: { size: 10, family: "'IBM Plex Mono', ui-monospace, monospace" } } },
                y: { border: { display: false }, grid: { display: false }, ticks: { font: { size: 11, family: "'IBM Plex Mono', ui-monospace, monospace" } } }
            },
            plugins: {
                legend: { display: false },
                ...({ neonGlow: false } as any),
                tooltip: { ...(baseTooltipConfig as any), callbacks: { title: (i: any[]) => `Port ${i[0].label}`, label: (c: any) => `${c.parsed.x} scans` } }
            }
        }
    })
    paint()
    updateChart()
    themeObserver = new MutationObserver(m => { if (m.some(x => x.attributeName === 'class')) setTimeout(paint, 50) })
    themeObserver.observe(document.documentElement, { attributes: true })
})
watch(topPorts, updateChart)
onUnmounted(() => { if (chart) chart.destroy(); if (themeObserver) themeObserver.disconnect() })
</script>

<template>
    <div class="min-h-full flex flex-col gap-4 sm:gap-6 max-w-[1600px] w-full mx-auto px-2 sm:px-4 lg:px-6 py-4 sm:py-6">
        <PageHeader
            title="Detected Scans"
            description="Port scans and ICMP probes that hit the decoys, from all stored events (active and archived). TrueSignal only detects scans; it never scans your network."
        />

        <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
            <div v-for="t in tiles" :key="t.label" class="bg-bg-surface border border-border-default rounded-lg shadow-sm p-4 sm:p-5 flex flex-col gap-1">
                <span class="text-sm text-text-m">{{ t.label }}</span>
                <span class="text-2xl font-mono leading-tight" :class="t.alert && t.value > 0 ? 'text-critical' : 'text-text-h'">{{ loading ? '–' : t.value }}</span>
            </div>
        </div>

        <div class="flex flex-col gap-4 sm:gap-6">
            <div class="w-full max-w-[720px] h-[340px]">
                <BaseWidget>
                    <template #header>
                        <div class="shrink-0">
                            <h3 class="text-base font-medium text-text-h">Most Probed Ports</h3>
                            <p class="text-sm text-text-m mt-1">Port scans that hit each port (top 10)</p>
                        </div>
                    </template>
                    <div class="flex-1 relative mt-3 mb-4 min-h-0 w-full">
                        <div v-if="!loading && topPorts.length === 0" class="absolute inset-0 flex items-center justify-center text-base text-text-m z-10">No port scans recorded</div>
                        <canvas ref="chartCanvas" role="img" :aria-label="`Most probed ports: ${topPorts.map(([p, n]) => `${p} ${n}`).join(', ')}`"></canvas>
                    </div>
                </BaseWidget>
            </div>

            <div class="w-full bg-bg-surface border border-border-default rounded-lg shadow-sm overflow-hidden flex flex-col">
                <div class="px-5 py-3 border-b border-border-default flex flex-wrap items-center gap-3">
                    <div class="flex bg-secondary-main p-1 rounded-md border border-secondary-border text-sm" role="group" aria-label="Scan type">
                        <button v-for="k in ([['all', 'All'], ['port', 'Port scans'], ['icmp', 'ICMP']] as const)" :key="k[0]" type="button"
                                :aria-pressed="kind === k[0]" @click="kind = k[0]"
                                class="px-3 py-1 rounded-sm transition-colors outline-none"
                                :class="kind === k[0] ? 'bg-primary-selected text-primary-text' : 'text-secondary-text hover:bg-secondary-hover'">{{ k[1] }}</button>
                    </div>
                    <input v-model="search" type="search" placeholder="Search source, node, port, tool" aria-label="Search scans"
                           class="flex-[1_1_200px] max-w-xs ml-auto px-3 py-1.5 text-sm bg-input-bg border border-input-border rounded-md outline-none focus:border-primary-main focus:ring-1 focus:ring-focus-ring text-text-h" />
                </div>
                <div class="overflow-auto max-h-[600px]">
                    <table class="min-w-full text-left text-sm">
                        <thead class="text-text-m bg-bg-inset sticky top-0">
                            <tr>
                                <th class="px-5 py-2.5 font-medium">Time</th>
                                <th class="px-4 py-2.5 font-medium">Source</th>
                                <th class="px-4 py-2.5 font-medium">Type</th>
                                <th class="px-4 py-2.5 font-medium">Ports</th>
                                <th class="px-4 py-2.5 font-medium">Tool guess</th>
                                <th class="px-5 py-2.5 font-medium text-right">Node</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr v-if="loading"><td colspan="6" class="px-5 py-8 text-center text-text-m">Loading…</td></tr>
                            <tr v-else-if="loadError"><td colspan="6" class="px-5 py-8 text-center text-danger-text">{{ loadError }}</td></tr>
                            <tr v-else-if="rows.length === 0"><td colspan="6" class="px-5 py-8 text-center text-text-m">{{ scans.length ? 'No scans match the filters.' : 'No scans detected.' }}</td></tr>
                            <tr v-for="e in rows" :key="e.id" class="border-t border-border-default">
                                <td class="px-5 py-2.5 font-mono text-text-m whitespace-nowrap">{{ formatDateTime(e.timestamp) }}</td>
                                <td class="px-4 py-2.5 font-mono text-text-h whitespace-nowrap">
                                    {{ e.source }}
                                    <span v-if="scannedThenTouched.has(e.source)" class="ml-1.5 px-1.5 py-px rounded text-xs font-sans border text-critical border-critical/40" title="This source also interacted with a decoy service">touched a decoy</span>
                                </td>
                                <td class="px-4 py-2.5 text-text-h whitespace-nowrap">{{ e.eventTrigger === PORT_SCAN ? (e.details?.scan_type || 'Port scan') : `ICMP ${e.details?.icmp_type || 'probe'}` }}</td>
                                <td class="px-4 py-2.5 font-mono text-text-m whitespace-nowrap">
                                    <template v-if="e.eventTrigger === PORT_SCAN">
                                        <span class="text-text-h">{{ e.details?.count ?? ports(e).length }} ports</span>
                                        <span v-if="ports(e).length" class="ml-1" :title="ports(e).join(', ')">· {{ ports(e).slice(0, 6).join(', ') }}{{ ports(e).length > 6 ? '…' : '' }}</span>
                                    </template>
                                    <span v-else>–</span>
                                </td>
                                <td class="px-4 py-2.5 text-text-m whitespace-nowrap">{{ e.details?.tool_guess || '–' }}</td>
                                <td class="px-5 py-2.5 font-mono text-right text-text-h whitespace-nowrap">{{ nodeAlias(e.nodeId) }}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</template>
