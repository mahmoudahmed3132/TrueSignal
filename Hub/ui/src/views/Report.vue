<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, nextTick, watch } from 'vue'
import { storeToRefs } from 'pinia'
import Chart from 'chart.js/auto'
import { api } from '../api/client'
import { useFleetStore } from '../stores/Fleet/fleet'
import { useConfigStore } from '../stores/Config/config'
import { useAppStore } from '../stores/System/app'
import { decoyName, shortDecoyName } from '../utils/decoyNames'
import { formatDateTime } from '../utils/allEvents'
import { getComputedRgb } from '../utils/theme'
import { baseTooltipConfig, applyChartTheme } from '../utils/chartConfig'
import BaseButton from '../components/ui/forms/BaseButton.vue'

// Evidence report for a period: what the decoys saw, what TrueSignal
// detected, and how the control is configured. Printed to PDF from the
// browser; the JSON download is the machine-readable copy.
interface Report {
    from: string; to: string; generatedAt: string
    summary: { events: number; criticalEvents: number; uniqueSources: number; decoysDeployed: number; decoysTouched: number; decoyTypesDeployed: number; honeytokensTotal: number; honeytokensUsed: number; techniquesObserved: number; byType: { sensorId: string; events: number; uniqueSources: number; deployed: number; touched: number }[] }
    severity: { critical: number; high: number; medium: number; low: number; info: number }
    daily: { date: string; events: number; critical: number }[]
    topSources: { source: string; events: number; critical: number; decoys: number; firstSeen: string; lastSeen: string; asset: { name: string; criticality: string } | null }[]
    sourcesTotal: number
    assets: { name: string; criticality: string; sources: number; events: number }[]
    techniques: { id: string; name: string; tactics: string[]; primaryEvents: number; secondaryEvents: number; sources: number }[]
    honeytokenUses: { timestamp: string; username: string; source: string; nodeId: string; sensorId: string }[]
    archivedEvents: number
}

const fleetStore = useFleetStore()
const configStore = useConfigStore()
const appStore = useAppStore()
const { nodes, manifests } = storeToRefs(fleetStore)
const nodeAlias = (id: string) => nodes.value.find(n => n.id === id)?.alias || id

const preset = ref<'7' | '30' | '90' | 'custom'>('30')
const today = () => new Date().toISOString().slice(0, 10)
const daysAgo = (n: number) => new Date(Date.now() - n * 86400000).toISOString().slice(0, 10)
const customFrom = ref(daysAgo(30))
const customTo = ref(today())

const report = ref<Report | null>(null)
const mfa = ref<{ enabled: boolean; required: boolean } | null>(null)
const loading = ref(false)
const loadError = ref('')

const range = computed(() => {
    if (preset.value === 'custom') {
        // The end date is inclusive in the form, exclusive in the API.
        const to = new Date(customTo.value + 'T00:00:00Z')
        to.setUTCDate(to.getUTCDate() + 1)
        return { from: customFrom.value, to: to.toISOString().slice(0, 10) }
    }
    const now = new Date()
    return { from: new Date(now.getTime() - Number(preset.value) * 86400000).toISOString(), to: now.toISOString() }
})

const generate = async () => {
    loading.value = true
    loadError.value = ''
    try {
        const q = new URLSearchParams(range.value)
        const [r, m] = await Promise.all([
            api.get(`/api/v2/report?${q}`).then(x => x.json()),
            api.get('/api/v2/auth/mfa').then(x => x.json()).catch(() => null)
        ])
        report.value = r as Report
        mfa.value = m ? { enabled: !!m.enabled, required: !!m.required } : null
        await nextTick()
        drawChart()
    } catch (e: any) {
        loadError.value = e?.message || 'Failed to generate the report'
    } finally {
        loading.value = false
    }
}
onMounted(generate)
watch(preset, p => { if (p !== 'custom') generate() })

const sev = computed(() => report.value?.severity)
const sevRows = computed(() => sev.value ? (['critical', 'high', 'medium', 'low', 'info'] as const).map(k => ({ k, n: sev.value![k] })) : [])
// Per-asset totals over all sources in range (one CIDR asset may cover
// several attacking addresses), not the 25-row top-sources table.
const assetActivity = computed(() => report.value?.assets || [])

interface Kpi { l: string; v: number | string; a?: boolean }
const kpis = computed<Kpi[]>(() => {
    const r = report.value
    if (!r) return []
    return [
        { l: 'Interactions', v: r.summary.events },
        { l: 'Critical', v: r.summary.criticalEvents, a: true },
        { l: 'Attacker sources', v: r.summary.uniqueSources },
        { l: 'Decoys touched', v: `${r.summary.decoysTouched} / ${r.summary.decoysDeployed}` },
        { l: 'ATT&CK techniques', v: r.summary.techniquesObserved },
        { l: 'Honeytoken uses', v: r.honeytokenUses.length, a: true },
        { l: 'Assets involved', v: assetActivity.value.length, a: true },
        { l: 'Archived (not counted)', v: r.archivedEvents }
    ]
})

const findings = computed(() => {
    const r = report.value
    if (!r) return []
    const s = r.summary
    const out: string[] = []
    if (s.events === 0) {
        out.push(`No attacker interaction with the ${s.decoysDeployed} deployed decoys was recorded in this period.`)
    } else {
        out.push(`${s.events} interactions from ${s.uniqueSources} source${s.uniqueSources === 1 ? '' : 's'} touched ${s.decoysTouched} of ${s.decoysDeployed} deployed decoys; ${s.criticalEvents} were critical (logins or honeytoken use).`)
    }
    const assets = assetActivity.value
    if (assets.length) out.push(`${assets.length} inventoried asset${assets.length === 1 ? ' was' : 's were'} the source of decoy activity: ${assets.map(a => `${a.name} (${a.criticality}; ${a.events} event${a.events === 1 ? '' : 's'} from ${a.sources} address${a.sources === 1 ? '' : 'es'})`).join(', ')}. Treat these hosts as likely compromised.`)
    if (r.honeytokenUses.length) out.push(`Planted credentials were used ${r.honeytokenUses.length} time${r.honeytokenUses.length === 1 ? '' : 's'}: an attacker read a lure and tried its credential.`)
    if (s.techniquesObserved) out.push(`${s.techniquesObserved} MITRE ATT&CK technique${s.techniquesObserved === 1 ? ' was' : 's were'} observed.`)
    if (r.archivedEvents) out.push(`${r.archivedEvents} further events were archived (whitelisted sources, known scanners or analyst triage) and are not counted above.`)
    return out
})

// --- daily activity chart (single series, one axis) ---
const chartCanvas = ref<HTMLCanvasElement | null>(null)
let chart: any = null
const drawChart = () => {
    if (!chartCanvas.value || !report.value) return
    if (chart) chart.destroy()
    const color = getComputedRgb('--primary-main')
    chart = new Chart(chartCanvas.value, {
        type: 'bar',
        data: { labels: report.value.daily.map(d => d.date.slice(5)), datasets: [{ data: report.value.daily.map(d => d.events), backgroundColor: color, borderRadius: 3, maxBarThickness: 18 }] },
        options: {
            responsive: true, maintainAspectRatio: false, animation: false,
            plugins: { legend: { display: false }, ...({ neonGlow: false } as any), tooltip: { ...(baseTooltipConfig as any), callbacks: { label: (c: any) => `${c.parsed.y} interactions` } } },
            scales: {
                x: { grid: { display: false }, ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 12, font: { size: 10, family: "'IBM Plex Mono', ui-monospace, monospace" } } },
                y: { beginAtZero: true, border: { display: false }, ticks: { precision: 0, maxTicksLimit: 5, font: { size: 10 } } }
            }
        }
    })
    applyChartTheme(chart)
}
onUnmounted(() => { if (chart) chart.destroy() })

// Print in the light theme: dark-mode text on paper (backgrounds are not
// printed) would be unreadable. The theme is restored afterwards.
const print = async () => {
    const wasDark = document.documentElement.classList.contains('dark')
    if (wasDark) {
        document.documentElement.classList.remove('dark')
        await nextTick()
        drawChart()
        window.addEventListener('afterprint', () => { document.documentElement.classList.add('dark'); drawChart() }, { once: true })
    }
    window.print()
}

const downloadJson = () => {
    if (!report.value) return
    const payload = { report: report.value, nodes: nodes.value.map(n => ({ id: n.id, alias: n.alias, status: n.status, sensors: (n.installedSensors || []).map((s: any) => s.sensorId) })), posture: posture.value }
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }))
    const a = document.createElement('a')
    a.href = url
    a.download = `truesignal-report-${report.value.from.slice(0, 10)}_${report.value.to.slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(url)
}

const listSize = (s: string) => (s || '').split(',').map(x => x.trim()).filter(Boolean).length
const posture = computed(() => {
    const c = configStore.config
    return [
        { label: 'SIEM forwarding', value: c.siemAddress ? `Enabled (${c.siemProtocol}${['elastic', 'logscale'].includes(c.siemProtocol) ? '' : ', ' + c.siemFormat})` : 'Not configured', ok: !!c.siemAddress },
        { label: 'Alert notifications', value: c.webhookUrl && c.webhookType !== 'none' ? `${c.webhookType} (${(c.webhookEvents || []).join(', ')})` : 'Not configured', ok: !!c.webhookUrl && c.webhookType !== 'none' },
        { label: 'Alerting armed', value: appStore.isArmed ? 'Yes' : 'No (disarmed)', ok: !!appStore.isArmed },
        { label: 'Admin MFA', value: mfa.value ? (mfa.value.enabled ? (mfa.value.required ? 'Enabled and required' : 'Enabled') : 'Not enabled') : 'Unknown', ok: !!mfa.value?.enabled },
        { label: 'Event retention', value: `Auto-archive ${c.autoArchiveDays || 'off'}${c.autoArchiveDays ? ' days' : ''}, auto-purge ${c.autoPurgeDays || 'off'}${c.autoPurgeDays ? ' days' : ''}`, ok: true },
        { label: 'Whitelisted sources / known scanners', value: `${listSize(c.whitelistedSources)} / ${listSize(c.knownScanners)} entries`, ok: true },
        { label: 'Hub version', value: appStore.version ? `v${appStore.version}` : 'Unknown', ok: true }
    ]
})

const tacticNames: Record<string, string> = {
    TA0043: 'Reconnaissance', TA0001: 'Initial Access', TA0003: 'Persistence', TA0004: 'Privilege Escalation', TA0005: 'Defense Evasion',
    TA0006: 'Credential Access', TA0007: 'Discovery', TA0008: 'Lateral Movement', TA0009: 'Collection', TA0040: 'Impact'
}
const fmtDate = (iso: string) => iso ? new Intl.DateTimeFormat('default', { year: 'numeric', month: 'short', day: 'numeric' }).format(new Date(iso)) : ''
const periodLabel = computed(() => {
    if (!report.value) return ''
    const end = new Date(report.value.to)
    if (preset.value === 'custom') end.setUTCDate(end.getUTCDate() - 1)
    return `${fmtDate(report.value.from)} – ${fmtDate(end.toISOString())}`
})
const th = 'px-3 py-2 font-medium text-left'
const td = 'px-3 py-2'
</script>

<template>
    <div class="min-h-full flex flex-col gap-4 max-w-[1100px] w-full mx-auto px-2 sm:px-4 lg:px-6 py-4 sm:py-6 print:max-w-none print:p-0">
        <div class="print:hidden flex flex-wrap items-end gap-3 bg-bg-surface border border-border-default rounded-lg shadow-sm p-4">
            <div class="flex bg-secondary-main p-1 rounded-md border border-secondary-border text-sm" role="group" aria-label="Report period">
                <button v-for="p in ([['7', 'Last 7 days'], ['30', 'Last 30 days'], ['90', 'Last 90 days'], ['custom', 'Custom']] as const)" :key="p[0]" type="button"
                        :aria-pressed="preset === p[0]" @click="preset = p[0]"
                        class="px-3 py-1 rounded-sm transition-colors outline-none"
                        :class="preset === p[0] ? 'bg-primary-selected text-primary-text' : 'text-secondary-text hover:bg-secondary-hover'">{{ p[1] }}</button>
            </div>
            <template v-if="preset === 'custom'">
                <label class="flex flex-col text-xs text-text-m">From<input v-model="customFrom" type="date" class="px-2 py-1 text-sm bg-input-bg border border-input-border rounded-md text-text-h" /></label>
                <label class="flex flex-col text-xs text-text-m">To<input v-model="customTo" type="date" class="px-2 py-1 text-sm bg-input-bg border border-input-border rounded-md text-text-h" /></label>
                <BaseButton variant="secondary" class="!py-1.5 !text-sm" @click="generate">Generate</BaseButton>
            </template>
            <div class="flex gap-2 ml-auto">
                <BaseButton variant="secondary" class="!py-1.5 !text-sm" :disabled="!report" @click="downloadJson">Download JSON</BaseButton>
                <BaseButton variant="primary" class="!py-1.5 !text-sm" :disabled="!report" @click="print">Print / Save as PDF</BaseButton>
            </div>
            <p v-if="loadError" class="basis-full text-sm text-danger-text">{{ loadError }}</p>
        </div>

        <article v-if="report" class="bg-bg-surface border border-border-default rounded-lg shadow-sm p-6 sm:p-8 flex flex-col gap-8 text-text-h print:border-0 print:shadow-none print:p-0">
            <header class="flex flex-wrap items-end justify-between gap-4 border-b border-border-default pb-5">
                <div>
                    <div class="text-sm text-text-m">TrueSignal deception report</div>
                    <h1 class="text-h1 font-medium tracking-tight">{{ periodLabel }}</h1>
                </div>
                <dl class="text-sm text-text-m grid grid-cols-[auto_auto] gap-x-4 gap-y-0.5">
                    <dt>Generated</dt><dd class="text-text-h font-mono">{{ formatDateTime(report.generatedAt) }}</dd>
                    <dt>Hub</dt><dd class="text-text-h font-mono">{{ configStore.config.hubEndpoint }}</dd>
                </dl>
            </header>

            <section class="print-avoid-break">
                <h2 class="text-base font-medium mb-3">Summary</h2>
                <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
                    <div v-for="k in kpis" :key="k.l" class="border border-border-default rounded-md px-3 py-2">
                        <div class="text-xs text-text-m">{{ k.l }}</div>
                        <div class="text-xl font-mono" :class="k.a && Number(k.v) > 0 ? 'text-critical' : ''">{{ k.v }}</div>
                    </div>
                </div>
                <ul class="list-disc pl-5 text-sm space-y-1">
                    <li v-for="f in findings" :key="f">{{ f }}</li>
                </ul>
            </section>

            <section class="print-avoid-break">
                <h2 class="text-base font-medium mb-3">Daily activity</h2>
                <div class="h-[180px]"><canvas ref="chartCanvas" role="img" :aria-label="`Interactions per day: ${report.daily.map(d => `${d.date} ${d.events}`).join(', ')}`"></canvas></div>
            </section>

            <section class="grid sm:grid-cols-2 gap-6 print-avoid-break">
                <div>
                    <h2 class="text-base font-medium mb-3">By severity</h2>
                    <table class="w-full text-sm border border-border-default">
                        <tbody>
                            <tr v-for="r in sevRows" :key="r.k" class="border-t border-border-default first:border-t-0">
                                <td :class="td" class="capitalize" :style="{ color: `var(--color-${r.k})` }">{{ r.k }}</td>
                                <td :class="td" class="text-right font-mono">{{ r.n }}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                <div>
                    <h2 class="text-base font-medium mb-3">By decoy type</h2>
                    <table class="w-full text-sm border border-border-default">
                        <thead class="bg-bg-inset text-text-m"><tr><th :class="th">Decoy</th><th :class="th" class="text-right">Interactions</th><th :class="th" class="text-right">Sources</th></tr></thead>
                        <tbody>
                            <tr v-for="t in report.summary.byType" :key="t.sensorId" class="border-t border-border-default">
                                <td :class="td" :title="decoyName(t.sensorId, manifests)">{{ shortDecoyName(t.sensorId, manifests) }}</td>
                                <td :class="td" class="text-right font-mono">{{ t.events }}</td>
                                <td :class="td" class="text-right font-mono">{{ t.uniqueSources }}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </section>

            <section>
                <h2 class="text-base font-medium mb-1">Top sources</h2>
                <p class="text-xs text-text-m mb-3">{{ report.sourcesTotal }} sources in total; known assets first, then by critical events. A known asset as the source points to a likely compromised internal host.</p>
                <table v-if="report.topSources.length" class="w-full text-sm border border-border-default">
                    <thead class="bg-bg-inset text-text-m"><tr><th :class="th">Source</th><th :class="th">Asset</th><th :class="th" class="text-right">Events</th><th :class="th" class="text-right">Critical</th><th :class="th" class="text-right">Decoys</th><th :class="th">First – last seen</th></tr></thead>
                    <tbody>
                        <tr v-for="s in report.topSources" :key="s.source" class="border-t border-border-default print-avoid-break">
                            <td :class="td" class="font-mono">{{ s.source }}</td>
                            <td :class="td"><span v-if="s.asset" class="text-critical">{{ s.asset.name }} ({{ s.asset.criticality }})</span><span v-else class="text-text-l">–</span></td>
                            <td :class="td" class="text-right font-mono">{{ s.events }}</td>
                            <td :class="[td, s.critical ? 'text-critical' : '']" class="text-right font-mono">{{ s.critical }}</td>
                            <td :class="td" class="text-right font-mono">{{ s.decoys }}</td>
                            <td :class="td" class="font-mono text-xs text-text-m whitespace-nowrap">{{ formatDateTime(s.firstSeen) }} – {{ formatDateTime(s.lastSeen) }}</td>
                        </tr>
                    </tbody>
                </table>
                <p v-else class="text-sm text-text-m">None.</p>
            </section>

            <section class="print-avoid-break">
                <h2 class="text-base font-medium mb-3">MITRE ATT&amp;CK techniques observed</h2>
                <table v-if="report.techniques.length" class="w-full text-sm border border-border-default">
                    <thead class="bg-bg-inset text-text-m"><tr><th :class="th">Technique</th><th :class="th">Tactics</th><th :class="th" class="text-right">Events</th><th :class="th" class="text-right">Sources</th></tr></thead>
                    <tbody>
                        <tr v-for="t in report.techniques" :key="t.id" class="border-t border-border-default">
                            <td :class="td"><span class="font-mono">{{ t.id }}</span> {{ t.name }}</td>
                            <td :class="td" class="text-text-m">{{ t.tactics.map(id => tacticNames[id] || id).join(', ') }}</td>
                            <td :class="td" class="text-right font-mono">{{ t.primaryEvents }}<span v-if="t.secondaryEvents" class="text-text-l"> +{{ t.secondaryEvents }}</span></td>
                            <td :class="td" class="text-right font-mono">{{ t.sources }}</td>
                        </tr>
                    </tbody>
                </table>
                <p v-else class="text-sm text-text-m">None.</p>
                <p class="text-xs text-text-m mt-2">Events = events with this as the primary technique (+ as a secondary). Mapping: Docs/siem/attack-mapping.md.</p>
            </section>

            <section v-if="report.honeytokenUses.length" class="print-avoid-break">
                <h2 class="text-base font-medium mb-3">Honeytoken use</h2>
                <table class="w-full text-sm border border-border-default">
                    <thead class="bg-bg-inset text-text-m"><tr><th :class="th">Time</th><th :class="th">Credential</th><th :class="th">Source</th><th :class="th">Used against</th></tr></thead>
                    <tbody>
                        <tr v-for="u in report.honeytokenUses" :key="u.timestamp + u.source" class="border-t border-border-default">
                            <td :class="td" class="font-mono text-xs whitespace-nowrap">{{ formatDateTime(u.timestamp) }}</td>
                            <td :class="td" class="font-mono">{{ u.username }}</td>
                            <td :class="td" class="font-mono">{{ u.source }}</td>
                            <td :class="td">{{ shortDecoyName(u.sensorId, manifests) }} <span class="font-mono text-xs text-text-m">{{ nodeAlias(u.nodeId) }}</span></td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="print-avoid-break">
                <h2 class="text-base font-medium mb-1">Decoy coverage</h2>
                <p class="text-xs text-text-m mb-3">Nodes and decoys as deployed when the report was generated.</p>
                <table class="w-full text-sm border border-border-default">
                    <thead class="bg-bg-inset text-text-m"><tr><th :class="th">Node</th><th :class="th">Status</th><th :class="th">Decoys</th><th :class="th">Last heartbeat</th></tr></thead>
                    <tbody>
                        <tr v-for="n in nodes" :key="n.id" class="border-t border-border-default">
                            <td :class="td" class="font-mono">{{ n.alias }}</td>
                            <td :class="td" class="capitalize">{{ n.status }}</td>
                            <td :class="td">{{ (n.installedSensors || []).map((s: any) => shortDecoyName(s.sensorId, manifests)).join(', ') || '–' }}</td>
                            <td :class="td" class="font-mono text-xs whitespace-nowrap">{{ n.lastHeartbeat ? formatDateTime(n.lastHeartbeat) : '–' }}</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="print-avoid-break">
                <h2 class="text-base font-medium mb-3">Control configuration</h2>
                <table class="w-full text-sm border border-border-default">
                    <tbody>
                        <tr v-for="p in posture" :key="p.label" class="border-t border-border-default first:border-t-0">
                            <td :class="td" class="text-text-m w-1/3">{{ p.label }}</td>
                            <td :class="[td, p.ok ? '' : 'text-critical']">{{ p.value }}</td>
                        </tr>
                    </tbody>
                </table>
            </section>

            <section class="print-avoid-break text-sm text-text-m border-t border-border-default pt-5">
                <h2 class="text-base font-medium text-text-h mb-2">Scope of this evidence</h2>
                <p>TrueSignal is a deception control: decoy services, decoy files and planted credentials that no legitimate user or process should touch, so any interaction is treated as suspicious and alerted. It supports, and does not replace, network intrusion detection and prevention. This report can serve as supporting evidence for PCI DSS v4.0 Requirement 11.5.1 (intrusion-detection techniques detect and alert on suspected compromise) and for Central Bank of Egypt cyber-security reviews of intrusion-detection capability. Figures exclude Hub liveness events and archived events (whitelisted sources, known scanners, analyst triage).</p>
                <div class="grid grid-cols-3 gap-6 mt-8 text-text-h">
                    <div class="border-t border-text-h pt-1 text-xs">Reviewed by</div>
                    <div class="border-t border-text-h pt-1 text-xs">Role</div>
                    <div class="border-t border-text-h pt-1 text-xs">Date and signature</div>
                </div>
            </section>
        </article>
        <div v-else-if="loading" class="text-text-m">Generating…</div>
    </div>
</template>
