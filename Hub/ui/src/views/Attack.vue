<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { api } from '../api/client'
import { useAppStore } from '../stores/System/app'
import type { AttackProjection, TechniqueStat } from '../stores/Attack/attack'
import { techniqueUrl } from '../stores/Attack/attack'
import { formatDateTime } from '../utils/allEvents'
import PageHeader from '../components/ui/layout/PageHeader.vue'
import BaseTimeFilter from '../components/ui/forms/BaseTimeFilter.vue'

// ATT&CK matrix of every technique TrueSignal decoys can evidence, shaded
// by how many events had it as their primary technique. Techniques filed
// under several tactics (Valid Accounts) appear in each column, as in the
// ATT&CK Navigator.
const appStore = useAppStore()
const projection = ref<AttackProjection | null>(null)
const timeframe = ref('All')
const loading = ref(true)
const loadError = ref('')
const selected = ref<TechniqueStat | null>(null)

const tfParam = computed(() => (timeframe.value === 'All' ? 'alltime' : timeframe.value))
const query = computed(() => `timeframe=${tfParam.value}&archived=${appStore.viewingArchive ? 'true' : 'false'}`)

const load = async () => {
    loading.value = true
    loadError.value = ''
    try {
        const res = await api.get(`/api/v2/attack?${query.value}`)
        projection.value = (await res.json()) as AttackProjection
        if (selected.value) selected.value = projection.value.techniques.find(t => t.id === selected.value!.id) || null
    } catch (e: any) {
        loadError.value = e?.message || 'Failed to load ATT&CK data'
    } finally {
        loading.value = false
    }
}
onMounted(load)
watch([timeframe, () => appStore.viewingArchive], load)

const maxScore = computed(() => Math.max(1, ...(projection.value?.techniques || []).map(t => t.primaryEvents)))

const columns = computed(() => {
    const p = projection.value
    if (!p) return []
    return p.tactics
        .map(tc => {
            const cells = p.techniques
                .filter(t => t.tactics.includes(tc.id))
                .sort((a, b) => (b.primaryEvents - a.primaryEvents) || (b.secondaryEvents - a.secondaryEvents) || a.id.localeCompare(b.id))
            return { tactic: tc, cells, observed: cells.filter(c => c.primaryEvents + c.secondaryEvents > 0).length }
        })
        .filter(col => col.cells.length > 0)
})

// Sequential single-hue scale on the critical colour, mixed into the
// surface so it works in both themes. Bin 0 = covered, no primary events.
const BIN_MIX = [0, 22, 42, 66, 90]
const binOf = (t: TechniqueStat): number => {
    if (t.primaryEvents === 0) return 0
    return Math.min(4, Math.ceil((t.primaryEvents / maxScore.value) * 4))
}
const cellStyle = (t: TechniqueStat) => {
    const mix = BIN_MIX[binOf(t)]
    if (mix === 0) return {}
    return { background: `color-mix(in oklab, var(--sev-critical) ${mix}%, var(--bg-surface))` }
}
const darkText = (t: TechniqueStat) => binOf(t) < 3

const layerHref = computed(() => `/api/v2/attack/layer?${query.value}`)
</script>

<template>
    <div class="min-h-full flex flex-col gap-4 sm:gap-6 max-w-[1600px] w-full mx-auto px-2 sm:px-4 lg:px-6 py-4 sm:py-6">
        <PageHeader
            title="Attack Navigator"
            description="Decoy and honeytoken activity mapped to MITRE ATT&CK (Enterprise). Every technique TrueSignal can evidence is shown; shading counts the events that had it as their primary technique. The same mapping is sent to the SIEM (ECS threat.*, syslog mitre_technique / mitre_tactic)."
        />

        <div class="flex flex-wrap items-center gap-3">
            <div class="flex flex-wrap gap-4 text-sm text-text-m">
                <span><span class="font-mono text-lg" :class="(projection?.techniquesObserved || 0) > 0 ? 'text-critical' : 'text-text-h'">{{ projection?.techniquesObserved ?? '–' }}</span> of {{ projection?.techniquesCovered ?? '–' }} covered techniques observed</span>
                <span><span class="font-mono text-lg text-text-h">{{ projection?.mappedEvents ?? '–' }}</span> mapped events</span>
            </div>
            <div class="flex items-center gap-3 ml-auto">
                <BaseTimeFilter v-model="timeframe" :options="['24H', '7D', '30D', 'All']" />
                <a :href="layerHref" download="truesignal-attack-layer.json"
                   class="px-3 py-1.5 text-sm rounded-md border bg-secondary-main text-secondary-text border-secondary-border hover:bg-secondary-hover"
                   title="ATT&CK Navigator layer (format 4.5). Open it at mitre-attack.github.io/attack-navigator via Open Existing Layer.">Export Navigator layer</a>
            </div>
        </div>

        <div v-if="loadError" class="text-danger-text text-sm">{{ loadError }}</div>

        <div class="flex flex-col gap-4 sm:gap-6">
            <div class="w-full overflow-x-auto bg-bg-surface border border-border-default rounded-lg shadow-sm">
                <div class="grid gap-2 p-3" role="grid" aria-label="ATT&CK matrix"
                     :style="{ gridTemplateColumns: `repeat(${columns.length || 1}, minmax(104px, 1fr))` }">
                    <div v-for="col in columns" :key="col.tactic.id" class="flex flex-col gap-1.5 min-w-0" role="rowgroup">
                        <div class="px-2 py-2 rounded bg-bg-inset text-center" role="columnheader">
                            <div class="text-sm font-medium text-text-h leading-tight">{{ col.tactic.name }}</div>
                            <div class="text-xs text-text-m font-mono">{{ col.tactic.id }} · {{ col.observed }}/{{ col.cells.length }}</div>
                        </div>
                        <button v-for="t in col.cells" :key="t.id" type="button" role="gridcell"
                                @click="selected = t"
                                :aria-pressed="selected?.id === t.id"
                                :title="`${t.id} ${t.name}: ${t.primaryEvents} events (primary), ${t.secondaryEvents} (secondary)`"
                                class="text-left px-2 py-1.5 rounded border transition-shadow outline-none focus-visible:ring-2 focus-visible:ring-highlight-border"
                                :class="[
                                    t.primaryEvents + t.secondaryEvents > 0 ? 'border-transparent' : 'border-dashed border-border-default bg-bg-surface',
                                    selected?.id === t.id ? 'ring-2 ring-text-h' : ''
                                ]"
                                :style="cellStyle(t)">
                            <div class="flex items-baseline justify-between gap-1">
                                <span class="text-xs font-mono" :class="darkText(t) ? 'text-text-m' : 'text-white/85'">{{ t.id }}</span>
                                <span v-if="t.primaryEvents" class="text-xs font-mono font-medium" :class="darkText(t) ? 'text-text-h' : 'text-white'">{{ t.primaryEvents }}</span>
                                <span v-else-if="t.secondaryEvents" class="text-xs font-mono text-text-l" title="Only as a secondary technique">+{{ t.secondaryEvents }}</span>
                            </div>
                            <div class="text-xs leading-snug" :class="darkText(t) ? 'text-text-h' : 'text-white'">{{ t.name.includes(': ') ? t.name.split(': ')[1] : t.name }}</div>
                        </button>
                    </div>
                    <div v-if="loading && !projection" class="p-6 text-text-m">Loading…</div>
                </div>
                <div class="flex flex-wrap items-center gap-4 px-4 py-2.5 border-t border-border-default text-xs text-text-m">
                    <span class="flex items-center gap-1.5"><span class="w-4 h-3 rounded-sm border border-dashed border-border-default"></span>Covered, no events</span>
                    <span class="flex items-center gap-1.5">
                        Fewer
                        <span v-for="m in BIN_MIX.slice(1)" :key="m" class="w-4 h-3 rounded-sm" :style="{ background: `color-mix(in oklab, var(--sev-critical) ${m}%, var(--bg-surface))` }"></span>
                        More events (primary)
                    </span>
                    <span>+n: seen only as a secondary technique</span>
                </div>
            </div>

            <aside class="w-full max-w-3xl bg-bg-surface border border-border-default rounded-lg shadow-sm p-5" aria-live="polite">
                <template v-if="selected">
                    <div class="text-xs font-mono text-text-m">{{ selected.id }}</div>
                    <h2 class="text-base font-medium text-text-h mt-0.5">{{ selected.name }}</h2>
                    <dl class="mt-4 grid grid-cols-2 sm:grid-cols-4 gap-x-6 gap-y-3 text-sm max-w-2xl">
                        <dt class="text-text-m">Primary events</dt><dd class="font-mono text-right" :class="selected.primaryEvents ? 'text-critical' : 'text-text-h'">{{ selected.primaryEvents }}</dd>
                        <dt class="text-text-m">Secondary events</dt><dd class="font-mono text-right text-text-h">{{ selected.secondaryEvents }}</dd>
                        <dt class="text-text-m">Sources</dt><dd class="font-mono text-right text-text-h">{{ selected.sources }}</dd>
                        <dt class="text-text-m">Last seen</dt><dd class="font-mono text-right text-text-h">{{ selected.lastSeen ? formatDateTime(selected.lastSeen) : '–' }}</dd>
                    </dl>
                    <div class="mt-4 text-sm">
                        <div class="text-text-m mb-1">Tactics</div>
                        <div class="text-text-h">{{ selected.tactics.map(id => projection?.tactics.find(t => t.id === id)?.name || id).join(', ') }}</div>
                    </div>
                    <div class="mt-4 text-sm">
                        <div class="text-text-m mb-1">Triggers</div>
                        <div v-if="selected.triggers.length" class="flex flex-wrap gap-1.5">
                            <span v-for="tr in selected.triggers" :key="tr" class="px-1.5 py-0.5 rounded border border-border-default font-mono text-xs text-text-h">{{ tr }}</span>
                        </div>
                        <div v-else class="text-text-l">None in this timeframe</div>
                    </div>
                    <a :href="techniqueUrl(selected.id)" target="_blank" rel="noopener noreferrer"
                       class="inline-block mt-5 text-sm text-highlight-text underline underline-offset-2">View on attack.mitre.org</a>
                </template>
                <p v-else class="text-sm text-text-m">Select a technique to see its events, sources and triggers.</p>
            </aside>
        </div>
    </div>
</template>
