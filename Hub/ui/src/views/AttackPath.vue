<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { storeToRefs } from 'pinia'
import { api } from '../api/client'
import { useSourcesStore, labelsOf } from '../stores/Sources/sources'
import { useFleetStore } from '../stores/Fleet/fleet'
import type { EventPayload } from '../stores/Events/events'
import { techniqueUrl } from '../stores/Attack/attack'
import { decoyName, shortDecoyName } from '../utils/decoyNames'
import { formatDateTime } from '../utils/allEvents'
import PageHeader from '../components/ui/layout/PageHeader.vue'

// One source's route through the decoys: which decoys it reached, in what
// order, with which ATT&CK techniques, and how its tactics progressed.
interface Step { nodeId: string; sensorId: string; firstSeen: string; lastSeen: string; events: number; maxSeverity: string; triggers: string[]; techniques: string[] }
interface PathDTO {
    source: string
    asset: { name: string; criticality: string } | null
    events: number
    truncated: boolean
    firstSeen: string
    lastSeen: string
    steps: Step[]
    progression: { firstSeen: string; technique: string; name: string; tactics: { id: string; name: string }[] }[]
    timeline: EventPayload[]
}

const route = useRoute()
const router = useRouter()
const sourcesStore = useSourcesStore()
const fleetStore = useFleetStore()
const { profiles } = storeToRefs(sourcesStore)
const { nodes, manifests } = storeToRefs(fleetStore)

const nodeAlias = (id: string) => nodes.value.find(n => n.id === id)?.alias || id
const source = computed(() => String(route.query.source || ''))
const data = ref<PathDTO | null>(null)
const loading = ref(false)
const loadError = ref('')
const pickerSearch = ref('')

// Most worrying first: known assets, then multi-decoy, then volume.
const ranked = computed(() => {
    const q = pickerSearch.value.trim().toLowerCase()
    return [...profiles.value]
        .filter(p => p.source !== 'truesignal-hub' && (!q || [p.source, p.asset?.name || ''].join(' ').toLowerCase().includes(q)))
        .sort((a, b) => (Number(!!b.asset) - Number(!!a.asset)) || (b.decoys - a.decoys) || (b.events - a.events))
})

const load = async () => {
    if (!source.value) { data.value = null; return }
    loading.value = true
    loadError.value = ''
    try {
        const res = await api.get(`/api/v2/path?source=${encodeURIComponent(source.value)}`)
        data.value = (await res.json()) as PathDTO
    } catch (e: any) {
        loadError.value = e?.message || 'Failed to load the path'
    } finally {
        loading.value = false
    }
}

onMounted(async () => {
    await sourcesStore.fetchSources()
    if (!source.value && ranked.value.length) router.replace({ query: { source: ranked.value[0].source } })
    else load()
})
watch(source, load)

const pick = (s: string) => router.push({ query: { source: s } })

const sevVar = (s: string) => `var(--color-${s})`
const duration = computed(() => {
    if (!data.value?.firstSeen || !data.value?.lastSeen) return ''
    const ms = new Date(data.value.lastSeen).getTime() - new Date(data.value.firstSeen).getTime()
    const h = ms / 3600000
    if (h < 1) return `${Math.max(1, Math.round(ms / 60000))} min`
    if (h < 48) return `${Math.round(h)} h`
    return `${Math.round(h / 24)} days`
})
</script>

<template>
    <div class="min-h-full flex flex-col gap-4 sm:gap-6 max-w-[1600px] w-full mx-auto px-2 sm:px-4 lg:px-6 py-4 sm:py-6">
        <PageHeader
            title="Attack Path"
            description="One source's route through the decoys, in the order it first reached each one, with the ATT&CK techniques it used and how its tactics progressed. Active and archived events are included; Hub liveness is not."
        />

        <div class="flex flex-col lg:flex-row gap-4 sm:gap-6 items-start">
            <aside class="w-full lg:w-[280px] shrink-0 bg-bg-surface border border-border-default rounded-lg shadow-sm overflow-hidden">
                <div class="p-3 border-b border-border-default">
                    <input v-model="pickerSearch" type="search" placeholder="Search source or asset" aria-label="Search sources"
                           class="w-full px-3 py-1.5 text-sm bg-input-bg border border-input-border rounded-md outline-none focus:border-primary-main text-text-h" />
                </div>
                <ul class="max-h-[640px] overflow-y-auto" aria-label="Sources">
                    <li v-if="ranked.length === 0" class="px-4 py-6 text-sm text-text-m">No sources yet.</li>
                    <li v-for="p in ranked" :key="p.source">
                        <button type="button" @click="pick(p.source)"
                                class="w-full text-left px-4 py-2.5 border-b border-border-default hover:bg-secondary-hover outline-none"
                                :class="p.source === source ? 'bg-secondary-selected' : ''"
                                :aria-current="p.source === source ? 'true' : undefined">
                            <div class="flex items-center justify-between gap-2">
                                <span class="font-mono text-sm text-text-h truncate">{{ p.source }}</span>
                                <span class="text-xs font-mono text-text-m shrink-0">{{ p.decoys }} decoys</span>
                            </div>
                            <div class="flex items-center gap-1.5 mt-0.5 text-xs">
                                <span v-if="p.asset" class="text-critical truncate">{{ p.asset.name }}</span>
                                <span class="text-text-l">{{ p.events }} events</span>
                                <span v-if="labelsOf(p).has('scanner')" class="text-text-l">· scanner</span>
                                <span v-if="labelsOf(p).has('whitelisted')" class="text-text-l">· whitelisted</span>
                            </div>
                        </button>
                    </li>
                </ul>
            </aside>

            <section class="flex-1 min-w-0 w-full flex flex-col gap-4 sm:gap-6">
                <div v-if="loadError" class="text-sm text-danger-text">{{ loadError }}</div>
                <div v-else-if="!source" class="text-text-m">Select a source.</div>
                <template v-else-if="data">
                    <div class="bg-bg-surface border border-border-default rounded-lg shadow-sm p-5 flex flex-wrap gap-x-8 gap-y-3 items-baseline">
                        <div>
                            <div class="font-mono text-xl text-text-h">{{ data.source }}</div>
                            <div v-if="data.asset" class="text-sm mt-0.5">
                                <span class="text-critical font-medium">{{ data.asset.name }}</span>
                                <span class="text-text-m"> · {{ data.asset.criticality }} criticality · likely compromised internal host</span>
                            </div>
                        </div>
                        <div class="text-sm text-text-m"><span class="font-mono text-lg text-text-h">{{ data.events }}</span> events</div>
                        <div class="text-sm text-text-m"><span class="font-mono text-lg" :class="data.steps.length > 1 ? 'text-critical' : 'text-text-h'">{{ data.steps.length }}</span> decoys</div>
                        <div class="text-sm text-text-m">{{ formatDateTime(data.firstSeen) }} → {{ formatDateTime(data.lastSeen) }} <span v-if="duration">({{ duration }})</span></div>
                        <div v-if="data.truncated" class="text-xs text-archive-text basis-full">Showing the most recent 2,000 events.</div>
                    </div>

                    <div v-if="data.progression.length" class="bg-bg-surface border border-border-default rounded-lg shadow-sm p-5">
                        <h3 class="text-base font-medium text-text-h mb-1">Tactic progression</h3>
                        <p class="text-xs text-text-m mb-3">Each step is the technique that first brought a tactic into this path. A technique ATT&amp;CK files under several tactics is one step.</p>
                        <ol class="flex flex-wrap items-center gap-2">
                            <li v-for="(s, i) in data.progression" :key="s.technique" class="flex items-center gap-2">
                                <span class="px-2.5 py-1.5 rounded-md border border-border-default bg-bg-inset text-sm" :title="`${s.technique} ${s.name}, first at ${formatDateTime(s.firstSeen)}`">
                                    <span class="text-text-h">{{ s.tactics.map(t => t.name).join(' / ') }}</span>
                                    <span class="block text-xs text-text-m"><span class="font-mono">{{ s.technique }}</span> {{ s.name }}</span>
                                </span>
                                <span v-if="i < data.progression.length - 1" class="text-text-l" aria-hidden="true">→</span>
                            </li>
                        </ol>
                    </div>

                    <div class="bg-bg-surface border border-border-default rounded-lg shadow-sm p-5">
                        <h3 class="text-base font-medium text-text-h mb-3">Path through the decoys</h3>
                        <ol class="flex flex-wrap items-stretch gap-2" aria-label="Decoys in order of first contact">
                            <li class="flex items-center gap-2">
                                <div class="px-3 py-2 rounded-md border-2 border-text-h font-mono text-sm text-text-h">{{ data.source }}</div>
                                <span class="text-text-l text-lg" aria-hidden="true">→</span>
                            </li>
                            <li v-for="(s, i) in data.steps" :key="s.nodeId + s.sensorId" class="flex items-center gap-2">
                                <div class="w-[210px] rounded-md border border-border-default bg-bg-base p-3 border-l-4" :style="{ borderLeftColor: sevVar(s.maxSeverity) }">
                                    <div class="flex items-baseline justify-between gap-2">
                                        <span class="text-xs font-mono text-text-m">#{{ i + 1 }} · {{ formatDateTime(s.firstSeen) }}</span>
                                        <span class="text-xs font-mono text-text-h">×{{ s.events }}</span>
                                    </div>
                                    <div class="text-sm font-medium text-text-h mt-1 truncate" :title="decoyName(s.sensorId, manifests)">{{ shortDecoyName(s.sensorId, manifests) }}</div>
                                    <div class="text-xs font-mono text-text-m truncate">{{ nodeAlias(s.nodeId) }}</div>
                                    <div class="text-xs text-text-m mt-1.5 truncate" :title="s.triggers.join(', ')">{{ s.triggers.map(t => t.replace(/_/g, ' ')).join(', ') }}</div>
                                    <div class="flex flex-wrap gap-1 mt-1.5">
                                        <a v-for="t in s.techniques" :key="t" :href="techniqueUrl(t)" target="_blank" rel="noopener noreferrer"
                                           class="px-1.5 py-px rounded border border-border-default text-xs font-mono text-text-h hover:border-highlight-border">{{ t }}</a>
                                    </div>
                                </div>
                                <span v-if="i < data.steps.length - 1" class="text-text-l text-lg" aria-hidden="true">→</span>
                            </li>
                        </ol>
                    </div>

                    <div class="bg-bg-surface border border-border-default rounded-lg shadow-sm overflow-hidden">
                        <h3 class="text-base font-medium text-text-h px-5 pt-4 pb-3">Timeline</h3>
                        <div class="overflow-auto max-h-[520px]">
                            <table class="min-w-full text-left text-sm">
                                <thead class="text-text-m bg-bg-inset sticky top-0">
                                    <tr>
                                        <th class="px-5 py-2 font-medium">Time</th>
                                        <th class="px-4 py-2 font-medium">Severity</th>
                                        <th class="px-4 py-2 font-medium">Trigger</th>
                                        <th class="px-4 py-2 font-medium">ATT&amp;CK</th>
                                        <th class="px-4 py-2 font-medium">Decoy</th>
                                        <th class="px-5 py-2 font-medium">Target</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr v-for="e in [...data.timeline].reverse()" :key="e.id" class="border-t border-border-default">
                                        <td class="px-5 py-2 font-mono text-text-m whitespace-nowrap">{{ formatDateTime(e.timestamp) }}</td>
                                        <td class="px-4 py-2 capitalize whitespace-nowrap" :style="{ color: sevVar(e.severity) }">{{ e.severity }}</td>
                                        <td class="px-4 py-2 text-text-h whitespace-nowrap">{{ e.eventTrigger.replace(/_/g, ' ') }}<span v-if="e.isArchived" class="ml-1.5 text-xs text-text-l">archived</span></td>
                                        <td class="px-4 py-2 font-mono text-text-m whitespace-nowrap" :title="e.attack?.primary.name">{{ e.attack?.primary.id || '–' }}</td>
                                        <td class="px-4 py-2 text-text-h whitespace-nowrap">{{ shortDecoyName(e.sensorId, manifests) }} <span class="font-mono text-xs text-text-m">{{ nodeAlias(e.nodeId) }}</span></td>
                                        <td class="px-5 py-2 font-mono text-text-m truncate max-w-[260px]" :title="e.target">{{ e.target }}</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </template>
                <div v-else-if="loading" class="text-text-m">Loading…</div>
            </section>
        </div>
    </div>
</template>
