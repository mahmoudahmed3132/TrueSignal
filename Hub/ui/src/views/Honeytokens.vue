<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { storeToRefs } from 'pinia'
import { api } from '../api/client'
import { useFleetStore } from '../stores/Fleet/fleet'
import { fetchAllEvents, formatDateTime } from '../utils/allEvents'
import type { EventPayload } from '../stores/Events/events'
import { decoyName } from '../utils/decoyNames'
import PageHeader from '../components/ui/layout/PageHeader.vue'

interface Honeytoken {
    id: string
    username: string
    nodeId: string
    sensorId: string
    createdAt: string
    lastUsedAt: string
    useCount: number
}

const fleetStore = useFleetStore()
const { nodes, manifests } = storeToRefs(fleetStore)

const tokens = ref<Honeytoken[]>([])
const uses = ref<EventPayload[]>([])
const loading = ref(true)
const loadError = ref('')
const search = ref('')
const statusFilter = ref<'all' | 'used' | 'unused'>('all')
const expanded = ref<Set<string>>(new Set())

const nodeAlias = (id: string) => nodes.value.find(n => n.id === id)?.alias || id

const load = async () => {
    loading.value = true
    loadError.value = ''
    try {
        const [res, events] = await Promise.all([api.get('/api/v2/honeytokens'), fetchAllEvents()])
        tokens.value = (await res.json()) as Honeytoken[]
        uses.value = events.filter(e => e.eventTrigger === 'honeytoken_used')
    } catch (e: any) {
        loadError.value = e?.message || 'Failed to load honeytokens'
    } finally {
        loading.value = false
    }
}
onMounted(load)

const usesOf = (id: string) => uses.value.filter(e => e.details?.honeytoken_id === id)

const filtered = computed(() => {
    const q = search.value.trim().toLowerCase()
    return tokens.value.filter(t => {
        if (statusFilter.value === 'used' && t.useCount === 0) return false
        if (statusFilter.value === 'unused' && t.useCount > 0) return false
        if (!q) return true
        return [t.username, t.id, nodeAlias(t.nodeId), t.nodeId, t.sensorId].join(' ').toLowerCase().includes(q)
    }).sort((a, b) => (b.useCount - a.useCount) || (a.createdAt < b.createdAt ? 1 : -1))
})

const usedCount = computed(() => tokens.value.filter(t => t.useCount > 0).length)

const toggle = (id: string) => {
    const next = new Set(expanded.value)
    next.has(id) ? next.delete(id) : next.add(id)
    expanded.value = next
}
</script>

<template>
    <div class="min-h-full flex flex-col max-w-[1600px] w-full mx-auto px-2 sm:px-4 lg:px-6 py-4 sm:py-6">
        <PageHeader
            title="Honeytokens"
            description="Credentials the Hub planted in File Canary lures, one per File Canary instance. Any use is critical: it raises honeytoken_used, ignores the whitelist and the known-scanner list, and is published to the SIEM watchlist."
        />

        <div class="bg-bg-surface border border-border-default rounded-lg shadow-sm overflow-hidden">
            <div class="px-5 py-3 border-b border-border-default flex flex-wrap items-center gap-3">
                <span class="text-base text-text-h font-medium">
                    {{ tokens.length }} planted
                    <span class="text-text-m font-normal">·</span>
                    <span :class="usedCount > 0 ? 'text-critical' : 'text-success-main'">{{ usedCount }} used</span>
                </span>
                <label class="relative flex-[1_1_220px] max-w-xs ml-auto">
                    <span class="sr-only">Search honeytokens</span>
                    <input v-model="search" type="search" placeholder="Search username, node, ID"
                           class="w-full px-3 py-1.5 text-sm bg-input-bg border border-input-border rounded-md outline-none focus:border-primary-main focus:ring-1 focus:ring-focus-ring text-text-h" />
                </label>
                <div class="flex bg-secondary-main p-1 rounded-md border border-secondary-border text-sm" role="group" aria-label="Filter by use">
                    <button v-for="f in (['all', 'used', 'unused'] as const)" :key="f" type="button"
                            :aria-pressed="statusFilter === f" @click="statusFilter = f"
                            class="px-3 py-1 rounded-sm capitalize transition-colors outline-none"
                            :class="statusFilter === f ? 'bg-primary-selected text-primary-text' : 'text-secondary-text hover:bg-secondary-hover'">{{ f }}</button>
                </div>
                <a href="/api/v2/honeytokens?format=csv" download="truesignal-honeytokens.csv"
                   class="px-3 py-1.5 text-sm rounded-md border bg-secondary-main text-secondary-text border-secondary-border hover:bg-secondary-hover"
                   title="Username list for a SIEM lookup table">Export CSV</a>
            </div>

            <div class="overflow-x-auto">
                <table class="min-w-full text-left">
                    <thead class="text-sm text-text-m bg-bg-inset">
                        <tr>
                            <th class="px-3 py-2.5 w-8"></th>
                            <th class="px-4 py-2.5 font-medium">Status</th>
                            <th class="px-4 py-2.5 font-medium">Username</th>
                            <th class="px-4 py-2.5 font-medium">Planted on</th>
                            <th class="px-4 py-2.5 font-medium">Created</th>
                            <th class="px-4 py-2.5 font-medium text-right">Uses</th>
                            <th class="px-5 py-2.5 font-medium text-right">Last used</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-if="loading"><td colspan="7" class="px-5 py-8 text-center text-text-m">Loading…</td></tr>
                        <tr v-else-if="loadError"><td colspan="7" class="px-5 py-8 text-center text-danger-text">{{ loadError }}</td></tr>
                        <tr v-else-if="tokens.length === 0"><td colspan="7" class="px-5 py-8 text-center text-text-m">No honeytokens yet. The Hub plants one per File Canary instance when its compose is first generated.</td></tr>
                        <tr v-else-if="filtered.length === 0"><td colspan="7" class="px-5 py-8 text-center text-text-m">No honeytokens match the filters.</td></tr>
                        <template v-for="t in filtered" :key="t.id">
                            <tr class="border-t border-border-default hover:bg-secondary-hover cursor-pointer" @click="toggle(t.id)">
                                <td class="px-3 py-3 text-text-m">
                                    <svg class="w-4 h-4 transition-transform" :class="expanded.has(t.id) ? 'rotate-90 text-text-h' : ''" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
                                </td>
                                <td class="px-4 py-3">
                                    <span class="px-2 py-0.5 rounded border text-sm whitespace-nowrap"
                                          :class="t.useCount > 0 ? 'text-critical border-critical bg-danger-bg' : 'text-success-text border-success-border bg-success-bg'">
                                        {{ t.useCount > 0 ? 'Used' : 'Not used' }}
                                    </span>
                                </td>
                                <td class="px-4 py-3 font-mono text-text-h">{{ t.username }}</td>
                                <td class="px-4 py-3 text-text-m">
                                    <span class="text-text-h font-mono">{{ nodeAlias(t.nodeId) }}</span>
                                    <span class="text-sm"> · {{ decoyName(t.sensorId, manifests) }}</span>
                                </td>
                                <td class="px-4 py-3 font-mono text-sm text-text-m whitespace-nowrap">{{ formatDateTime(t.createdAt) }}</td>
                                <td class="px-4 py-3 font-mono text-right" :class="t.useCount > 0 ? 'text-critical' : 'text-text-m'">{{ t.useCount }}</td>
                                <td class="px-5 py-3 font-mono text-sm text-right text-text-m whitespace-nowrap">{{ t.lastUsedAt ? formatDateTime(t.lastUsedAt) : '–' }}</td>
                            </tr>
                            <tr v-if="expanded.has(t.id)" class="bg-bg-base">
                                <td colspan="7" class="px-11 py-4">
                                    <p class="text-sm text-text-m mb-2">Token <span class="font-mono text-text-h">{{ t.id }}</span>. The secret is never shown; it lives only in the lure files.</p>
                                    <p v-if="usesOf(t.id).length === 0" class="text-sm text-text-m">
                                        {{ t.useCount > 0 ? 'Uses were recorded, but their events have been purged.' : 'Never used.' }}
                                    </p>
                                    <table v-else class="text-sm">
                                        <thead class="text-text-m"><tr>
                                            <th class="pr-6 py-1 font-medium text-left">Time</th>
                                            <th class="pr-6 py-1 font-medium text-left">Source</th>
                                            <th class="pr-6 py-1 font-medium text-left">Used against</th>
                                            <th class="pr-6 py-1 font-medium text-left">Matched on</th>
                                        </tr></thead>
                                        <tbody>
                                            <tr v-for="u in usesOf(t.id)" :key="u.id">
                                                <td class="pr-6 py-1 font-mono text-text-m whitespace-nowrap">{{ formatDateTime(u.timestamp) }}</td>
                                                <td class="pr-6 py-1 font-mono text-text-h">{{ u.source }}</td>
                                                <td class="pr-6 py-1 text-text-h">
                                                    <span class="font-mono">{{ nodeAlias(u.nodeId) }}</span> · {{ decoyName(u.sensorId, manifests) }}
                                                    <span class="text-text-m">({{ String(u.details?.triggering_trigger || '').replace(/_/g, ' ') }})</span>
                                                </td>
                                                <td class="pr-6 py-1 text-text-m">{{ u.details?.matched_on }}</td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </td>
                            </tr>
                        </template>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</template>
