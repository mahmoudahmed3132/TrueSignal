<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { api } from '../api/client'
import { fetchAllEvents, formatDateTime } from '../utils/allEvents'
import type { EventPayload } from '../stores/Events/events'
import PageHeader from '../components/ui/layout/PageHeader.vue'

interface Artifact {
    filename: string
    contentType: string
    content: string
    value: string
}

interface Beacon {
    id: string
    token: string
    type: 'dns' | 'web_bug' | 'kubeconfig'
    name: string
    memo: string
    domain: string
    createdAt: string
    lastUsedAt: string
    useCount: number
    artifact: Artifact
}

const typeLabels: Record<Beacon['type'], string> = {
    dns: 'DNS name',
    web_bug: 'Web bug',
    kubeconfig: 'Kubeconfig',
}
const typeHelp: Record<Beacon['type'], string> = {
    dns: 'A host name that alerts when resolved. Plant it where only an intruder would use it: an ~/.ssh/config Host entry, DB_HOST in an .env file, an inventory, or a script an attacker would run.',
    web_bug: 'A remote image that alerts when loaded. Paste the <img> tag into an HTML page or a document that fetches remote images. Avoid mail that crosses a gateway: link scanners fetch images on delivery.',
    kubeconfig: 'A kubeconfig whose API server name alerts when kubectl resolves it. Plant it as ~/.kube/config on a jump host or in a repo.',
}

const beacons = ref<Beacon[]>([])
const domains = ref<string[]>([])
const uses = ref<EventPayload[]>([])
const loading = ref(true)
const loadError = ref('')
const search = ref('')
const expanded = ref<Set<string>>(new Set())

const form = ref({ type: 'dns' as Beacon['type'], name: '', memo: '', domain: '' })
const creating = ref(false)
const createError = ref('')
const copied = ref('')

const load = async () => {
    loading.value = true
    loadError.value = ''
    try {
        const [res, events] = await Promise.all([api.get('/api/v2/beacons'), fetchAllEvents()])
        const body = await res.json() as { beacons: Beacon[]; domains: string[] }
        beacons.value = body.beacons
        domains.value = body.domains
        if (!form.value.domain && domains.value.length > 0) form.value.domain = domains.value[0]
        uses.value = events.filter(e => e.eventTrigger === 'beacon_triggered')
    } catch (e: any) {
        loadError.value = e?.message || 'Failed to load beacons'
    } finally {
        loading.value = false
    }
}
onMounted(load)

const create = async () => {
    creating.value = true
    createError.value = ''
    try {
        const res = await api.post('/api/v2/beacons', form.value)
        const b = await res.json() as Beacon
        beacons.value = [b, ...beacons.value]
        expanded.value = new Set([b.id])
        form.value = { ...form.value, name: '', memo: '' }
    } catch (e: any) {
        createError.value = e?.message || 'Failed to create beacon'
    } finally {
        creating.value = false
    }
}

const remove = async (b: Beacon) => {
    if (!confirm(`Delete beacon "${b.name}"? Its past events are kept, but if it is used later the alert will only say "unknown beacon" (medium). Remove the planted artifact too.`)) return
    try {
        await api.delete(`/api/v2/beacons/${encodeURIComponent(b.id)}`)
        beacons.value = beacons.value.filter(x => x.id !== b.id)
    } catch (e: any) {
        loadError.value = e?.message || 'Failed to delete beacon'
    }
}

const copy = async (text: string, key: string) => {
    try {
        await navigator.clipboard.writeText(text)
        copied.value = key
        setTimeout(() => { if (copied.value === key) copied.value = '' }, 1500)
    } catch {
        // Clipboard blocked (non-HTTPS); the text is selectable.
    }
}

const usesOf = (id: string) => uses.value.filter(e => (e.details?.beacon as any)?.id === id)
const unknownUses = computed(() => uses.value.filter(e => e.details?.beacon_known === false).length)

const filtered = computed(() => {
    const q = search.value.trim().toLowerCase()
    return beacons.value.filter(b => !q || [b.name, b.memo, b.id, b.type, b.domain, b.token].join(' ').toLowerCase().includes(q))
        .sort((a, b) => (b.useCount - a.useCount) || (a.createdAt < b.createdAt ? 1 : -1))
})
const usedCount = computed(() => beacons.value.filter(b => b.useCount > 0).length)

const toggle = (id: string) => {
    const next = new Set(expanded.value)
    next.has(id) ? next.delete(id) : next.add(id)
    expanded.value = next
}
</script>

<template>
    <div class="min-h-full flex flex-col max-w-[1600px] w-full mx-auto px-2 sm:px-4 lg:px-6 py-4 sm:py-6">
        <PageHeader
            title="Beacons"
            description="Callback tokens to plant where only an intruder would use them. When one is resolved or loaded, a Token Receiver raises a critical beacon_triggered event that ignores the whitelist and the known-scanner list."
        />

        <div class="bg-bg-surface border border-border-default rounded-lg shadow-sm p-5 mb-4">
            <h2 class="text-base text-text-h font-medium mb-3">New beacon</h2>
            <p v-if="!loading && domains.length === 0" class="text-sm text-warning-text mb-3">
                No Token Receiver is deployed. Add the Token Receiver sensor to an internet-facing node and set its TS_BEACON_DOMAIN to a zone delegated to it; beacons point into that zone.
            </p>
            <form class="grid gap-3 md:grid-cols-[180px_1fr_1fr_220px_auto] items-end" @submit.prevent="create">
                <label class="text-sm text-text-m">Type
                    <select v-model="form.type" class="mt-1 w-full px-3 py-1.5 text-sm bg-input-bg border border-input-border rounded-md text-text-h">
                        <option v-for="(label, t) in typeLabels" :key="t" :value="t">{{ label }}</option>
                    </select>
                </label>
                <label class="text-sm text-text-m">Name (where it is planted)
                    <input v-model="form.name" required maxlength="128" placeholder="jump-01 ~/.kube/config"
                           class="mt-1 w-full px-3 py-1.5 text-sm bg-input-bg border border-input-border rounded-md text-text-h" />
                </label>
                <label class="text-sm text-text-m">Memo (optional)
                    <input v-model="form.memo" maxlength="512" placeholder="Owner, ticket, removal date"
                           class="mt-1 w-full px-3 py-1.5 text-sm bg-input-bg border border-input-border rounded-md text-text-h" />
                </label>
                <label class="text-sm text-text-m">Zone
                    <select v-if="domains.length > 0" v-model="form.domain" class="mt-1 w-full px-3 py-1.5 text-sm bg-input-bg border border-input-border rounded-md text-text-h font-mono">
                        <option v-for="d in domains" :key="d" :value="d">{{ d }}</option>
                    </select>
                    <input v-else v-model="form.domain" placeholder="t.example.com"
                           class="mt-1 w-full px-3 py-1.5 text-sm bg-input-bg border border-input-border rounded-md text-text-h font-mono" />
                </label>
                <button type="submit" :disabled="creating || !form.name.trim()"
                        class="px-4 py-1.5 text-sm rounded-md bg-primary-main text-primary-text hover:bg-primary-hover disabled:opacity-50">
                    {{ creating ? 'Creating…' : 'Create' }}
                </button>
            </form>
            <p class="text-sm text-text-m mt-2">{{ typeHelp[form.type] }}</p>
            <p v-if="createError" class="text-sm text-danger-text mt-2">{{ createError }}</p>
        </div>

        <div class="bg-bg-surface border border-border-default rounded-lg shadow-sm overflow-hidden">
            <div class="px-5 py-3 border-b border-border-default flex flex-wrap items-center gap-3">
                <span class="text-base text-text-h font-medium">
                    {{ beacons.length }} beacons
                    <span class="text-text-m font-normal">·</span>
                    <span :class="usedCount > 0 ? 'text-critical' : 'text-success-main'">{{ usedCount }} triggered</span>
                    <template v-if="unknownUses > 0">
                        <span class="text-text-m font-normal">·</span>
                        <span class="text-warning-text" title="Valid tokens the Hub has no beacon for (deleted beacons)">{{ unknownUses }} unknown-token events</span>
                    </template>
                </span>
                <label class="relative flex-[1_1_220px] max-w-xs ml-auto">
                    <span class="sr-only">Search beacons</span>
                    <input v-model="search" type="search" placeholder="Search name, memo, type, ID"
                           class="w-full px-3 py-1.5 text-sm bg-input-bg border border-input-border rounded-md outline-none focus:border-primary-main focus:ring-1 focus:ring-focus-ring text-text-h" />
                </label>
            </div>

            <div class="overflow-x-auto">
                <table class="min-w-full text-left">
                    <thead class="text-sm text-text-m bg-bg-inset">
                        <tr>
                            <th class="px-3 py-2.5 w-8"></th>
                            <th class="px-4 py-2.5 font-medium">Status</th>
                            <th class="px-4 py-2.5 font-medium">Name</th>
                            <th class="px-4 py-2.5 font-medium">Type</th>
                            <th class="px-4 py-2.5 font-medium">Created</th>
                            <th class="px-4 py-2.5 font-medium text-right">Uses</th>
                            <th class="px-5 py-2.5 font-medium text-right">Last used</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-if="loading"><td colspan="7" class="px-5 py-8 text-center text-text-m">Loading…</td></tr>
                        <tr v-else-if="loadError"><td colspan="7" class="px-5 py-8 text-center text-danger-text">{{ loadError }}</td></tr>
                        <tr v-else-if="beacons.length === 0"><td colspan="7" class="px-5 py-8 text-center text-text-m">No beacons yet.</td></tr>
                        <tr v-else-if="filtered.length === 0"><td colspan="7" class="px-5 py-8 text-center text-text-m">No beacons match the search.</td></tr>
                        <template v-for="b in filtered" :key="b.id">
                            <tr class="border-t border-border-default hover:bg-secondary-hover cursor-pointer" @click="toggle(b.id)">
                                <td class="px-3 py-3 text-text-m">
                                    <svg class="w-4 h-4 transition-transform" :class="expanded.has(b.id) ? 'rotate-90 text-text-h' : ''" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
                                </td>
                                <td class="px-4 py-3">
                                    <span class="px-2 py-0.5 rounded border text-sm whitespace-nowrap"
                                          :class="b.useCount > 0 ? 'text-critical border-critical bg-danger-bg' : 'text-success-text border-success-border bg-success-bg'">
                                        {{ b.useCount > 0 ? 'Triggered' : 'Quiet' }}
                                    </span>
                                </td>
                                <td class="px-4 py-3 text-text-h">
                                    {{ b.name }}
                                    <div v-if="b.memo" class="text-sm text-text-m">{{ b.memo }}</div>
                                </td>
                                <td class="px-4 py-3 text-text-m whitespace-nowrap">{{ typeLabels[b.type] || b.type }}</td>
                                <td class="px-4 py-3 font-mono text-sm text-text-m whitespace-nowrap">{{ formatDateTime(b.createdAt) }}</td>
                                <td class="px-4 py-3 font-mono text-right" :class="b.useCount > 0 ? 'text-critical' : 'text-text-m'">{{ b.useCount }}</td>
                                <td class="px-5 py-3 font-mono text-sm text-right text-text-m whitespace-nowrap">{{ b.lastUsedAt ? formatDateTime(b.lastUsedAt) : '–' }}</td>
                            </tr>
                            <tr v-if="expanded.has(b.id)" class="bg-bg-base">
                                <td colspan="7" class="px-11 py-4 space-y-3">
                                    <div class="flex flex-wrap items-center gap-2 text-sm">
                                        <span class="text-text-m">{{ b.type === 'web_bug' ? 'URL' : 'Host name' }}</span>
                                        <code class="font-mono text-text-h break-all">{{ b.artifact.value }}</code>
                                        <button type="button" class="px-2 py-0.5 rounded border border-secondary-border bg-secondary-main text-secondary-text hover:bg-secondary-hover"
                                                @click="copy(b.artifact.value, b.id + ':v')">{{ copied === b.id + ':v' ? 'Copied' : 'Copy' }}</button>
                                        <a :href="`/api/v2/beacons/${b.id}/download`" :download="b.artifact.filename"
                                           class="px-2 py-0.5 rounded border border-secondary-border bg-secondary-main text-secondary-text hover:bg-secondary-hover">Download {{ b.artifact.filename }}</a>
                                        <button type="button" class="ml-auto px-2 py-0.5 rounded border border-danger-border text-danger-text hover:bg-danger-bg"
                                                @click="remove(b)">Delete</button>
                                    </div>
                                    <pre class="text-sm font-mono bg-bg-inset border border-border-default rounded-md p-3 overflow-x-auto text-text-h whitespace-pre">{{ b.artifact.content }}</pre>
                                    <p v-if="usesOf(b.id).length === 0" class="text-sm text-text-m">
                                        {{ b.useCount > 0 ? 'Uses were recorded, but their events have been purged.' : 'Never triggered.' }}
                                    </p>
                                    <table v-else class="text-sm">
                                        <thead class="text-text-m"><tr>
                                            <th class="pr-6 py-1 font-medium text-left">Time</th>
                                            <th class="pr-6 py-1 font-medium text-left">Source</th>
                                            <th class="pr-6 py-1 font-medium text-left">Channel</th>
                                            <th class="pr-6 py-1 font-medium text-left">Detail</th>
                                        </tr></thead>
                                        <tbody>
                                            <tr v-for="u in usesOf(b.id)" :key="u.id">
                                                <td class="pr-6 py-1 font-mono text-text-m whitespace-nowrap">{{ formatDateTime(u.timestamp) }}</td>
                                                <td class="pr-6 py-1 font-mono text-text-h">{{ u.source }}</td>
                                                <td class="pr-6 py-1 text-text-h uppercase">{{ u.details?.channel }}</td>
                                                <td class="pr-6 py-1 text-text-m">
                                                    <template v-if="u.details?.channel === 'dns'">
                                                        {{ u.details?.query_type }} via resolver
                                                        <span v-if="u.details?.client_subnet"> · client subnet <span class="font-mono">{{ u.details?.client_subnet }}</span></span>
                                                    </template>
                                                    <template v-else>{{ u.details?.user_agent || '–' }}</template>
                                                </td>
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
