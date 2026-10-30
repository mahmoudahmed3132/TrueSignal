<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api/client'
import { useAppStore } from '../stores/System/app'
import { formatDateTime } from '../utils/allEvents'
import { COUNTRY_SHAPES, WORLD_VIEWBOX } from '../utils/worldMap'
import PageHeader from '../components/ui/layout/PageHeader.vue'
import BaseTimeFilter from '../components/ui/forms/BaseTimeFilter.vue'

interface GeoPoint {
    lat: number
    lon: number
    city: string
    region: string
    country: string
    countryCode: string
    events: number
    beaconEvents: number
    sourceCount: number
    sources: string[]
    triggers: string[]
    maxSeverity: string
    lastSeen: string
}
interface GeoCountry { countryCode: string; country: string; events: number; sources: number }
interface GeoStatus {
    enabled: boolean
    path: string
    databaseType?: string
    buildDate?: string
    autoUpdate: boolean
    lastError?: string
    attribution: string
    attributionUrl: string
}
interface GeoProjection {
    timeframe: string
    geoip: GeoStatus
    events: number
    locatedEvents: number
    internalEvents: number
    unlocatedEvents: number
    points: GeoPoint[]
    countries: GeoCountry[]
}

// Sources are located when events are read (DB-IP IP to City Lite), never
// stored. Internal addresses are not looked up, so the decoys' own subnet
// never appears here: the map fills from beacons opened outside and from
// any decoy exposed to public addresses.
const appStore = useAppStore()
const router = useRouter()
const data = ref<GeoProjection | null>(null)
const timeframe = ref('All')
const loading = ref(true)
const loadError = ref('')
const selected = ref<GeoPoint | null>(null)

const tfParam = computed(() => (timeframe.value === 'All' ? 'alltime' : timeframe.value))

const load = async () => {
    loading.value = true
    loadError.value = ''
    try {
        const res = await api.get(`/api/v2/geo?timeframe=${tfParam.value}&archived=${appStore.viewingArchive ? 'true' : 'false'}`)
        data.value = (await res.json()) as GeoProjection
        if (selected.value) {
            const s = selected.value
            selected.value = data.value.points.find(p => p.lat === s.lat && p.lon === s.lon) || null
        }
    } catch (e: any) {
        loadError.value = e?.message || 'Failed to load the map'
    } finally {
        loading.value = false
    }
}
onMounted(load)
watch([timeframe, () => appStore.viewingArchive], load)

const W = WORLD_VIEWBOX.width
const H = WORLD_VIEWBOX.height
const project = (lat: number, lon: number) => ({ x: (lon + 180) * 2, y: (90 - lat) * 2 })

const countryEvents = computed(() => {
    const m = new Map<string, number>()
    for (const c of data.value?.countries || []) m.set(c.countryCode, c.events)
    return m
})
const maxCountry = computed(() => Math.max(1, ...(data.value?.countries || []).map(c => c.events)))
const maxPoint = computed(() => Math.max(1, ...(data.value?.points || []).map(p => p.events)))

// Countries with activity are shaded on the critical hue, mixed into the
// surface so both themes work; the rest stay neutral.
const countryFill = (a2: string) => {
    const n = countryEvents.value.get(a2)
    if (!n) return 'var(--bg-inset)'
    const mix = 14 + Math.round((n / maxCountry.value) * 36)
    return `color-mix(in oklab, var(--sev-critical) ${mix}%, var(--bg-surface))`
}
const countryTitle = (a2: string, name: string) => {
    const n = countryEvents.value.get(a2)
    return n ? `${name}: ${n} events` : name
}

const sevVar: Record<string, string> = {
    critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--sev-medium)', low: 'var(--sev-low)', info: 'var(--sev-info)',
}
// Area proportional to events, so a big cluster doesn't swamp the map.
const radius = (p: GeoPoint) => 2.5 + Math.sqrt(p.events / maxPoint.value) * 9

// Small points draw on top of big ones.
const drawOrder = computed(() => [...(data.value?.points || [])].sort((a, b) => b.events - a.events))

const place = (p: GeoPoint) => [p.city, p.region, p.country].filter(Boolean).join(', ') || `${p.lat}, ${p.lon}`
const investigate = (source: string) => router.push({ path: '/path', query: { source } })
</script>

<template>
    <div class="min-h-full flex flex-col gap-4 sm:gap-6 max-w-[1600px] w-full mx-auto px-2 sm:px-4 lg:px-6 py-4 sm:py-6">
        <PageHeader
            title="GeoIP Map"
            description="Where decoy and beacon activity came from, for public source addresses. Internal addresses are never looked up, so activity from the decoys' own network is counted but not mapped. A DNS beacon is placed by its EDNS Client Subnet when the resolver sends one, otherwise by the resolver."
        />

        <div v-if="data && !data.geoip.enabled" class="bg-warning-bg border border-warning-border text-warning-text rounded-lg p-4 text-sm">
            <p class="font-medium">No GeoIP database is loaded, so nothing can be placed on the map.</p>
            <p class="mt-1">
                Place DB-IP's free <span class="font-mono">IP to City Lite</span> MMDB at
                <span class="font-mono">{{ data.geoip.path }}</span> (the Hub picks it up within an hour), or set
                <span class="font-mono">TS_GEOIP_AUTO_UPDATE=true</span> to let the Hub download it monthly from download.db-ip.com.
            </p>
            <p v-if="data.geoip.lastError" class="mt-1 font-mono">{{ data.geoip.lastError }}</p>
        </div>

        <div class="flex flex-wrap items-center gap-3">
            <div class="flex flex-wrap gap-x-5 gap-y-1 text-sm text-text-m">
                <span><span class="font-mono text-lg text-text-h">{{ data?.locatedEvents ?? '–' }}</span> located events</span>
                <span><span class="font-mono text-lg text-text-h">{{ data?.countries.length ?? '–' }}</span> countries</span>
                <span :title="'Private, CGNAT, loopback and link-local sources are never looked up'"><span class="font-mono text-lg text-text-h">{{ data?.internalEvents ?? '–' }}</span> internal (not mapped)</span>
                <span :title="'Public addresses the database has no location for, and non-IP sources'"><span class="font-mono text-lg text-text-h">{{ data?.unlocatedEvents ?? '–' }}</span> unlocated</span>
            </div>
            <div class="ml-auto"><BaseTimeFilter v-model="timeframe" :options="['24H', '7D', '30D', 'All']" /></div>
        </div>

        <div v-if="loadError" class="text-danger-text text-sm">{{ loadError }}</div>

        <div class="bg-bg-surface border border-border-default rounded-lg shadow-sm overflow-hidden">
            <svg :viewBox="`0 0 ${W} ${H}`" class="w-full h-auto block" role="img"
                 :aria-label="`World map with ${data?.points.length || 0} locations of decoy activity`">
                <rect :width="W" :height="H" fill="var(--bg-surface)" />
                <g stroke="var(--border-default)" stroke-width="0.35" stroke-linejoin="round">
                    <path v-for="c in COUNTRY_SHAPES" :key="c.name" :d="c.d" :fill="countryFill(c.a2)">
                        <title>{{ countryTitle(c.a2, c.name) }}</title>
                    </path>
                </g>
                <g>
                    <circle v-for="p in drawOrder" :key="`${p.lat},${p.lon}`"
                            :cx="project(p.lat, p.lon).x" :cy="project(p.lat, p.lon).y" :r="radius(p)"
                            :fill="sevVar[p.maxSeverity] || sevVar.medium" fill-opacity="0.75"
                            :stroke="selected === p ? 'var(--text-h)' : 'var(--bg-surface)'" :stroke-width="selected === p ? 1.2 : 0.6"
                            class="cursor-pointer outline-none" tabindex="0" role="button"
                            :aria-label="`${place(p)}: ${p.events} events from ${p.sourceCount} sources`"
                            @click="selected = p" @keydown.enter="selected = p">
                        <title>{{ place(p) }}: {{ p.events }} events, {{ p.sourceCount }} sources</title>
                    </circle>
                </g>
            </svg>
            <div class="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-2.5 border-t border-border-default text-xs text-text-m">
                <span v-for="s in ['critical', 'high', 'medium', 'low']" :key="s" class="flex items-center gap-1.5 capitalize">
                    <span class="w-2.5 h-2.5 rounded-full" :style="{ background: sevVar[s] }"></span>{{ s }}
                </span>
                <span>Circle size: events · colour: highest severity at that place · shaded countries: events</span>
                <span class="ml-auto">
                    <a :href="data?.geoip.attributionUrl || 'https://db-ip.com'" target="_blank" rel="noopener noreferrer" class="underline hover:text-text-h">{{ data?.geoip.attribution || 'IP Geolocation by DB-IP' }}</a>
                    <span v-if="data?.geoip.buildDate"> · database {{ data.geoip.buildDate }}</span>
                </span>
            </div>
        </div>

        <div class="grid gap-4 sm:gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <aside class="bg-bg-surface border border-border-default rounded-lg shadow-sm p-5" aria-live="polite">
                <template v-if="selected">
                    <h2 class="text-base font-medium text-text-h">{{ place(selected) }}</h2>
                    <dl class="mt-3 grid grid-cols-2 gap-x-6 gap-y-2 text-sm max-w-md">
                        <dt class="text-text-m">Events</dt><dd class="font-mono text-right text-text-h">{{ selected.events }}</dd>
                        <dt class="text-text-m">Beacon events</dt><dd class="font-mono text-right" :class="selected.beaconEvents ? 'text-critical' : 'text-text-h'">{{ selected.beaconEvents }}</dd>
                        <dt class="text-text-m">Sources</dt><dd class="font-mono text-right text-text-h">{{ selected.sourceCount }}</dd>
                        <dt class="text-text-m">Highest severity</dt><dd class="text-right capitalize" :style="{ color: sevVar[selected.maxSeverity] }">{{ selected.maxSeverity }}</dd>
                        <dt class="text-text-m">Last seen</dt><dd class="font-mono text-right text-text-h">{{ formatDateTime(selected.lastSeen) }}</dd>
                    </dl>
                    <h3 class="text-sm font-medium text-text-h mt-4">Triggers</h3>
                    <p class="text-sm text-text-m">{{ selected.triggers.map(t => t.replace(/_/g, ' ')).join(', ') }}</p>
                    <h3 class="text-sm font-medium text-text-h mt-4">Sources<span v-if="selected.sourceCount > selected.sources.length" class="text-text-m font-normal"> (first {{ selected.sources.length }} of {{ selected.sourceCount }})</span></h3>
                    <ul class="mt-1 text-sm space-y-1">
                        <li v-for="s in selected.sources" :key="s" class="flex items-center gap-3">
                            <span class="font-mono text-text-h">{{ s }}</span>
                            <button type="button" class="text-xs underline text-text-m hover:text-text-h" @click="investigate(s)">Attack Path</button>
                        </li>
                    </ul>
                    <p class="text-xs text-text-m mt-3">For a DNS beacon located by its client subnet, the source listed is the subnet's network address, not the resolver that reported it.</p>
                </template>
                <p v-else class="text-sm text-text-m">{{ loading ? 'Loading…' : 'Select a circle on the map for the activity at that place.' }}</p>
            </aside>

            <div class="bg-bg-surface border border-border-default rounded-lg shadow-sm overflow-hidden">
                <table class="min-w-full text-left text-sm">
                    <thead class="text-text-m bg-bg-inset">
                        <tr>
                            <th class="px-4 py-2.5 font-medium">Country</th>
                            <th class="px-4 py-2.5 font-medium text-right">Events</th>
                            <th class="px-4 py-2.5 font-medium text-right">Sources</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-if="!loading && (data?.countries.length || 0) === 0"><td colspan="3" class="px-4 py-6 text-center text-text-m">No located activity in this period.</td></tr>
                        <tr v-for="c in data?.countries || []" :key="c.countryCode" class="border-t border-border-default">
                            <td class="px-4 py-2 text-text-h"><span class="font-mono text-text-m mr-2">{{ c.countryCode }}</span>{{ c.country }}</td>
                            <td class="px-4 py-2 font-mono text-right text-text-h">{{ c.events }}</td>
                            <td class="px-4 py-2 font-mono text-right text-text-m">{{ c.sources }}</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</template>
