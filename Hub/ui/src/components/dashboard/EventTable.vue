<script setup lang="ts">
import { ref, computed, nextTick, watch, onMounted } from 'vue'
import { storeToRefs } from 'pinia'
import { useAppStore } from '../../stores/System/app.ts'
import { useEventsStore } from '../../stores/Events/events.ts'
import { useFleetStore } from '../../stores/Fleet/fleet.ts'
import { formatSensorId } from '../../utils/formatSensorId'
import { useSourcesStore, labelsOf, SOURCE_LABELS } from '../../stores/Sources/sources'
import type { SourceLabel } from '../../stores/Sources/sources'
import { techniqueUrl } from '../../stores/Attack/attack'


const appStore = useAppStore()
const eventsStore = useEventsStore()
const fleetStore = useFleetStore()

const { viewingArchive } = storeToRefs(appStore)
const { filteredEvents: rawEvents, isFetching } = storeToRefs(eventsStore)
const { nodes: fleet } = storeToRefs(fleetStore)

const sourcesStore = useSourcesStore()
const { bySource } = storeToRefs(sourcesStore)
onMounted(() => sourcesStore.fetchSources())
watch(() => eventsStore.events[0]?.id, () => sourcesStore.scheduleRefresh())

// Search and triage-label filters. Labels combine with AND: "Multi-decoy" +
// "Internal" shows internal sources that touched several decoys.
const search = ref('')
const activeLabels = ref<Set<SourceLabel>>(new Set())
// ATT&CK tactic filter: matches the tactics of the event's primary technique.
const tacticFilter = ref('')
const tacticOptions = computed(() => {
    const seen = new Map<string, string>()
    for (const e of displayEvents.value as any[]) {
        for (const t of e.attack?.primary?.tactics || []) seen.set(t.id, t.name)
    }
    return [...seen.entries()].map(([id, name]) => ({ id, name })).sort((a, b) => a.name.localeCompare(b.name))
})
const toggleLabel = (id: SourceLabel) => {
    const next = new Set(activeLabels.value)
    next.has(id) ? next.delete(id) : next.add(id)
    activeLabels.value = next
}
const clearFilters = () => { search.value = ''; activeLabels.value = new Set(); tacticFilter.value = '' }
const hasFilters = computed(() => search.value.trim() !== '' || activeLabels.value.size > 0 || tacticFilter.value !== '')

const sortCol = ref('timestamp')
const sortDesc = ref(true)
const expandedRows = ref<Set<string>>(new Set())

const currentPage = ref(1)
const itemsPerPage = ref(50)

const displayEvents = ref<any[]>([])

watch([rawEvents, isFetching], ([newEvents, fetching]) => {
    // Freeze the UI on the old data if the filter yields an empty array while fetching
    if (fetching && newEvents.length === 0 && displayEvents.value.length > 0) {
        return 
    }
    displayEvents.value = newEvents
}, { immediate: true })

// Resolve nodeId → alias for display
const getNodeAlias = (nodeId: string | null) => {
    if (!nodeId) return 'Unassigned'
    const node = fleet.value.find(n => n.id === nodeId)
    return node?.alias || nodeId
}

watch([viewingArchive, sortCol, sortDesc, () => displayEvents.value.length], () => {
    if (displayEvents.value.length === 0) currentPage.value = 1
    expandedRows.value = new Set()
})

const toggleSort = (col: string) => {
    if (sortCol.value === col) sortDesc.value = !sortDesc.value
    else { sortCol.value = col; sortDesc.value = ['timestamp', 'severity'].includes(col) }
}

const toggleRow = async (id: string) => {
    const newSet = new Set(expandedRows.value)
    const isExpanding = !newSet.has(id)
    
    if (isExpanding) {
        newSet.add(id)
        const eventTarget = displayEvents.value.find((e: any) => e.id === id)
        if (eventTarget && !eventTarget.isRead) eventsStore.markEventRead(id)
    } else {
        newSet.delete(id)
    }
    expandedRows.value = newSet

    if (isExpanding) {
        await nextTick()
        const detailsRow = document.getElementById(`details-${id}`)
        if (detailsRow) detailsRow.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
    }
}

const isDownArrow = (col: string) => {
    if (sortCol.value !== col) return true; 
    return ['timestamp', 'severity'].includes(col) ? sortDesc.value : !sortDesc.value;
}

const matchesSearch = (e: any, q: string): boolean => {
    if (!q) return true
    const hay = [e.eventTrigger, e.source, e.target, e.sensorId, e.severity, getNodeAlias(e.nodeId), e.attack?.primary?.id || '', e.attack?.primary?.name || '', JSON.stringify(e.details || {})]
        .join(' ').toLowerCase()
    return q.split(/\s+/).every(term => hay.includes(term))
}

const filteredEvents = computed(() => {
    const q = search.value.trim().toLowerCase()
    const want = [...activeLabels.value]
    const tactic = tacticFilter.value
    if (!q && want.length === 0 && !tactic) return displayEvents.value
    return displayEvents.value.filter((e: any) => {
        if (!matchesSearch(e, q)) return false
        if (tactic && !(e.attack?.primary?.tactics || []).some((t: any) => t.id === tactic)) return false
        if (want.length === 0) return true
        const labels = labelsOf(bySource.value.get(e.source))
        return want.every(l => labels.has(l))
    })
})

const sourceBadges = (source: string): { text: string; title: string; tone: string }[] => {
    const p = bySource.value.get(source)
    if (!p) return []
    const out: { text: string; title: string; tone: string }[] = []
    if (p.asset) out.push({
        text: p.asset.name,
        title: `Known asset ${p.asset.name} (${p.asset.criticality} criticality): a likely compromised internal host`,
        tone: ['critical', 'high'].includes(p.asset.criticality) ? 'alert' : 'muted'
    })
    if (p.decoys > 1) out.push({ text: `${p.decoys} decoys`, title: `Touched ${p.decoys} decoys`, tone: 'alert' })
    if (p.knownScanner) out.push({ text: 'scanner', title: 'On the known-scanner list', tone: 'muted' })
    if (p.whitelisted) out.push({ text: 'whitelisted', title: 'On the whitelist', tone: 'muted' })
    return out
}

watch([search, activeLabels, tacticFilter], () => { currentPage.value = 1 })

const sortedEvents = computed(() => {
    return [...filteredEvents.value].sort((a, b) => {
        let valA: any = (a as any)[sortCol.value] || ''
        let valB: any = (b as any)[sortCol.value] || ''
        if (sortCol.value === 'severity') {
            const scores = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }
            valA = scores[valA.toLowerCase() as keyof typeof scores] || 0
            valB = scores[valB.toLowerCase() as keyof typeof scores] || 0
        }
        if (sortCol.value === 'nodeId') {
            // Sort by alias for display consistency, fallback to nodeId
            valA = getNodeAlias(a.nodeId)
            valB = getNodeAlias(b.nodeId)
        }
        if (valA < valB) return sortDesc.value ? 1 : -1
        if (valA > valB) return sortDesc.value ? -1 : 1
        return 0
    })
})

const totalPages = computed(() => Math.ceil(sortedEvents.value.length / itemsPerPage.value) || 1)

const paginatedEvents = computed(() => {
    const start = (currentPage.value - 1) * itemsPerPage.value
    const end = start + itemsPerPage.value
    return sortedEvents.value.slice(start, end)
})

const visiblePages = computed(() => {
    const total = totalPages.value;
    const current = currentPage.value;
    if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
    if (current <= 4) return [1, 2, 3, 4, 5, '...', total];
    if (current >= total - 3) return [1, '...', total - 4, total - 3, total - 2, total - 1, total];
    return [1, '...', current - 1, current, current + 1, '...', total];
});

const prevPage = () => { if (currentPage.value > 1) currentPage.value-- }
const nextPage = () => { if (currentPage.value < totalPages.value) currentPage.value++ }

const goToPage = (page: number | string) => {
    if (typeof page === 'number') {
        currentPage.value = page
    }
}

const handleArchiveAll = async () => {
    if (!confirm('Archive all currently active events?')) return
    const res = await eventsStore.archiveAll()
    if (!res.success) alert(res.error)
}

const handleArchiveEvent = async (eventId: string) => {
    const res = await eventsStore.archiveEvent(eventId)
    if (!res.success) alert(res.error)
}

// Formatters
const formatEventType = (type: string) => type ? type.replace(/_/g, ' ') : ''
const formatString = (str: string | number) => str ? String(str).replace(/_/g, ' ') : ''
const formatJson = (val: any) => {
    if (val === null) return 'null'
    if (val === undefined) return 'undefined'
    return typeof val === 'object' ? JSON.stringify(val, null, 2) : String(val)
}
const getDataType = (val: any) => {
    if (val === null || val === undefined) return 'primitive'
    if (Array.isArray(val)) {
        if (val.length > 0 && typeof val[0] === 'object' && val[0] !== null) return 'object_array'
        return 'primitive_array'
    }
    if (typeof val === 'object') return 'object'
    return 'primitive'
}
const handleExport = () => {
    const url = new URL('/api/v2/events/export', window.location.origin)
    url.searchParams.append('archived', viewingArchive.value ? 'true' : 'false')
    if (fleetStore.selectedNodeId) url.searchParams.append('nodeId', fleetStore.selectedNodeId)
    if (fleetStore.selectedSensorId) url.searchParams.append('sensorId', fleetStore.selectedSensorId)
    const a = document.createElement('a')
    a.href = url.toString()
    a.download = 'truesignal_events.json'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
}

const formatTime = (timestamp: string) => {
    if (!timestamp) return ''
    const dateObj = new Date(timestamp)
    const now = new Date()

    const isToday = 
        dateObj.getDate() === now.getDate() && 
        dateObj.getMonth() === now.getMonth() && 
        dateObj.getFullYear() === now.getFullYear()

    if (isToday) {
        return new Intl.DateTimeFormat('default', {
            hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false 
        }).format(dateObj)
    }

    return new Intl.DateTimeFormat('default', {
        month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false 
    }).format(dateObj)
}
</script>

<template>
    <div class="bg-bg-surface border border-border-default rounded-lg overflow-hidden flex flex-col shadow-sm w-full relative z-0">
        
        <div class="pl-5 pr-4 py-3 border-b border-border-default flex justify-between items-center bg-bg-surface shrink-0">
            <div class="flex items-center gap-3">
                <h3 class="text-base font-medium text-text-h">
                    {{ viewingArchive ? 'Archived Events' : 'Active Threat Queue' }}
                </h3>
                <div v-show="!viewingArchive" class="hidden sm:flex items-center gap-2">
                    <span class="w-1.5 h-1.5 rounded-full bg-success-main animate-pulse shadow-[0_0_8px_var(--color-success-main)]"></span>
                    <span class="text-sm tracking-wide text-text-m">Live</span>
                </div>
            </div>
            
            <div class="flex items-center gap-2">
                <button v-show="displayEvents.length > 0" @click="handleExport"
                        type="button"
                        title="Export JSON"
                        aria-label="Export all events as JSON"
                        class="p-1.5 rounded-md text-text-m transition-colors outline-none hover:bg-secondary-hover hover:text-text-h active:scale-95">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
                </button>
                <button v-show="!viewingArchive && displayEvents.length > 0" @click="handleArchiveAll"
                        type="button"
                        aria-label="Archive all active events"
                        class="px-2.5 py-1 rounded-md text-base transition-colors shadow-sm border outline-none bg-secondary-main text-secondary-text border-secondary-border hover:bg-archive-bg hover:text-archive-text hover:border-archive-border active:scale-95">
                    Archive All
                </button>
            </div>
        </div>

        <div class="px-5 py-3 border-b border-border-default flex flex-wrap items-center gap-2 bg-bg-surface shrink-0">
            <label class="relative flex-[1_1_240px] max-w-sm">
                <span class="sr-only">Search events</span>
                <svg class="w-4 h-4 absolute left-2.5 top-1/2 -translate-y-1/2 text-text-l pointer-events-none" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-4.35-4.35M17 10.5a6.5 6.5 0 11-13 0 6.5 6.5 0 0113 0z"></path></svg>
                <input v-model="search" type="search" placeholder="Search trigger, source, target, sensor, node, details"
                       class="w-full pl-8 pr-3 py-1.5 text-sm bg-input-bg border border-input-border rounded-md outline-none focus:border-primary-main focus:ring-1 focus:ring-focus-ring text-text-h" />
            </label>
            <div class="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter by source label">
                <button v-for="l in SOURCE_LABELS" :key="l.id" type="button" :title="l.hint"
                        :aria-pressed="activeLabels.has(l.id)"
                        @click="toggleLabel(l.id)"
                        class="px-2.5 py-1 rounded-full text-xs border transition-colors outline-none"
                        :class="activeLabels.has(l.id)
                            ? 'bg-primary-selected text-primary-text border-primary-border'
                            : 'bg-secondary-main text-secondary-text border-secondary-border hover:bg-secondary-hover'">
                    {{ l.text }}
                </button>
            </div>
            <label class="flex items-center">
                <span class="sr-only">Filter by ATT&amp;CK tactic</span>
                <select v-model="tacticFilter"
                        class="px-2.5 py-1 text-xs rounded-full border bg-secondary-main text-secondary-text border-secondary-border outline-none focus:border-primary-main"
                        :class="tacticFilter ? '!bg-primary-selected !text-primary-text !border-primary-border' : ''">
                    <option value="">All ATT&amp;CK tactics</option>
                    <option v-for="t in tacticOptions" :key="t.id" :value="t.id">{{ t.name }}</option>
                </select>
            </label>
            <div v-if="hasFilters" class="flex items-center gap-2 ml-auto">
                <span class="text-xs text-text-m font-mono">{{ filteredEvents.length }} / {{ displayEvents.length }}</span>
                <button type="button" @click="clearFilters" class="text-xs text-text-m hover:text-text-h underline underline-offset-2">Clear</button>
            </div>
        </div>

        <div class="overflow-x-auto overflow-y-auto custom-scroll max-h-[600px] lg:max-h-[700px] flex-1 after:content-[''] after:block after:h-4 after:shrink-0">
            <table class="min-w-full text-left border-separate border-spacing-0">
                <thead class="text-base text-text-m sticky top-0 bg-bg-surface z-30 shadow-[0_1px_0_0_var(--color-border-default)] select-none">
                    <tr>
                        <th class="px-3 py-3 w-8"></th>
                        <th @click="toggleSort('severity')" class="px-3 py-3 cursor-pointer hover:text-text-h transition-colors group" role="button" tabindex="0" aria-label="Sort by threat severity">
                            <div class="flex items-center gap-1.5">Threat
                                <svg class="w-3 h-3 transition-transform duration-normal" :class="[sortCol === 'severity' ? 'opacity-100 text-highlight-border' : 'opacity-0 group-hover:opacity-50 text-text-m', isDownArrow('severity') ? 'rotate-180' : '']" viewBox="0 0 384 512" fill="currentColor"><path d="M214.6 41.4c-12.5-12.5-32.8-12.5-45.3 0l-160 160c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0L160 141.2V448c0 17.7 14.3 32 32 32s32-14.3 32-32V141.2L329.4 246.6c12.5 12.5 32.8 12.5 45.3 0s12.5-32.8 0-45.3l-160-160z"></path></svg>
                            </div>
                        </th>
                        <th @click="toggleSort('eventTrigger')" class="px-4 py-3 cursor-pointer hover:text-text-h transition-colors group" role="button" tabindex="0" aria-label="Sort by event trigger type">
                            <div class="flex items-center gap-1.5">Event Trigger
                                <svg class="w-3 h-3 transition-transform duration-normal" :class="[sortCol === 'eventTrigger' ? 'opacity-100 text-highlight-border' : 'opacity-0 group-hover:opacity-50 text-text-m', isDownArrow('eventTrigger') ? 'rotate-180' : '']" viewBox="0 0 384 512" fill="currentColor"><path d="M214.6 41.4c-12.5-12.5-32.8-12.5-45.3 0l-160 160c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0L160 141.2V448c0 17.7 14.3 32 32 32s32-14.3 32-32V141.2L329.4 246.6c12.5 12.5 32.8 12.5 45.3 0s12.5-32.8 0-45.3l-160-160z"></path></svg>
                            </div>
                        </th>
                        <th @click="toggleSort('source')" class="px-4 py-3 cursor-pointer hover:text-text-h transition-colors group" role="button" tabindex="0" aria-label="Sort by source">
                            <div class="flex items-center gap-1.5">Source
                                <svg class="w-3 h-3 transition-transform duration-normal" :class="[sortCol === 'source' ? 'opacity-100 text-highlight-border' : 'opacity-0 group-hover:opacity-50 text-text-m', isDownArrow('source') ? 'rotate-180' : '']" viewBox="0 0 384 512" fill="currentColor"><path d="M214.6 41.4c-12.5-12.5-32.8-12.5-45.3 0l-160 160c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0L160 141.2V448c0 17.7 14.3 32 32 32s32-14.3 32-32V141.2L329.4 246.6c12.5 12.5 32.8 12.5 45.3 0s12.5-32.8 0-45.3l-160-160z"></path></svg>
                            </div>
                        </th>
                        <th @click="toggleSort('target')" class="px-4 py-3 cursor-pointer hover:text-text-h transition-colors group" role="button" tabindex="0" aria-label="Sort by target">
                            <div class="flex items-center gap-1.5">Target
                                <svg class="w-3 h-3 transition-transform duration-normal" :class="[sortCol === 'target' ? 'opacity-100 text-highlight-border' : 'opacity-0 group-hover:opacity-50 text-text-m', isDownArrow('target') ? 'rotate-180' : '']" viewBox="0 0 384 512" fill="currentColor"><path d="M214.6 41.4c-12.5-12.5-32.8-12.5-45.3 0l-160 160c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0L160 141.2V448c0 17.7 14.3 32 32 32s32-14.3 32-32V141.2L329.4 246.6c12.5 12.5 32.8 12.5 45.3 0s12.5-32.8 0-45.3l-160-160z"></path></svg>
                            </div>
                        </th>
                        
                        <th @click="toggleSort('sensorId')" class="px-4 py-3 cursor-pointer hover:text-text-h transition-colors group" role="button" tabindex="0" aria-label="Sort by sensor id">
                            <div class="flex items-center gap-1.5">Sensor
                                <svg class="w-3 h-3 transition-transform duration-normal" :class="[sortCol === 'sensorId' ? 'opacity-100 text-highlight-border' : 'opacity-0 group-hover:opacity-50 text-text-m', isDownArrow('sensorId') ? 'rotate-180' : '']" viewBox="0 0 384 512" fill="currentColor"><path d="M214.6 41.4c-12.5-12.5-32.8-12.5-45.3 0l-160 160c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0L160 141.2V448c0 17.7 14.3 32 32 32s32-14.3 32-32V141.2L329.4 246.6c12.5 12.5 32.8 12.5 45.3 0s12.5-32.8 0-45.3l-160-160z"></path></svg>
                            </div>
                        </th>

                        <th @click="toggleSort('nodeId')" class="px-4 py-3 text-right cursor-pointer hover:text-text-h transition-colors group" role="button" tabindex="0" aria-label="Sort by node">
                            <div class="flex items-center justify-end gap-1.5">Node
                                <svg class="w-3 h-3 transition-transform duration-normal" :class="[sortCol === 'nodeId' ? 'opacity-100 text-highlight-border' : 'opacity-0 group-hover:opacity-50 text-text-m', isDownArrow('nodeId') ? 'rotate-180' : '']" viewBox="0 0 384 512" fill="currentColor"><path d="M214.6 41.4c-12.5-12.5-32.8-12.5-45.3 0l-160 160c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0L160 141.2V448c0 17.7 14.3 32 32 32s32-14.3 32-32V141.2L329.4 246.6c12.5 12.5 32.8 12.5 45.3 0s12.5-32.8 0-45.3l-160-160z"></path></svg>
                            </div>
                        </th>

                        <th @click="toggleSort('timestamp')" class="px-5 py-3 text-right cursor-pointer hover:text-text-h transition-colors group" role="button" tabindex="0" aria-label="Sort by timestamp">
                            <div class="flex items-center justify-end gap-1.5">Time
                                <svg class="w-3 h-3 transition-transform duration-normal" :class="[sortCol === 'timestamp' ? 'opacity-100 text-highlight-border' : 'opacity-0 group-hover:opacity-50 text-text-m', isDownArrow('timestamp') ? 'rotate-180' : '']" viewBox="0 0 384 512" fill="currentColor"><path d="M214.6 41.4c-12.5-12.5-32.8-12.5-45.3 0l-160 160c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0L160 141.2V448c0 17.7 14.3 32 32 32s32-14.3 32-32V141.2L329.4 246.6c12.5 12.5 32.8 12.5 45.3 0s12.5-32.8 0-45.3l-160-160z"></path></svg>
                            </div>
                        </th>
                        <th v-if="!viewingArchive" class="px-4 py-3 w-16"></th>
                    </tr>
                </thead>
                
                <tbody class="relative z-0">
                    <tr v-if="filteredEvents.length === 0 && !isFetching">
                        <td :colspan="viewingArchive ? 8 : 9" class="px-5 py-8 border-b border-border-default text-center text-text-m text-base">
                            {{ displayEvents.length > 0 ? 'No events match the filters.' : 'No events.' }}
                        </td>
                    </tr>
                    
                    <template v-for="event in paginatedEvents" :key="event.id">
                        <tr class="hover:bg-secondary-hover cursor-pointer transition-colors duration-[var(--duration-fast)] relative z-0 group"
                            :class="[ 'bleed-' + event.severity.toLowerCase(), expandedRows.has(event.id) ? 'bg-bg-base' : '' ]"
                            @click="toggleRow(event.id)">
                            
                            <td class="px-3 py-3 border-l-[3px] text-text-m transition-all duration-[var(--duration-fast)]" 
                                :class="expandedRows.has(event.id) ? 'border-b border-transparent' : 'border-b border-border-default'"
                                :style="{ borderLeftColor: event.severity ? `var(--color-${event.severity.toLowerCase()})` : 'transparent' }">
                                <svg class="w-4 h-4 transition-transform duration-normal" :class="expandedRows.has(event.id) ? 'rotate-90 text-text-h' : 'group-hover:text-text-h'" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
                            </td>

                            <td class="px-3 py-3 flex items-center gap-3" :class="expandedRows.has(event.id) ? 'border-b border-transparent' : 'border-b border-border-default'">
                                <div v-show="!event.isRead" class="w-1.5 h-1.5 rounded-full bg-danger-main shrink-0 animate-pulse"></div>
                                <span class="px-2 py-0.5 rounded border text-base bg-bg-surface whitespace-nowrap capitalize" 
                                      :style="{ borderColor: `var(--color-${event.severity.toLowerCase()})`, color: `var(--color-${event.severity.toLowerCase()})` }">
                                    {{ event.severity }}
                                </span>
                            </td>
                            
                            <td class="px-4 py-3 text-base font-base text-text-h capitalize max-w-[140px] md:max-w-[200px] lg:max-w-md xl:max-w-2xl 2xl:max-w-none truncate" :class="expandedRows.has(event.id) ? 'border-b border-transparent' : 'border-b border-border-default'" :title="formatEventType(event.eventTrigger)">
                                {{ formatEventType(event.eventTrigger) }}
                                <span v-if="event.attack" class="hidden 2xl:inline ml-1.5 px-1.5 py-px rounded text-xs font-mono normal-case border border-border-default text-text-m"
                                      :title="`MITRE ATT&CK ${event.attack.primary.id} ${event.attack.primary.name} (${event.attack.primary.tactics.map((t: any) => t.name).join(', ')})`">{{ event.attack.primary.id }}</span>
                            </td>
                            
                            <td class="px-4 py-3 text-base text-text-m font-mono max-w-[160px] md:max-w-[240px] lg:max-w-sm xl:max-w-xl 2xl:max-w-none" :class="expandedRows.has(event.id) ? 'border-b border-transparent' : 'border-b border-border-default'" :title="event.source">
                                <!-- Address (never truncated) and its event count; triage badges on a second line. -->
                                <div class="flex items-center gap-1.5 min-w-0">
                                    <span class="shrink-0 max-w-full truncate">{{ event.source }}</span>
                                    <span v-if="(bySource.get(event.source)?.events || 0) > 1" class="shrink-0 text-xs text-text-l" :title="`${bySource.get(event.source)?.events} events from this source`">×{{ bySource.get(event.source)?.events }}</span>
                                </div>
                                <div v-if="sourceBadges(event.source).length" class="flex items-center gap-1 mt-1 min-w-0 overflow-hidden">
                                    <span v-for="b in sourceBadges(event.source).slice(0, 1)" :key="b.text" :title="b.title"
                                          class="shrink-0 max-w-[130px] truncate px-1.5 py-px rounded text-xs font-sans border"
                                          :class="b.tone === 'alert' ? 'text-critical border-critical/40' : 'text-text-m border-border-default'">{{ b.text }}</span>
                                    <span v-if="sourceBadges(event.source).length > 1" class="shrink-0 text-xs font-sans text-text-l"
                                          :title="sourceBadges(event.source).slice(1).map(b => b.title).join('\n')">+{{ sourceBadges(event.source).length - 1 }}</span>
                                </div>
                            </td>
                            <td class="px-4 py-3 text-base text-text-m font-mono max-w-[120px] md:max-w-[180px] lg:max-w-sm xl:max-w-xl 2xl:max-w-none truncate" :class="expandedRows.has(event.id) ? 'border-b border-transparent' : 'border-b border-border-default'" :title="event.target">{{ event.target }}</td>
                            
                            <td class="px-4 py-3 text-base text-text-h font-mono max-w-[140px] md:max-w-[200px] lg:max-w-sm xl:max-w-xl 2xl:max-w-none truncate" :class="expandedRows.has(event.id) ? 'border-b border-transparent' : 'border-b border-border-default'" :title="event.sensorId">{{ formatSensorId(event.sensorId) }}</td>
                            
                            <td class="px-4 py-3 text-base font-medium text-right text-text-h font-mono w-[130px] min-w-[130px] max-w-[130px] truncate" :class="expandedRows.has(event.id) ? 'border-b border-transparent' : 'border-b border-border-default'" :title="event.nodeId || 'Unassigned'">{{ getNodeAlias(event.nodeId) }}</td>
                            
                            <td class="px-5 py-3 text-base text-right text-text-m font-mono whitespace-nowrap" :class="expandedRows.has(event.id) ? 'border-b border-transparent' : 'border-b border-border-default'" :title="event.timestamp">{{ formatTime(event.timestamp) }}</td>
                            
                            <td v-if="!viewingArchive" class="px-4 py-2 text-right w-16" :class="expandedRows.has(event.id) ? 'border-b border-transparent' : 'border-b border-border-default'">
                                <button @click.stop="handleArchiveEvent(event.id)"                                     
                                        type="button"
                                        aria-label="Archive this event"                                        
                                        class="flex items-center justify-center w-6 h-6 ml-auto rounded-md transition-all duration-[var(--duration-fast)] shadow-sm active:scale-95 border outline-none bg-secondary-main text-secondary-text border-secondary-border hover:bg-archive-bg hover:text-archive-text hover:border-archive-border"
                                        title="Archive Event">
                                    <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                        <path d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4"></path>
                                    </svg>
                                </button>
                            </td>
                        </tr>

                       <tr v-if="expandedRows.has(event.id)" :id="'details-' + event.id">
                            <td :colspan="viewingArchive ? 8 : 9" class="p-0 border-b border-border-default bg-bg-base">
                                <div class="pl-11 pr-5 pb-5 pt-2">
                                    
                                    <div class="px-6 py-5 bg-bg-surface border border-border-default rounded-lg shadow-sm relative overflow-hidden w-fit max-w-full">
                                        <div class="absolute left-0 top-0 bottom-0 w-1" :style="{ backgroundColor: event.severity ? `var(--color-${event.severity.toLowerCase()})` : 'transparent' }"></div>
                                        
                                        <div class="mb-5 flex flex-col gap-1.5 text-sm">
                                            <div>
                                                <router-link :to="{ path: '/path', query: { source: event.source } }" class="text-highlight-text underline underline-offset-2" @click.stop>Investigate {{ event.source }} in Attack Path →</router-link>
                                            </div>
                                            <div v-if="event.attack" class="text-text-h">
                                                <span class="text-text-m">MITRE ATT&amp;CK</span>
                                                <a :href="techniqueUrl(event.attack.primary.id)" target="_blank" rel="noopener noreferrer" class="ml-2 font-mono underline underline-offset-2 text-highlight-text" @click.stop>{{ event.attack.primary.id }}</a>
                                                {{ event.attack.primary.name }}
                                                <span class="text-text-m">({{ event.attack.primary.tactics.map((t: any) => t.name).join(', ') }})</span>
                                                <span v-if="event.attack.secondary?.length" class="text-text-m"> · also {{ event.attack.secondary.map((t: any) => `${t.id} ${t.name}`).join(', ') }}</span>
                                            </div>
                                            <div v-if="bySource.get(event.source)?.asset" class="text-text-h">
                                                <span class="text-text-m">Source asset</span>
                                                <span class="ml-2 font-medium">{{ bySource.get(event.source)!.asset!.name }}</span>
                                                <span class="text-text-m"> ({{ bySource.get(event.source)!.asset!.criticality }} criticality): likely compromised internal host</span>
                                            </div>
                                            <div v-if="event.sourceGeo" class="text-text-h">
                                                <span class="text-text-m">Location</span>
                                                <span class="ml-2">{{ [event.sourceGeo.city, event.sourceGeo.region, event.sourceGeo.country].filter(Boolean).join(', ') }}</span>
                                                <span class="text-text-m font-mono"> {{ event.sourceGeo.countryCode }}</span>
                                                <span v-if="event.sourceGeo.basis === 'client_subnet'" class="text-text-m"> (from the beacon's client subnet {{ event.sourceGeo.address }}, not the resolver)</span>
                                                <router-link to="/map" class="ml-2 text-highlight-text underline underline-offset-2" @click.stop>Map →</router-link>
                                            </div>
                                        </div>
                                        <div class="flex flex-wrap gap-x-6 gap-y-6">
                                            
                                            <div v-for="(val, key) in event.details" :key="key" class="flex flex-col group w-fit min-w-[120px] max-w-full">
                                                <div class="flex items-center gap-1.5 mb-2">
                                                    <span class="w-1 h-1 rounded-full bg-border-default transition-colors group-hover:bg-highlight-border shrink-0"></span>
                                                    <span class="text-sm font-medium text-text-m capitalize truncate">{{ formatString(key) }}</span>
                                                </div>
                                                
                                                <div v-if="getDataType(val) === 'primitive_array'" class="flex flex-wrap gap-2">
                                                    <span v-for="(item, i) in val" :key="i" class="px-2 py-1 bg-bg-inset border border-border-default rounded text-base text-text-h font-mono break-all shadow-sm">
                                                        {{ String(item) }}
                                                    </span>
                                                </div>
                                                
                                                <div v-else-if="getDataType(val) === 'object_array'" class="flex flex-col gap-2">
                                                    <div v-for="(obj, i) in val" :key="i" class="bg-bg-inset border border-border-default rounded p-3 text-base font-mono shadow-inner overflow-x-auto w-fit max-w-full">
                                                        <div class="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1.5">
                                                            <template v-for="(subVal, subKey) in obj" :key="subKey">
                                                                <div class="text-text-m whitespace-nowrap">{{ subKey }}:</div>
                                                                <div class="text-text-h break-words whitespace-pre-wrap">{{ formatJson(subVal) }}</div>
                                                            </template>
                                                        </div>
                                                    </div>
                                                </div>
                                                
                                                <div v-else-if="getDataType(val) === 'object'" class="bg-bg-inset border border-border-default rounded p-3 text-base font-mono shadow-inner overflow-x-auto w-fit max-w-full">
                                                    <div class="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2">
                                                        <template v-for="(subVal, subKey) in val" :key="subKey">
                                                            <div class="text-text-m whitespace-nowrap border-b border-border-default pb-1.5">{{ subKey }}</div>
                                                            <div class="text-text-h break-words whitespace-pre-wrap border-b border-border-default pb-1.5">{{ formatJson(subVal) }}</div>
                                                        </template>
                                                    </div>
                                                </div>
                                                
                                                <div v-else class="bg-bg-inset border border-border-default rounded px-3 py-2 text-base text-text-h font-mono whitespace-pre-wrap break-words shadow-inner w-fit max-w-full inline-block">
                                                    {{ String(val) }}
                                                </div>
                                            </div>
                                            
                                        </div>
                                        <div class="mt-5 pt-3 border-t border-border-default flex justify-between items-center text-sm text-text-m font-mono">
                                            <div class="flex items-center gap-2">
                                                <span>Trace ID: {{ event.id }}</span>
                                            </div>
                                        </div>
                                    </div>
                                    
                                </div>
                            </td>
                        </tr>
                    </template>
                </tbody>
            </table>
        </div>

        <div v-if="sortedEvents.length > itemsPerPage" class="flex items-center justify-between border-t border-border-default bg-bg-surface px-4 py-3 sm:px-5 shrink-0">
            <div class="flex flex-1 justify-between sm:hidden">
                <button @click="prevPage" :disabled="currentPage === 1"
                        type="button"
                        class="relative inline-flex items-center rounded-md border border-border-default bg-bg-surface px-4 py-2 text-base text-text-h hover:bg-secondary-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
                    Previous
                </button>
                <button @click="nextPage" :disabled="currentPage === totalPages"
                        type="button"
                        class="relative ml-3 inline-flex items-center rounded-md border border-border-default bg-bg-surface px-4 py-2 text-base text-text-h hover:bg-secondary-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
                    Next
                </button>
            </div>
            <div class="hidden sm:flex sm:flex-1 sm:items-center sm:justify-between">
                <div>
                    <p class="text-base text-text-m">
                        Showing <span class="font-medium text-text-h">{{ (currentPage - 1) * itemsPerPage + 1 }}</span> to <span class="font-medium text-text-h">{{ Math.min(currentPage * itemsPerPage, sortedEvents.length) }}</span> of <span class="font-medium text-text-h">{{ sortedEvents.length }}</span> events
                    </p>
                </div>
                <div>
                    <nav class="isolate inline-flex -space-x-px rounded-md shadow-sm" aria-label="Pagination">
                        <button @click="prevPage" :disabled="currentPage === 1" 
                                class="relative inline-flex items-center rounded-l-md px-2 py-1.5 border border-border-default bg-bg-surface text-text-m hover:bg-secondary-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors focus:z-20 outline-none">
                            <span class="sr-only">Previous</span>
                            <svg class="w-4 h-4" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" d="M11.78 5.22a.75.75 0 0 1 0 1.06L8.06 10l3.72 3.72a.75.75 0 1 1-1.06 1.06l-4.25-4.25a.75.75 0 0 1 0-1.06l4.25-4.25a.75.75 0 0 1 1.06 0Z" clip-rule="evenodd" /></svg>
                        </button>
                        <template v-for="(page, idx) in visiblePages" :key="idx">
                            <span v-if="page === '...'" 
                                  class="relative inline-flex items-center px-3.5 py-1.5 text-base text-text-m border border-border-default bg-bg-surface">
                                ...
                            </span>
                            <button v-else @click="goToPage(page)"
                                    class="relative inline-flex items-center px-3.5 py-1.5 text-base border border-border-default transition-colors focus:z-20 outline-none"
                                    :class="currentPage === page ? 'z-10 bg-primary-selected text-primary-text shadow-inner border-primary-selected' : 'bg-bg-surface text-text-m hover:bg-secondary-hover hover:text-text-h'">
                                {{ page }}
                            </button>
                        </template>
                        <button @click="nextPage" :disabled="currentPage === totalPages" 
                                class="relative inline-flex items-center rounded-r-md px-2 py-1.5 border border-border-default bg-bg-surface text-text-m hover:bg-secondary-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors focus:z-20 outline-none">
                            <span class="sr-only">Next</span>
                            <svg class="w-4 h-4" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                <path fill-rule="evenodd" d="M8.22 5.22a.75.75 0 0 1 1.06 0l4.25 4.25a.75.75 0 0 1 0 1.06l-4.25 4.25a.75.75 0 0 1-1.06-1.06L11.94 10 8.22 6.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" />
                            </svg>
                        </button>
                    </nav>
                </div>
            </div>
        </div>
    </div>
</template>