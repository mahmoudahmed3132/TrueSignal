<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { storeToRefs } from 'pinia'
import { api } from '../api/client'
import { useSourcesStore } from '../stores/Sources/sources'
import { parseCsv, toCsv } from '../utils/csv'
import { isAddrOrCidr } from '../utils/ipTokens'
import PageHeader from '../components/ui/layout/PageHeader.vue'
import BaseButton from '../components/ui/forms/BaseButton.vue'

// Inventory of protected hosts and ranges. A decoy touched from one of
// them names the real host that is likely compromised; events and the SIEM
// carry the asset name and criticality. The Hub validates on save.
interface Asset { name: string; address: string; criticality: string; owner: string; tags: string[] }

const CRITICALITIES = ['low', 'medium', 'high', 'critical']

const sourcesStore = useSourcesStore()
const { profiles } = storeToRefs(sourcesStore)

const saved = ref<Asset[]>([])
const rows = ref<Asset[]>([])
const loading = ref(true)
const saving = ref(false)
const message = ref('')
const isError = ref(false)
const search = ref('')
const fileInput = ref<HTMLInputElement | null>(null)

const draft = ref<Asset>({ name: '', address: '', criticality: 'medium', owner: '', tags: [] })
const draftTags = ref('')

const load = async () => {
    loading.value = true
    try {
        const res = await api.get('/api/v2/assets')
        saved.value = ((await res.json()).assets || []) as Asset[]
        rows.value = JSON.parse(JSON.stringify(saved.value))
    } catch (e: any) {
        isError.value = true
        message.value = e?.message || 'Failed to load assets'
    } finally {
        loading.value = false
    }
}
onMounted(() => { load(); sourcesStore.fetchSources() })

const dirty = computed(() => JSON.stringify(rows.value) !== JSON.stringify(saved.value))

// Attacker activity per asset, from the source profiles.
const activity = computed(() => {
    const m = new Map<string, { events: number; sources: number }>()
    for (const p of profiles.value) {
        if (!p.asset) continue
        const a = m.get(p.asset.name) || { events: 0, sources: 0 }
        a.events += p.events
        a.sources += 1
        m.set(p.asset.name, a)
    }
    return m
})

const filtered = computed(() => {
    const q = search.value.trim().toLowerCase()
    const list = rows.value.map((a, i) => ({ a, i }))
    if (!q) return list
    return list.filter(({ a }) => [a.name, a.address, a.owner, a.criticality, ...a.tags].join(' ').toLowerCase().includes(q))
})

const flash = (msg: string, err = false) => {
    message.value = msg
    isError.value = err
    if (!err) setTimeout(() => { if (message.value === msg) message.value = '' }, 4000)
}

const addDraft = () => {
    const d = draft.value
    if (!d.name.trim() || !isAddrOrCidr(d.address.trim())) {
        flash('Name and a valid IP or CIDR range are required.', true)
        return
    }
    rows.value.push({ ...d, name: d.name.trim(), address: d.address.trim(), owner: d.owner.trim(), tags: draftTags.value.split(/[;,]/).map(t => t.trim()).filter(Boolean) })
    draft.value = { name: '', address: '', criticality: 'medium', owner: '', tags: [] }
    draftTags.value = ''
    message.value = ''
}

const remove = (i: number) => rows.value.splice(i, 1)

const save = async () => {
    saving.value = true
    try {
        const res = await api.put('/api/v2/assets', { assets: rows.value })
        saved.value = ((await res.json()).assets || []) as Asset[]
        rows.value = JSON.parse(JSON.stringify(saved.value))
        flash(`Saved ${saved.value.length} assets.`)
        sourcesStore.fetchSources()
    } catch (e: any) {
        flash(e?.message || 'Save failed', true)
    } finally {
        saving.value = false
    }
}

const discard = () => { rows.value = JSON.parse(JSON.stringify(saved.value)); message.value = '' }

// CSV columns: name,address,criticality,owner,tags (tags separated by ";").
// A header row is detected and skipped. Imported rows are appended; rows
// whose address is already in the inventory are skipped.
const onImport = async (ev: Event) => {
    const input = ev.target as HTMLInputElement
    const file = input.files?.[0]
    input.value = ''
    if (!file) return
    if (file.size > 2 * 1024 * 1024) return flash('File is larger than 2 MB.', true)
    const parsed = parseCsv(await file.text())
    if (parsed.length && /name/i.test(parsed[0][0] || '') && /address|ip/i.test(parsed[0][1] || '')) parsed.shift()
    const existing = new Set(rows.value.map(r => r.address))
    let added = 0, skipped = 0, invalid = 0
    for (const r of parsed) {
        const [name = '', address = '', criticality = '', owner = '', tags = ''] = r.map(c => c.trim())
        if (!name || !isAddrOrCidr(address)) { invalid++; continue }
        if (existing.has(address)) { skipped++; continue }
        existing.add(address)
        rows.value.push({
            name, address, owner,
            criticality: CRITICALITIES.includes(criticality.toLowerCase()) ? criticality.toLowerCase() : 'medium',
            tags: tags.split(';').map(t => t.trim()).filter(Boolean)
        })
        added++
    }
    flash(`${added} assets added from ${file.name}` + (skipped ? `, ${skipped} duplicates skipped` : '') + (invalid ? `, ${invalid} invalid rows skipped` : '') + '. Save to apply.', added === 0)
}

const exportCsv = () => {
    const csv = toCsv([['name', 'address', 'criticality', 'owner', 'tags'], ...saved.value.map(a => [a.name, a.address, a.criticality, a.owner, a.tags.join(';')])])
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
    const a = document.createElement('a')
    a.href = url
    a.download = 'truesignal-assets.csv'
    a.click()
    URL.revokeObjectURL(url)
}

const critClass = (c: string) => ({
    critical: 'text-critical border-critical bg-danger-bg',
    high: 'text-high border-high',
    medium: 'text-text-h border-border-default',
    low: 'text-text-m border-border-default'
} as Record<string, string>)[c] || 'text-text-m border-border-default'

const inputCls = 'px-2.5 py-1.5 text-sm bg-input-bg border border-input-border rounded-md outline-none focus:border-primary-main text-text-h'
</script>

<template>
    <div class="min-h-full flex flex-col gap-4 sm:gap-6 max-w-[1600px] w-full mx-auto px-2 sm:px-4 lg:px-6 py-4 sm:py-6">
        <div class="flex flex-wrap items-end justify-between gap-4">
            <PageHeader
                title="Assets"
                description="Your real hosts and ranges, with criticality and owner. When a decoy is touched from an inventoried address, the event, the dashboard and the SIEM name that asset: it is the host to investigate first. Inventoried addresses count as internal even in public space."
            />
            <div class="flex items-center gap-3 mb-[var(--space-flow)]">
                <span v-if="dirty" class="text-sm text-archive-text">Unsaved changes</span>
                <BaseButton v-if="dirty" variant="secondary" @click="discard">Discard</BaseButton>
                <BaseButton variant="primary" :disabled="!dirty || saving" @click="save">{{ saving ? 'Saving…' : 'Save' }}</BaseButton>
            </div>
        </div>

        <div v-if="message" role="status" class="text-sm px-3 py-2 rounded-md border w-fit"
             :class="isError ? 'bg-danger-bg text-danger-text border-danger-border' : 'bg-success-bg text-success-text border-success-border'">{{ message }}</div>

        <div class="bg-bg-surface border border-border-default rounded-lg shadow-sm overflow-hidden">
            <div class="px-5 py-3 border-b border-border-default flex flex-wrap items-center gap-3">
                <span class="text-base text-text-h font-medium">{{ rows.length }} assets</span>
                <input v-model="search" type="search" placeholder="Search name, address, owner, tag" aria-label="Search assets"
                       class="flex-[1_1_220px] max-w-xs ml-auto" :class="inputCls" />
                <BaseButton variant="secondary" class="!py-1.5 !px-3 !text-sm" @click="fileInput?.click()">Import CSV…</BaseButton>
                <input ref="fileInput" type="file" accept=".csv,text/csv" class="hidden" @change="onImport" />
                <BaseButton variant="secondary" class="!py-1.5 !px-3 !text-sm" :disabled="saved.length === 0" @click="exportCsv">Export CSV</BaseButton>
            </div>

            <form class="px-5 py-3 border-b border-border-default bg-bg-base flex flex-wrap items-end gap-2" @submit.prevent="addDraft">
                <label class="flex flex-col gap-1 text-xs text-text-m">Name<input v-model="draft.name" :class="inputCls" placeholder="pg-primary" /></label>
                <label class="flex flex-col gap-1 text-xs text-text-m">IP or CIDR<input v-model="draft.address" :class="inputCls" class="font-mono" placeholder="10.20.4.17" /></label>
                <label class="flex flex-col gap-1 text-xs text-text-m">Criticality
                    <select v-model="draft.criticality" :class="inputCls"><option v-for="c in CRITICALITIES" :key="c" :value="c">{{ c }}</option></select>
                </label>
                <label class="flex flex-col gap-1 text-xs text-text-m">Owner<input v-model="draft.owner" :class="inputCls" placeholder="Payments team" /></label>
                <label class="flex flex-col gap-1 text-xs text-text-m">Tags (; separated)<input v-model="draftTags" :class="inputCls" placeholder="pci;prod" /></label>
                <BaseButton type="submit" variant="secondary" class="!py-1.5 !px-3 !text-sm">Add</BaseButton>
                <span class="text-xs text-text-l basis-full">CSV import columns: name, address, criticality, owner, tags (tags separated by ";"). A header row is skipped.</span>
            </form>

            <div class="overflow-x-auto">
                <table class="min-w-full text-left text-sm">
                    <thead class="text-text-m bg-bg-inset">
                        <tr>
                            <th class="px-5 py-2.5 font-medium">Name</th>
                            <th class="px-4 py-2.5 font-medium">Address</th>
                            <th class="px-4 py-2.5 font-medium">Criticality</th>
                            <th class="px-4 py-2.5 font-medium">Owner</th>
                            <th class="px-4 py-2.5 font-medium">Tags</th>
                            <th class="px-4 py-2.5 font-medium text-right" title="Events whose source belongs to this asset">Decoy activity from it</th>
                            <th class="px-5 py-2.5 w-12"></th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-if="loading"><td colspan="7" class="px-5 py-8 text-center text-text-m">Loading…</td></tr>
                        <tr v-else-if="rows.length === 0"><td colspan="7" class="px-5 py-8 text-center text-text-m">No assets yet. Add your critical hosts and ranges above or import a CSV.</td></tr>
                        <tr v-else-if="filtered.length === 0"><td colspan="7" class="px-5 py-8 text-center text-text-m">No assets match the search.</td></tr>
                        <tr v-for="{ a, i } in filtered" :key="i" class="border-t border-border-default">
                            <td class="px-5 py-2"><input v-model="a.name" :class="inputCls" class="w-full min-w-[140px]" :aria-label="`Name of asset ${i + 1}`" /></td>
                            <td class="px-4 py-2"><input v-model="a.address" :class="[inputCls, isAddrOrCidr(a.address) ? '' : '!border-danger-main']" class="font-mono w-full min-w-[150px]" :aria-label="`Address of ${a.name}`" /></td>
                            <td class="px-4 py-2">
                                <select v-model="a.criticality" class="px-2 py-1 rounded border text-sm bg-bg-surface" :class="critClass(a.criticality)" :aria-label="`Criticality of ${a.name}`">
                                    <option v-for="c in CRITICALITIES" :key="c" :value="c">{{ c }}</option>
                                </select>
                            </td>
                            <td class="px-4 py-2"><input v-model="a.owner" :class="inputCls" class="w-full min-w-[120px]" :aria-label="`Owner of ${a.name}`" /></td>
                            <td class="px-4 py-2 text-text-m">
                                <span v-for="t in a.tags" :key="t" class="inline-block mr-1 px-1.5 py-px rounded border border-border-default text-xs">{{ t }}</span>
                            </td>
                            <td class="px-4 py-2 text-right font-mono whitespace-nowrap" :class="activity.get(a.name)?.events ? 'text-critical' : 'text-text-l'">
                                <template v-if="activity.get(a.name)">{{ activity.get(a.name)!.events }} events · {{ activity.get(a.name)!.sources }} {{ activity.get(a.name)!.sources === 1 ? 'address' : 'addresses' }}</template>
                                <template v-else>–</template>
                            </td>
                            <td class="px-5 py-2 text-right">
                                <button type="button" @click="remove(i)" :aria-label="`Remove ${a.name}`" title="Remove"
                                        class="p-1 rounded text-text-m hover:text-danger-text hover:bg-danger-bg">
                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"></path></svg>
                                </button>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</template>
