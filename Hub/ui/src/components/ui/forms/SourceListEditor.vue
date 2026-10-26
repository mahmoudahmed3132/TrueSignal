<script setup lang="ts">
import { ref, computed } from 'vue'
import BaseButton from './BaseButton.vue'

// One entry per line: an IP, a CIDR range or an exact source name. The Hub
// validates and normalises the list on save.
const props = defineProps<{
    modelValue: string
    label: string
    description: string
    placeholder?: string
}>()
const emit = defineEmits<{ 'update:modelValue': [value: string] }>()

const fileInput = ref<HTMLInputElement | null>(null)
const importNote = ref('')
const importError = ref(false)

const MAX_FILE_BYTES = 1024 * 1024

const entries = (text: string): string[] =>
    text.split(/[\n,]/).map(s => s.trim()).filter(s => s && !s.startsWith('#'))

const count = computed(() => entries(props.modelValue).length)

// Pull IPv4/IPv6 addresses and CIDR ranges out of a text or CSV export
// (scanner inventories, threat-intel lists); other columns are ignored.
const ADDR = /(?:\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?\b)|(?:\b[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}(?:\/\d{1,3})?)/g

const onFile = async (ev: Event) => {
    const input = ev.target as HTMLInputElement
    const file = input.files?.[0]
    input.value = ''
    if (!file) return
    importError.value = false
    if (file.size > MAX_FILE_BYTES) {
        importError.value = true
        importNote.value = 'File is larger than 1 MB.'
        return
    }
    const found = (await file.text()).match(ADDR) || []
    const existing = new Set(entries(props.modelValue))
    const added = [...new Set(found)].filter(a => !existing.has(a))
    if (found.length === 0) {
        importError.value = true
        importNote.value = `No IP addresses or CIDR ranges found in ${file.name}.`
        return
    }
    const current = props.modelValue.trim()
    emit('update:modelValue', [current, ...added].filter(Boolean).join('\n'))
    importNote.value = `${added.length} new entries from ${file.name}` +
        (found.length - added.length > 0 ? `, ${found.length - added.length} duplicates skipped` : '') +
        '. Save to apply.'
}
</script>

<template>
    <div class="w-full">
        <div class="flex items-end justify-between gap-3 mb-1">
            <label class="block text-sm text-text-h">{{ label }}</label>
            <span class="text-xs text-text-l font-mono">{{ count }} {{ count === 1 ? 'entry' : 'entries' }}</span>
        </div>
        <textarea
            :value="modelValue"
            @input="emit('update:modelValue', ($event.target as HTMLTextAreaElement).value)"
            :placeholder="placeholder"
            rows="6"
            spellcheck="false"
            class="w-full px-3 py-2 text-sm font-mono bg-input-bg border border-input-border rounded-md shadow-sm outline-none resize-y focus:border-primary-main focus:ring-1 focus:ring-focus-ring text-text-h"
        ></textarea>
        <p class="text-sm text-text-m mt-1">{{ description }}</p>
        <div class="flex flex-wrap items-center gap-3 mt-2">
            <BaseButton variant="secondary" class="!py-1 !px-3 !text-sm" @click="fileInput?.click()">Import file…</BaseButton>
            <input ref="fileInput" type="file" accept=".txt,.csv,.lst,.list,text/plain,text/csv" class="hidden" @change="onFile" />
            <span v-if="importNote" class="text-xs" :class="importError ? 'text-danger-text' : 'text-text-m'" role="status">{{ importNote }}</span>
        </div>
    </div>
</template>
