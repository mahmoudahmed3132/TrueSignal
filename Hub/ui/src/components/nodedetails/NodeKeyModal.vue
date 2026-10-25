<script setup lang="ts">
import { ref, watch } from 'vue'
import BaseModal from '../ui/feedback/BaseModal.vue'
import BaseButton from '../ui/forms/BaseButton.vue'
import { useClipboard } from '../../utils/useClipboard'
import { useFleetStore } from '../../stores/Fleet/fleet'

const props = defineProps<{ show: boolean, nodeId: string | null, hubUrl: string }>()
const emit = defineEmits<{ (e: 'close'): void, (e: 'rotated', key: string): void }>()

const fleetStore = useFleetStore()
const { copiedStates, handleCopy } = useClipboard() as any

const newKey = ref<string | null>(null)
const confirming = ref(false)
const busy = ref(false)
const error = ref('')

watch(() => props.show, (open) => {
    if (!open) { newKey.value = null; confirming.value = false; error.value = '' }
})

const linkCommand = (key: string) =>
    `curl -fsSL https://raw.githubusercontent.com/mahmoudahmed3132/truesignal-dist/main/install.sh | TS_NODE_API_KEY=${key} bash -s -- --link ${props.hubUrl}`

const rotate = async () => {
    if (!props.nodeId) return
    busy.value = true
    error.value = ''
    try {
        newKey.value = await fleetStore.rotateNodeKey(props.nodeId)
        emit('rotated', newKey.value)
    } catch (e: any) {
        error.value = e?.message || 'Failed to rotate key.'
    } finally {
        busy.value = false
        confirming.value = false
    }
}
</script>

<template>
    <BaseModal :show="show" @close="$emit('close')" title="Manage Node Key">
        <div class="space-y-4">
            <template v-if="!newKey">
                <p class="text-sm text-text-m">Node keys are stored hashed and cannot be displayed again after they are issued. If you no longer have this node's key, rotate it to issue a new one.</p>
                <p class="text-sm text-danger-main">Rotating revokes the current key immediately. The node's sensors stop reporting until you re-link the node with the new key.</p>
                <p v-if="error" class="text-sm text-danger-main">{{ error }}</p>
                <div class="flex justify-end gap-3">
                    <BaseButton variant="secondary" @click="$emit('close')">Close</BaseButton>
                    <BaseButton v-if="!confirming" variant="danger" @click="confirming = true">Rotate Key</BaseButton>
                    <BaseButton v-else variant="danger" :disabled="busy" @click="rotate">{{ busy ? 'Rotating…' : 'Confirm Rotation' }}</BaseButton>
                </div>
            </template>
            <template v-else>
                <p class="text-sm text-text-m">Copy the new key now. It will not be shown again.</p>
                <div class="bg-bg-surface border border-border-default rounded-lg p-4 text-sm break-all">
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-sm text-text-h font-semibold">New Node API Key</span>
                        <button @click="handleCopy('key-modal', newKey)" class="px-2.5 py-1 rounded-md text-sm font-medium font-sans transition-all duration-[var(--duration-fast)] shadow-sm active:scale-95 border outline-none" :class="copiedStates['key-modal'] ? 'bg-success-bg text-success-text border-success-border' : 'bg-secondary-main text-text-h border-secondary-border hover:bg-secondary-hover'">{{ copiedStates['key-modal'] ? 'Copied!' : 'Copy' }}</button>
                    </div>
                    <div class="text-text-m select-all font-mono">{{ newKey }}</div>
                </div>
                <p class="text-sm text-text-m">Re-link the node with it (run on the node as root), then run <code class="font-mono">truesignal apply</code>:</p>
                <div class="bg-bg-inset/50 border border-border-default rounded-md p-3 text-xs font-mono break-all select-all">{{ linkCommand(newKey) }}</div>
                <div class="flex justify-end">
                    <BaseButton variant="primary" @click="$emit('close')">Done</BaseButton>
                </div>
            </template>
        </div>
    </BaseModal>
</template>
