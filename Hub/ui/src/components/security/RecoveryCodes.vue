<script setup>
// Shows freshly issued recovery codes once, with a download. They are never
// retrievable again: the Hub keeps only their hashes.
const props = defineProps({
    codes: { type: Array, required: true }
})

const download = () => {
    const text = 'TrueSignal Hub admin MFA recovery codes\n' +
        'Each code works once. Keep them offline.\n\n' + props.codes.join('\n') + '\n'
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
    const a = document.createElement('a')
    a.href = url
    a.download = 'truesignal-recovery-codes.txt'
    a.click()
    URL.revokeObjectURL(url)
}
</script>

<template>
    <div class="space-y-3">
        <p class="text-sm text-text-m">
            Save these recovery codes somewhere offline. Each one signs you in once if you lose your authenticator.
            They will not be shown again.
        </p>
        <ul class="grid grid-cols-2 gap-2 font-mono text-sm bg-bg-base border border-border-default rounded-md p-4">
            <li v-for="c in codes" :key="c" class="text-text-h select-all">{{ c }}</li>
        </ul>
        <button type="button" class="text-xs text-brand-accent hover:underline" @click="download">Download as .txt</button>
    </div>
</template>
