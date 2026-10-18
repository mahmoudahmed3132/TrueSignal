<script setup>
defineProps({
    showText: { type: Boolean, default: false }
})
</script>

<template>
    <div class="flex flex-col items-center">
        <div class="w-16 h-16 flex items-center justify-center rounded-lg bg-bg-surface border border-border-default shadow-sm p-3 transition-colors duration-normal">
            <svg class="w-full h-full text-text-h shrink-0" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="TrueSignal">
                <!-- TrueSignal mark: one clear spike over a flat baseline -->
                <circle cx="32" cy="32" r="26" fill="none" stroke="currentColor" stroke-width="4"/><path d="M10 34H22L27 24L32 46L37 14L42 34H54" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        </div>
        
        <div v-if="showText" class="text-center">
            <h1 class="text-h1 text-text-h tracking-tight">TrueSignal Sentinel</h1>
            <p class="text-sm text-text-m mt-1">Authorized personnel only</p>
        </div>
    </div>
</template>