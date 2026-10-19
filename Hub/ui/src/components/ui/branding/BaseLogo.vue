<script setup>
import BrandMark from './BrandMark.vue'

defineProps({
    showText: { type: Boolean, default: false }
})
</script>

<template>
    <div class="flex flex-col items-center">
        <div class="w-16 h-16 flex items-center justify-center rounded-lg bg-bg-surface border border-border-default shadow-sm p-3 transition-colors duration-normal">
            <BrandMark class="w-full h-full text-text-h shrink-0" />
        </div>
        
        <div v-if="showText" class="text-center">
            <h1 class="text-h1 text-text-h tracking-tight">TrueSignal</h1>
            <p class="text-sm text-text-m mt-1">Deception telemetry, audit-ready.</p>
        </div>
    </div>
</template>