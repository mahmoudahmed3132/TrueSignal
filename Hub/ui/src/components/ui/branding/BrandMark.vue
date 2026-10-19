<script setup>
// Ledger mark: two rings (the monitored space) and one offset point that
// has been touched. Rings follow the text colour; the point is the accent.
defineProps({
    title: { type: String, default: 'TrueSignal' }
})
</script>

<template>
    <svg viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" role="img" :aria-label="title">
        <circle cx="32" cy="32" r="25" fill="none" stroke="currentColor" stroke-width="3.5"/>
        <circle cx="32" cy="32" r="13.5" fill="none" stroke="currentColor" stroke-width="3.5"/>
        <circle cx="46" cy="18" r="7" fill="var(--brand-accent)"/>
    </svg>
</template>
