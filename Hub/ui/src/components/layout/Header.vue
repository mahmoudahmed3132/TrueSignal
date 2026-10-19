<script setup>
import { ref, computed } from 'vue'
import { storeToRefs } from 'pinia'
import { useRoute } from 'vue-router'
import { useAppStore } from '../../stores/System/app'
import { useEventsStore } from '../../stores/Events/events'
import { useClipboard } from '../../utils/useClipboard.js'
import BrandMark from '../ui/branding/BrandMark.vue'

const appStore = useAppStore()
const eventsStore = useEventsStore()
const route = useRoute()
const { copiedStates, handleCopy } = useClipboard()

const { isArmed, wizardUpdateAvailable, latestWizardVersion, wizardReleaseNotesUrl } = storeToRefs(appStore)
const { unreadCount } = storeToRefs(eventsStore)

const showInstallModal = ref(false)

const installCommand = computed(() => {
    if (wizardUpdateAvailable.value && latestWizardVersion.value) {
        return `curl -fsSL https://raw.githubusercontent.com/mahmoudahmed3132/TrueSignal/main/install.sh | bash -s -- --version ${latestWizardVersion.value}`
    }
    return 'curl -fsSL https://raw.githubusercontent.com/mahmoudahmed3132/TrueSignal/main/install.sh | bash'
})

const handleDismissWizardUpdate = async () => {
    await appStore.acknowledgeWizardUpdate()
}

const handleMarkAllRead = async () => {
    const res = await eventsStore.markAllRead()
    if (!res.success) alert(res.error)
}
</script>

<template>
    <header class="h-14 bg-gradient-to- from-bg to-transparent flex items-center justify-between px-4 sm:px-6 shrink-0 backdrop-blur-sm">
        
        <div class="flex items-center gap-4">
            <div class="flex items-center gap-2 pr-4 mr-2 border-r border-border-default">
                <BrandMark class="w-9 h-9 text-text-h shrink-0" />
            <span class="text-h1 font-bold text-text-h leading-none tracking-tight">TrueSignal</span>
        </div>
        
        <h2 class="text-base  text-text-m font-medium capitalize hidden sm:block">{{ String(route.name || '')?.replace('-', ' ') }}</h2>
    </div>
    
    <div class="flex items-center gap-3">
        <button v-show="unreadCount > 0" @click="handleMarkAllRead"
                type="button"
                aria-label="Mark all events as read"
                class="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-md text-xs  mr-1 bg-danger-bg text-danger-text border border-danger-border transition-colors hover:bg-danger-hover focus:outline-none shadow-sm">
            <span class="w-1.5 h-1.5 rounded-full bg-danger-main animate-pulse"></span>
            <span>{{ unreadCount }} Unread</span>
        </button>

        <button @click="appStore.toggleArmed()" 
                type="button"
                title="Disable / Enable push notifications"
                :aria-label="isArmed ? 'Disarm system' : 'Arm system'"
                class="px-3 py-1.5 rounded-md text-xs  transition-colors border shadow-sm focus:outline-none"
                :class="isArmed ? 'bg-success-bg text-success-text border-success-border hover:bg-success-selected' : 'bg-secondary-main text-secondary-text border-secondary-border hover:bg-secondary-hover hover:text-text-h'">
            <span>{{ isArmed ? 'Armed' : 'Passive' }}</span>
        </button>

        <button @click="showInstallModal = true" 
                type="button"
                :title="wizardUpdateAvailable ? `Wizard Update Available (${latestWizardVersion})` : 'Install Wizard'"
                :aria-label="wizardUpdateAvailable ? `Wizard Update Available (${latestWizardVersion})` : 'Install Wizard'"
                class="w-8 h-8 rounded-md bg-secondary-main border border-secondary-border text-secondary-text hover:text-text-h hover:bg-secondary-hover transition-colors flex items-center justify-center group shadow-sm focus:outline-none relative">
            <svg class="w-4 h-4 transition-transform duration-300 ease-out group-hover:scale-110" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="4 17 10 11 4 5"></polyline>
                <line x1="12" y1="19" x2="20" y2="19"></line>
            </svg>
            <span v-if="wizardUpdateAvailable" class="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-update-main opacity-75"></span>
                <span class="relative inline-flex rounded-full h-2.5 w-2.5 bg-update-main ring-2 ring-bg-surface"></span>
            </span>
        </button>

        <button @click="appStore.toggleTheme()" 
                type="button"
                aria-label="Toggle light and dark theme"
                class="w-8 h-8 rounded-md bg-secondary-main border border-secondary-border text-secondary-text hover:text-text-h hover:bg-secondary-hover transition-colors flex items-center justify-center group overflow-hidden shadow-sm focus:outline-none">
            <svg class="w-4 h-4 transition-transform duration-300 ease-out group-hover:rotate-45 group-hover:scale-110 block dark:hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="5"></circle><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"></path>
            </svg>
            <svg class="w-4 h-4 transition-transform duration-300 ease-out group-hover:-rotate-12 group-hover:scale-110 hidden dark:block" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"></path>
            </svg>
        </button>
        
        <div class="w-px h-4 bg-border-default mx-1"></div>
        
        <button @click="appStore.logout()" 
                type="button"
                aria-label="Logout and exit the system"
                class="text-xs  text-secondary-text hover:text-text-h transition-colors cursor-pointer bg-transparent border-0 p-0 focus:outline-none">Exit</button>
    </div>
</header>

<Teleport to="body">
    <transition enter-active-class="transition duration-normal ease-out" enter-from-class="opacity-0" enter-to-class="opacity-100" leave-active-class="transition duration-fast ease-in" leave-from-class="opacity-100" leave-to-class="opacity-0">
        <div v-if="showInstallModal" class="fixed inset-0 z-[var(--z-modal)] flex justify-center items-center p-4 sm:p-6 bg-black/60 backdrop-blur-sm" @mousedown.self="showInstallModal = false">
            <div class="bg-bg-base w-full max-w-2xl rounded-lg shadow-2xl flex flex-col overflow-hidden border border-border-default transform transition-all">
                <div class="px-6 py-5 border-b border-border-default flex justify-between items-center bg-bg-surface shrink-0">
                    <div class="flex items-center gap-3">
                        <h2 class="text-base font-semibold text-text-h">Install TrueSignal Wizard</h2>
                        
                        <!-- Update Badge Beside Title -->
                        <span v-if="wizardUpdateAvailable && latestWizardVersion" 
                              class="px-2.5 py-1 bg-update-bg border border-update-main/30 text-update-text text-xs font-mono font-medium rounded-md flex items-center gap-2 group/tag">
                            <span class="w-1.5 h-1.5 rounded-full bg-update-main animate-pulse shrink-0"></span>
                            <component :is="wizardReleaseNotesUrl ? 'a' : 'span'"
                                       :href="wizardReleaseNotesUrl"
                                       target="_blank"
                                       rel="noopener noreferrer"
                                       :title="wizardReleaseNotesUrl ? `View ${latestWizardVersion} release notes` : ''"
                                       :class="wizardReleaseNotesUrl ? 'hover:underline text-update-main hover:text-update-hover cursor-pointer' : 'text-update-text'"
                                       class="transition-colors">
                                {{ latestWizardVersion }}
                            </component>
                            <button @click.stop="handleDismissWizardUpdate" 
                                    type="button" 
                                    title="Dismiss update notice"
                                    aria-label="Dismiss update notice"
                                    class="opacity-70 group-hover/tag:opacity-100 text-update-text hover:text-danger-main transition-all outline-none focus:opacity-100 cursor-pointer flex items-center p-0.5 rounded">
                                <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>
                            </button>
                        </span>
                    </div>
                    <button @click="showInstallModal = false" type="button" aria-label="Close modal" class="p-2 -mr-2 text-text-m hover:text-text-h transition-colors duration-fast rounded-full hover:bg-secondary-hover focus:outline-none">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"></path></svg>
                    </button>
                </div>
                <div class="p-6 md:p-8 space-y-4">
                    <p class="text-sm text-text-m leading-normal">
                        {{ wizardUpdateAvailable ? 'Run the following command on your server to update the TrueSignal Wizard.' : 'Run the following command on your server to install the TrueSignal Wizard.' }}
                    </p>
                    <div class="bg-bg-inset/50 border border-border-default rounded-md p-4 relative group flex flex-col gap-3">
                        <code class="text-success-text text-sm font-mono whitespace-pre-wrap break-all leading-relaxed select-all">{{ installCommand }}</code>
                        <button @click="handleCopy('install-cmd', installCommand)" class="self-end px-3 py-1.5 rounded-md text-sm font-medium transition-all duration-fast shadow-sm active:scale-95 focus:outline-none border" :class="copiedStates['install-cmd'] ? 'bg-success-bg text-success-text border-success-border' : 'bg-bg-surface text-text-h border-border-default hover:bg-secondary-hover'">
                            {{ copiedStates['install-cmd'] ? 'Copied!' : 'Copy' }}
                        </button>
                    </div>
                    <p class="text-sm text-text-m mt-2 leading-normal">
                        This installs the binary to <code class="px-1 py-0.5 bg-bg-inset/50 border border-border-default rounded text-xs font-mono text-text-h">/usr/local/bin/truesignal</code> using the official TrueSignal installation script.
                    </p>
                </div>
            </div>
        </div>
    </transition>
</Teleport>
</template>