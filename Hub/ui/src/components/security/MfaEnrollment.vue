<script setup>
// MFA enrollment: re-enter the password (unless the caller already has it),
// scan the QR code, confirm with a code, then save the recovery codes.
import { ref, onMounted } from 'vue'
import { useAppStore } from '../../stores/System/app'
import BaseInput from '../ui/forms/BaseInput.vue'
import BaseButton from '../ui/forms/BaseButton.vue'
import RecoveryCodes from './RecoveryCodes.vue'

const props = defineProps({
    password: { type: String, default: '' }
})
const emit = defineEmits(['done', 'cancel'])
const appStore = useAppStore()

const step = ref(props.password ? 'loading' : 'password')
const pwd = ref(props.password)
const setup = ref(null)
const code = ref('')
const recovery = ref([])
const error = ref('')
const busy = ref(false)

const start = async () => {
    busy.value = true
    error.value = ''
    const res = await appStore.mfaSetup(pwd.value)
    busy.value = false
    if (res.error) {
        error.value = res.error
        step.value = 'password'
        return
    }
    setup.value = res
    step.value = 'scan'
}

const confirm = async () => {
    busy.value = true
    error.value = ''
    const res = await appStore.mfaEnable(code.value.trim())
    busy.value = false
    code.value = ''
    if (res.error) {
        error.value = res.error
        return
    }
    recovery.value = res.recoveryCodes || []
    pwd.value = ''
    step.value = 'codes'
}

// Group the base32 secret for manual entry.
const grouped = (s) => (s || '').match(/.{1,4}/g)?.join(' ') || ''

onMounted(() => { if (props.password) start() })
</script>

<template>
    <div class="space-y-4">
        <form v-if="step === 'password'" @submit.prevent="start" class="space-y-4">
            <p class="text-sm text-text-m">Enter your password to set up two-factor authentication.</p>
            <BaseInput v-model="pwd" label="Password" type="password" required autofocus />
            <div class="flex justify-end gap-3">
                <BaseButton variant="ghost" @click="emit('cancel')">Cancel</BaseButton>
                <BaseButton variant="primary" type="submit" :disabled="busy">Continue</BaseButton>
            </div>
        </form>

        <p v-else-if="step === 'loading'" class="text-sm text-text-m">Preparing enrollment...</p>

        <form v-else-if="step === 'scan'" @submit.prevent="confirm" class="space-y-4">
            <p class="text-sm text-text-m">
                Scan this code with an authenticator app (Microsoft Authenticator, Google Authenticator, 1Password, ...),
                then enter the 6-digit code it shows.
            </p>
            <div class="flex justify-center">
                <img v-if="setup?.qr" :src="setup.qr" alt="MFA QR code" class="w-48 h-48 bg-white p-2 rounded-md [image-rendering:pixelated]" />
            </div>
            <div class="text-xs text-text-m">
                Can't scan? Enter this key manually (time-based, 6 digits, 30 s):
                <div class="font-mono text-sm text-text-h mt-1 select-all break-all">{{ grouped(setup?.secret) }}</div>
            </div>
            <BaseInput v-model="code" label="6-digit code" placeholder="123456" required autofocus />
            <div class="flex justify-end gap-3">
                <BaseButton variant="ghost" @click="emit('cancel')">Cancel</BaseButton>
                <BaseButton variant="primary" type="submit" :disabled="busy">{{ busy ? 'Verifying...' : 'Enable MFA' }}</BaseButton>
            </div>
        </form>

        <div v-else-if="step === 'codes'" class="space-y-4">
            <RecoveryCodes :codes="recovery" />
            <div class="flex justify-end">
                <BaseButton variant="primary" @click="emit('done')">I have saved these codes</BaseButton>
            </div>
        </div>

        <div v-if="error" class="text-xs text-danger-text bg-danger-bg p-2.5 rounded-md border border-danger-border">{{ error }}</div>
    </div>
</template>
