<script setup>
import { ref } from 'vue'
import { useAppStore } from '../stores/System/app'
import BaseInput from '../components/ui/forms/BaseInput.vue'
import BaseButton from '../components/ui/forms/BaseButton.vue'
import BaseCard from '../components/ui/layout/BaseCard.vue'
import BaseAlert from '../components/ui/feedback/BaseAlert.vue'
import PageHeader from '../components/ui/layout/PageHeader.vue'
import ThemeToggle from '../components/ui/branding/ThemeToggle.vue'
import BaseLogo from '../components/ui/branding/BaseLogo.vue'
import MfaEnrollment from '../components/security/MfaEnrollment.vue'

const emit = defineEmits(['login-success', 'toggle-theme'])
const appStore = useAppStore()

const password = ref('')
const code = ref('')
// 'password' -> 'code' (MFA enrolled) or 'enroll' (TS_REQUIRE_MFA, not enrolled)
const step = ref('password')
const loading = ref(false)
const error = ref(false)
const errorText = ref('Access Denied: Invalid Key')
const rateLimited = ref(false)

const reset = () => {
    step.value = 'password'
    password.value = ''
    code.value = ''
}

const doLogin = async () => {
    loading.value = true
    error.value = false
    rateLimited.value = false
    
    const result = await appStore.login(password.value, step.value === 'code' ? code.value.trim() : '')
    
    if (result.success) {
        emit('login-success')
    } else if (result.enrollRequired) {
        step.value = 'enroll'
    } else if (result.mfaRequired) {
        step.value = 'code'
    } else if (result.status === 429) {
        rateLimited.value = true
        reset()
    } else if (result.invalidCode) {
        errorText.value = 'Invalid code'
        error.value = true
        code.value = ''
    } else {
        errorText.value = 'Access Denied: Invalid Key'
        error.value = true
        reset()
    }
    
    loading.value = false
}

const enrolled = async () => {
    password.value = ''
    await appStore.finishLogin()
    emit('login-success')
}
</script>

<template>
    <div class="h-screen flex flex-col items-center justify-center bg-bg-base p-6 relative transition-colors duration-normal">
        
        <div class="absolute top-6 right-6">
            <ThemeToggle @toggle="$emit('toggle-theme')" />
        </div>

        <div class="w-full max-w-sm z-10">
            
            <div class="mb-10">
                <BaseLogo />
                <PageHeader 
                    center 
                    title="TrueSignal" 
                    description="Authorized personnel only." 
                />
            </div>

            <BaseCard class="relative overflow-hidden transition-all duration-normal">
                <div class="absolute top-0 left-0 right-0 h-1 bg-brand-accent"></div>

                <div v-if="step === 'enroll'" class="mt-2">
                    <p class="text-sm text-text-m mb-4">This Hub requires two-factor authentication. Set it up to continue.</p>
                    <MfaEnrollment :password="password" @done="enrolled" @cancel="reset" />
                </div>

                <form v-else @submit.prevent="doLogin" class="mt-2 space-y-6">
                    <BaseInput 
                        v-if="step === 'password'"
                        v-model="password"
                        label="Authentication Key"
                        type="password"
                        placeholder="••••••••••••"
                        required
                        autofocus
                    />
                    <BaseInput
                        v-else
                        v-model="code"
                        label="Authentication code"
                        description="6-digit code from your authenticator app, or a recovery code."
                        placeholder="123456"
                        required
                        autofocus
                    />

                    <BaseButton
                        variant="primary"
                        type="submit"
                        :disabled="loading || rateLimited"
                        class="w-full h-11"
                    >
                        {{ loading ? 'Authenticating...' : (step === 'code' ? 'Verify' : 'Sign in') }}
                    </BaseButton>
                    <button v-if="step === 'code'" type="button" class="w-full text-xs text-text-m hover:underline" @click="reset">Use a different password</button>
                </form>

                <Transition
                    enter-active-class="transition duration-300 ease-out"
                    enter-from-class="transform -translate-y-2 opacity-0"
                    enter-to-class="transform translate-y-0 opacity-100"
                    leave-active-class="transition duration-200 ease-in"
                    leave-from-class="transform translate-y-0 opacity-100"
                    leave-to-class="transform -translate-y-2 opacity-0"
                >
                    <div v-if="error" class="mt-6">
                        <BaseAlert variant="danger" :message="errorText" />
                    </div>
                </Transition>

                <Transition
                    enter-active-class="transition duration-300 ease-out"
                    enter-from-class="transform -translate-y-2 opacity-0"
                    enter-to-class="transform translate-y-0 opacity-100"
                    leave-active-class="transition duration-200 ease-in"
                    leave-from-class="transform translate-y-0 opacity-100"
                    leave-to-class="transform -translate-y-2 opacity-0"
                >
                    <div v-if="rateLimited" class="mt-6">
                        <BaseAlert 
                            variant="danger" 
                            :message="'Too many attempts.\nPlease try again in 15 minutes.'"
                            class="whitespace-pre-line"
                        />
                    </div>
                </Transition>
            </BaseCard>
            
        </div>
    </div>
</template>