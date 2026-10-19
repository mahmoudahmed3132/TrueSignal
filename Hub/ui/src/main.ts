import { createApp } from 'vue'
import { createPinia } from 'pinia'
// Fonts are bundled, not loaded from a CDN: SOC networks are often offline,
// and a third-party font request on every load leaks that the Hub is in use.
import '@fontsource-variable/instrument-sans/wght.css'
import '@fontsource/ibm-plex-mono/400.css'
import '@fontsource/ibm-plex-mono/500.css'
import '@fontsource/ibm-plex-mono/600.css'
import './assets/style.css'
import App from './App.vue'
import router from './index'

const app = createApp(App)
app.use(createPinia())
app.use(router)
app.mount('#app')
