import Vue from 'vue'

export function lock (state, value) {
  Vue.set(state, 'lock', value)
}

export function config (state, value) {
  Vue.set(state, 'config', value)
}

export function lockValue (state, value) {
  state.lock.value = value
}

export function lockEnabled (state, value) {
  state.lock.enabled = value
}

export function lockInterval (state, value) {
  state.lock.interval = value
}

export function lockEvent (state, value) {
  state.lock.event = value
}

export function router (state, router) {
  state.router = router
}
