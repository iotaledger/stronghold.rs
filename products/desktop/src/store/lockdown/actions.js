// import { Notify, Loading } from 'quasar'

export async function lockup ({ state, getters, dispatch, commit }) {
  commit('lockEnabled', false)

  const interval = window.setInterval(() => {
    commit('lockValue', state.lock.value - 1)
    state.lock.value = state.lock.value - 1
    if (state.lock.value <= 0) {
      dispatch('lockdown')
    }
  }, state.lock.delta)
  commit('lockInterval', interval)

  const event = () => commit('lockValue', getters.lockMaxValue)
  window.addEventListener('click', event, false)
  window.addEventListener('keyup', event, false)
  window.addEventListener('mouseover', event, false)
  commit('lockEvent', event)
  // state.router.push('/identity/')
}

export async function lockdown ({ state, dispatch, getters, commit }) {
  commit('lockEnabled', true)

  commit('lockValue', getters.lockMaxValue)
  if (state.lock.interval) {
    window.clearInterval(state.lock.interval)
  }
  commit('lockInterval', null)

  if (state.lock.event) {
    window.removeEventListener('click', event, false)
    window.removeEventListener('keyup', event, false)
    window.removeEventListener('mouseover', event, false)
  }

  commit('lockEvent', null)
  await dispatch('entities/purge', null, { root: true })
  await dispatch('closeWorkers')
  commit('projects', {})
  commit('userData', { authLevel: '', id: '', name: '' })
  state.router.push('/')
}
