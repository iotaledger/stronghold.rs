export function lockMaxValue (state) {
  if (!state.lock.timer || state.lock.timer < 0) {
    return Number.POSITIVE_INFINITY
  }
  return Math.round(state.lock.timer / state.lock.delta)
}

export function locked (state) {
  return state.locked
}
