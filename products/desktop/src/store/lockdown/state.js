export default function () {
  const timer = 60000
  const delta = 400
  return {
    title: 'Stronghold',
    router: null,
    // non-secure configs
    configuring: false,
    config: {
      slider: 50,
      table: true,
      grid: true
    },
    lock: {
      enabled: true,
      timer: timer,
      delta: delta,
      value: Math.round(timer / delta),
      events: null
    },
    locked: true
  }
}
