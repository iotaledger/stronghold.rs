<template>
  <div id="q-app">
    <router-view />
  </div>
</template>
<script>
export default {
  name: 'Stronghold',
  created () {
    this.$q.dark.set(true)
  }
}
</script>
