<template>
  <q-page class='flex flex-center'>
    <q-card
      class='q-pa-lg bg-grey-9 full-width absolute-top'
      style='top: 0; bottom: 0; min-height: 100%'
    >
      <h3 class='q-my-sm text-right text-weight-thin'>Wipe</h3>
    </q-card>
  </q-page>
</template>

<script>
import { invoke } from '@tauri-apps/api/tauri'
// import { emit, listen } from '@tauri-apps/api/event'

export default {
  name: 'Connect',
  data () {
    return {
      pwd: '',
      isPwd: true,
      path: ''
    }
  },
  mounted () {},
  methods: {
    unlock () {
      invoke('unlock', {
        payload: {
          pwd: this.pwd,
          path: this.path
        }
      })
        .then((response) => {
          // do something with the Ok() response
          const { message } = response
          this.$q.notify(`${message}`)
        })
        .catch((error) => {
          // do something with the Err() response string
          this.$q.notify(error)
        })
    }
  }
}
</script>
