<template>
  <q-page class="flex flex-center">
    <q-card class="q-pa-lg bg-grey-9" style="width: 480px">
      <h2 class="q-my-sm">Stronghold</h2>
      <p>
        This application is a demonstration app for verifying that a coalition
        of strongholds works as expected.
      </p>
      <p>
        To use: Enter a decryption phrase and choose a path, then press unlock.
        If you are not actively using the interface, after 10 minutes the
        interface will be locked.
      </p>
    </q-card>
  </q-page>
</template>

<script>
import { invoke } from '@tauri-apps/api/tauri'
// import { emit, listen } from '@tauri-apps/api/event'

export default {
  name: 'PageIndex',
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
