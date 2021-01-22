<template>
  <q-page class="flex flex-center">
    <q-card class="q-pa-lg bg-grey-9" style="width: 480px">
      <h2>Coalition</h2>
    </q-card>
  </q-page>
</template>

<script>
import { promisified } from 'tauri/api/tauri'
// import { emit, listen } from 'tauri/api/event'

export default {
  name: 'Connect',
  data () {
    return {
      pwd: '',
      isPwd: true,
      path: ''
    }
  },
  mounted () {

  },
  methods: {
    unlock () {
      promisified({
        cmd: 'unlock',
        payload: {
          pwd: this.pwd,
          path: this.path
        }
      }).then(response => {
        // do something with the Ok() response
        const { message } = response
        this.$q.notify(`${message}`)
      }).catch(error => {
        // do something with the Err() response string
        this.$q.notify(error)
      })
    }
  }
}
</script>
