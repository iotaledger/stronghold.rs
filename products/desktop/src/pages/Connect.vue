<template>
  <q-page class="flex flex-center">
    <q-card class="q-pa-lg bg-grey-9" style="width: 480px">
      <h2 class="float-left">Connect</h2>
      <q-img class="float-right" src="peerid.png" height="128px" width="128px" />
      <q-input class="q-mb-sm full-width" outlined dense v-model="thisPeerID" readonly label="This PeerID" />
      <q-input class="q-mb-sm full-width" outlined dense v-model="remotePeerID" label="Remote PeerID" />
      <div style="min-width: 250px; max-width: 300px">
        <q-select
          filled
          v-model="modelMultiple"
          multiple
          :options="options"
          use-chips
          stack-label
          label="Permissions"
        />
      </div>

      <q-btn color="primary" class="q-mt-lg float-right" :disabled="!remoteMultiaddress" @click="unlock" label="Add to Coalition" />
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
      thisPeerID: '12D3KooWLyEaoayajvfJktzjvvNCe9XLxNFMmPajsvrHeMkgajAA',
      remotePeerID: '',
      path: '',
      modelMultiple: ['Readonly'],
      options: [
        'Readonly', 'Readwrite', 'Sync', 'Sign', 'Admin'
      ]
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
