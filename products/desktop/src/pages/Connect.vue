<template>
  <q-page class="flex flex-center">
    <q-card class="q-pa-lg bg-grey-9 full-width absolute-top" style="top:0;bottom:0;min-height:100%">
      <q-tabs
          v-model="tab"
          dense
          class="text-grey"
          active-color="primary"
          indicator-color="primary"
          align="justify"
          narrow-indicator
        >
          <q-tab name="incoming" label="Incoming" />
          <q-tab name="outgoing" label="Outgoing" />
          <q-tab name="groups" label="Groups" />
        </q-tabs>

        <q-separator />

        <q-tab-panels v-model="tab" animated>
          <q-tab-panel name="incoming">
            <div class="text-h6 float-left">Incoming Offer</div>
              <q-img class="q-mb-sm float-right" src="peerid.png" height="128px" width="128px" />
              <q-input class="q-ma-sm full-width" outlined dense v-model="thisPeerID" readonly label="This PeerID" />
              <div class="full-width">
                <q-select
                  outlined
                  v-model="modelMultiple"
                  multiple
                  :options="options"
                  use-chips
                  stack-label
                  label="Permissions"
                />
              </div>
              <q-btn color="primary" class="q-mt-sm q-mb-md float-right" :disabled="!remoteMultiaddress" @click="unlock" label="Add to Coalition" />
          </q-tab-panel>

          <q-tab-panel name="outgoing">
            <div class="text-h6">Outgoing Request</div>
              <q-input class="q-mb-sm full-width" outlined dense v-model="remotePeerID" label="Remote PeerID" />
              <div class="full-width">
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
              <q-btn color="primary" class="q-my-md float-right" :disabled="!remoteMultiaddress" @click="unlock" label="Add to Coalition" />

          </q-tab-panel>

          <q-tab-panel name="groups">
            <div class="text-h6">Groups</div>
            Lorem ipsum dolor sit amet consectetur adipisicing elit.
          </q-tab-panel>
        </q-tab-panels>
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
      tab: 'incoming',
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
<style lang="sass">
  .q-chip__content
    font-size: 0.8em
    padding: 0 3px 0 2px
</style>
