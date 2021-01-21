<template>
  <q-page class="flex flex-center">
    <q-card class="q-pa-lg bg-grey-9" style="width: 480px">
      <q-input
        outlined
        dense
        v-model="pwd"
        :type="isPwd ? 'password' : 'text'"
        label="Stronghold Decryption Phrase"
        class="q-mb-sm"
      >
        <template v-slot:append>
          <q-icon
            :name="isPwd ? 'visibility_off' : 'visibility'"
            class="cursor-pointer"
            @click="isPwd = !isPwd"
          />
        </template>
      </q-input>
      <q-input class="q-mb-sm" outlined dense v-model="path" label="Stronghold Snapshot Path" />
      <q-btn color="primary" class="q-mt-lg float-right" :disabled="!pwd" @click="unlock" label="unlock" />
    </q-card>
  </q-page>
</template>

<script>
import { promisified } from 'tauri/api/tauri'
// import { emit, listen } from 'tauri/api/event'

export default {
  name: 'PageIndex',
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
