<template>
  <q-page class="flex flex-center">
    <q-card
      class="q-pa-lg bg-grey-9 full-width absolute-top"
      style="top: 0; bottom: 0; min-height: 100%"
    >
      <h3 class="q-my-sm text-right text-weight-thin">Connect</h3>
      <q-tabs
        v-model="tab"
        dense
        class="text-grey"
        active-color="primary"
        indicator-color="primary"
        align="justify"
        narrow-indicator
      >
        <q-tab name="outgoing" label="Outgoing" />
        <q-tab name="incoming" label="Incoming" />
        <q-tab name="groups" label="Groups" />
      </q-tabs>

      <q-separator />

      <q-tab-panels v-model="tab" animated>
        <q-tab-panel name="outgoing">
          <div class="text-h6 float-left">Outgoing Offer</div>
          <div class="text-p float-left">
            On this page you can generate an outgoing offer as a QR code for
            easy scanning that will offer the receiver the ability to connect
            with your device.
          </div>
          <!--<q-img class="q-mb-sm float-right" src="peerid.png" height="158px" width="158px" / -->
          <VueQrcode
            class="q-mb-sm float-right"
            :value="thisPeerID"
            :options="{ width: 158 }"
          />
          <q-input
            class="q-ma-sm full-width"
            outlined
            dense
            :value="thisPeerID"
            readonly
            label="This PeerID + Permissions"
          />
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
          <q-btn
            color="primary"
            class="q-mt-sm q-mb-md float-right"
            :disabled="!remotePeerID"
            @click="send"
            label="Send to Coalition"
          />
          <!--<p>Enum debug: {{ accessVerifier }}</p>-->
        </q-tab-panel>

        <q-tab-panel name="incoming">
          <div class="text-h6">Incoming Request</div>
          <q-input
            class="q-mb-sm full-width"
            outlined
            dense
            v-model="remotePeerID"
            label="Remote PeerID"
          />
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
          <q-btn
            color="primary"
            class="q-my-md float-right"
            :disabled="!remotePeerID"
            @click="send"
            label="Invite to Coalition"
          />
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
import { invoke } from '@tauri-apps/api/tauri'
import { mapState } from 'vuex'
import VueQrcode from '@chenfengyuan/vue-qrcode'
// import { emit, listen } from '@tauri-apps/api/event'

const accessEnum = {
  RequestAlways: 1,
  ReadOnly: 2,
  ReadWrite: 4,
  Admin: 8,
  Verify: 16,
  Sign: 32,
  Sync: 64,
  Store: 128,
  Vault: 256,
  Runtime: 512
}

// decompose access code
function decodeAccess (v) {
  let access = 0
  const accesses = []
  while (v !== 0) {
    if ((v & 1) !== 0) {
      accesses.push(1 << access)
    }
    ++access
    v >>>= 1
  }
  const accessList = []

  accesses.forEach((v) => {
    accessList.push(
      Object.keys(accessEnum).find((key) => accessEnum[key] === v)
    )
  })

  return accessList
}

// create accessCode
function computeAccess (arr) {
  let access = 0
  const keys = Object.keys(accessEnum)
  arr.forEach((acc) => {
    if (keys.find((k) => k === acc)) {
      access = access + accessEnum[acc]
    }
  })
  return access
}

export default {
  name: 'Connect',
  components: { VueQrcode },
  data () {
    return {
      tab: 'outgoing',
      remotePeerID: '',
      path: '',
      modelMultiple: ['RequestAlways'],
      options: Object.keys(accessEnum)
    }
  },
  mounted () {},
  computed: {
    thisPeerID () {
      return `${this.$store.state.lockdown.peers.me}:${computeAccess(
        this.modelMultiple
      )}`
    },
    accessVerifier () {
      return decodeAccess(computeAccess(this.modelMultiple))
    },
    ...mapState('lockdown', {
      myPeerID (state) {
        return state.myPeerID
      }
    })
  },
  methods: {
    send () {
      invoke('send', {
        payload: {
          pwd: this.pwd,
          path: this.path
        }
      })
        .then((response) => {
          // do something with the Ok() response
          const { message } = response
          this.myPeerId = message
          // this.$q.notify(`${message}`)
        })
        .catch((error) => {
          // do something with the Err() response string
          this.$q.notify('error:', error)
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
