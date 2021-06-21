<template>
  <q-layout view="hHh LpR lFf" style="max-height:100%">
    <div class="row">
      <div class="col-auto">
        <q-scroll-area
          :thumb-style="thumbStyle"
          :bar-style="barStyle"
          dark
          :style="`height: ${$q.screen.height}px; width: 300px;border-right:solid 1px #333`"
        >
          <q-item v-if="locked" @click="lockCallback" clickable class="cursor-pointer bg-grey-10" style="width: 300px" dark>
            <q-item-section avatar class="sidebar-item" style="height:84px">
              <lock-timer></lock-timer>
            </q-item-section>
            <q-item-section class="q-ml-md" v-if="loggedIn">
              <q-item-label>Log Out</q-item-label>
            </q-item-section>
            <q-item-section class="q-ml-md" v-if="!loggedIn">

              <q-input
                outlined
                dense
                v-model="pwd"
                :type="isPwd ? 'password' : 'text'"
                label="Decryption Phrase"
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
              <q-input class="q-mb-sm" outlined dense v-model="path" label="Snapshot Path">
                <template v-slot:append>
                  <q-icon
                    name="fa fa-file"
                    class="cursor-pointer"
                    @click="chooseFile"
                  />
                </template>
              </q-input>
              <q-btn color="primary" class="q-mt-lg float-right" :disabled="!pwd" @click="unlock" label="unlock" />

            </q-item-section>
            <q-item-section v-if="loggedIn">
              <q-btn @click="register" v-if="!yubikey.registered" label="Register Yubikey" />
              <q-btn @click="sign" v-if="yubikey.registered && !yubikey.signedIn" label="Login with Yubikey" />
            </q-item-section>
          </q-item>
          <q-list v-if="loggedIn">
            <q-item-label
              header
              class="grey-1 text-weight-bolder"
            >
              Tools
            </q-item-label>
            <InternalLink
              v-for="link in actionLinks"
              :key="link.title"
              v-bind="link"
            />
          </q-list>
          <q-list  class="q-my-xl">
            <q-item-label
              header
              class="grey-1 text-weight-bolder"
            >
              Documentation and Help
            </q-item-label>
            <EssentialLink
              v-for="link in essentialLinks"
              :key="link.title"
              v-bind="link"
            />
          </q-list>
          <div class="bg-primary fixed-bottom z-top full-width">
            <div class="q-mx-sm">
              <div class="float-left text-weight-light text-black">Stronghold Verification App</div>
              <div class="float-right text-weight-light text-black">v{{ version }}</div>
            </div>
          </div>
        </q-scroll-area>
      </div>
      <div class="col">
        <q-scroll-area
          :thumb-style="thumbStyle"
          :bar-style="barStyle"
          dark
          :style="`height: ${$q.screen.height}px;`"
        >
          <q-page-container>
            <q-card
              v-if="status.peerId"
              class="q-pa-lg bg-grey-9 full-width absolute-top"
              style="top: 0; bottom: 0; min-height: 100%"
            >
              <h3 class="text-right text-weight-thin q-pb-xs" style="margin: -24px -5px 0 0">Connect</h3>
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
                <q-tab name="swarm" label="Swarm" />
                <q-tab name="remoteSign" label="Remote Sign" />
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

                <q-tab-panel name="swarm">
                  <div class="text-h6">Swarm</div>
                  <q-input v-model="RELAY_PEER_ID" label="Relay Peer ID"/>
                  <q-input v-model="RELAY_ADDR" label="Relay Address"/>
                  <q-btn @click="updateSwarm()" label="Update" />
                  <p>
                    {{ swarmInfo }}
                  </p>

                </q-tab-panel>
                <q-tab-panel name="remoteSign">
                  <div class="text-h6">Remote Sign</div>
                  <q-input v-model="remotePeer.id" label="Remote Peer ID"/>
                  <q-input v-model="remotePeer.message" label="Message to Sign" value="test" />
                  <q-input v-model="remotePeer.vault" label="Remote Vault"/>
                  <q-input v-model="remotePeer.location" label="Remote Key Path"/>
                  <q-btn @click="requestSig()" label="Update" />
                  <p>
                    Response: {{ remotePeer.response }}
                  </p>

                </q-tab-panel>
              </q-tab-panels>
            </q-card>
            <router-view v-else/>
          </q-page-container>
        </q-scroll-area>
      </div>
    </div>
  </q-layout>
</template>

<script>
import EssentialLink from 'components/EssentialLink.vue'
import InternalLink from 'components/InternalLink.vue'
import LockTimer from 'components/LockTimer.vue'
// import { invoke } from '@tauri-apps/api/tauri'
import { save } from '@tauri-apps/api/dialog'
import VueQrcode from '@chenfengyuan/vue-qrcode'
require('dotenv').config()

import { Stronghold, Location, Communication } from 'tauri-plugin-stronghold-api'
import { Authenticator } from 'tauri-plugin-authenticator-api'
import { invoke } from '@tauri-apps/api/tauri'

import { mapState, mapActions, mapMutations } from 'vuex'
const _package = require('../../package.json')
const auth = new Authenticator()
const application = 'https://stronghold.iota.org'

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

// not secure, but for this its fine
// todo: use rust
function uuidv4 () {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
    var r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8)
    return v.toString(16)
  })
}

const actionLinks = [
  {
    title: 'Dashboard',
    icon: 'fa fa-book',
    link: '/'
  },
  {
    title: 'Inspector',
    icon: 'fa fa-search',
    link: '/actions/inspect'
  },
  {
    title: 'Connect to Remote',
    icon: 'fa fa-wifi',
    link: '/actions/connect'
  },
  {
    title: 'Manage Coalition',
    icon: 'fa fa-users',
    link: '/actions/coalition'
  },
  {
    title: 'Wipe Stronghold',
    icon: 'fa fa-times',
    link: '/actions/wipe'
  }
]
const linksData = [
  {
    title: 'Docs',
    caption: 'stronghold',
    icon: 'school',
    link: 'https://iotaledger.github.io/stronghold.rs'
  },
  {
    title: 'Github',
    caption: 'iotaledger/stronghold.rs',
    icon: 'fab fa-github',
    link: 'https://github.com/iotaledger/stronghold.rs'
  },
  {
    title: 'Twitter',
    caption: '@iotatoken',
    icon: 'fab fa-twitter',
    link: 'https://twitter.com/iotatoken'
  },
  {
    title: 'Tauri',
    caption: 'Tauri Desktop App System',
    icon: 'fa fa-rocket',
    link: 'https://tauri.studio'
  }
]

export default {
  name: 'MainLayout',
  components: { EssentialLink, InternalLink, LockTimer, VueQrcode },
  data () {
    return {
      RELAY_PEER_ID: process.env.RELAY_PEER_ID,
      RELAY_ADDR: process.env.RELAY_ADDR,
      remotePeer: {
        id: '',
        message: 'test message',
        location: '',
        vault: '',
        path: '',
        response: {}
      },
      newRelayPeerId: null,
      tab: 'outgoing',
      swarmInfo: {},
      connectedToPeer: false,
      remotePeerID: '',
      path: '',
      modelMultiple: ['RequestAlways'],
      options: Object.keys(accessEnum),
      height: window.innerHeight,
      connectee: 'Not Connected',
      actionLinks: actionLinks,
      essentialLinks: linksData,
      version: _package.version,
      loggedIn: false,
      pwd: '',
      status: {},
      isPwd: true,
      yubikey: {
        registered: false,
        signedIn: false
      },
      thumbStyle: {
        right: '4px',
        borderRadius: '5px',
        backgroundColor: '#027be3',
        width: '5px',
        opacity: 0.75
      },
      barStyle: {
        right: '2px',
        borderRadius: '9px',
        backgroundColor: '#027be3',
        width: '9px',
        opacity: 0.2
      }
    }
  },
  computed: {
    ...mapState('lockdown', {
      loading: 'configuring',
      title: 'title',
      locked (state) { return state.lock.enabled }
      // myPeerID (state) { return state.peers.me }
    }),
    thisPeerID () {
      return `${this.status.peerId}:${computeAccess( // $store.state.lockdown.peers.me
        this.modelMultiple
      )}`
    },
    accessVerifier () {
      return decodeAccess(computeAccess(this.modelMultiple))
    }
    /*,
    ...mapState('lockdown', {
      myPeerID (state) {
        return state.myPeerID
      }
    })
    */
  },
  mounted () {
    auth.init() // initialize usb
  },
  methods: {
    ...mapActions('lockdown', ['lock', 'myPeerID']),
    ...mapMutations('lockdown', ['setLocalPeerID']),
    async requestSig () {
      // this.comms.startListening
      this.seedLocation = Location.generic('vault', 'seed')
      const privateKeyLocation = Location.generic('vault', 'derived')
      // const remoteVault = this.comms.getRemoteVault()
      await this.vault.deriveSLIP10([0, 0, 0], 'Seed', this.seedLocation, privateKeyLocation)
      const publicKey = await this.vault.getPublicKey(privateKeyLocation)
      this.$q.notify('got public key ' + publicKey)
      const message = 'Tauri + Stronghold!'
      const signature = await this.vault.sign(privateKeyLocation, message)
      this.$q.notify(`Signed "${message}" and got sig "${signature}"`)
    },
    async updateSwarm () {
      await this.comms.removeRelay(this.RELAY_PEER_ID)
      await this.comms.addPeer(this.RELAY_PEER_ID, this.RELAY_ADDR, 2)
      this.swarmInfo = await this.comms.getSwarmInfo()
    },
    send () {
      invoke('send', {
        payload: {
          pwd: this.pwd,
          path: this.path
        }
      })
        .then((response) => {
          // do something with the Ok() response
          // const { message } = response
          // this.myPeerId = message
          // this.$q.notify(`${message}`)
        })
        .catch((error) => {
          // do something with the Err() response string
          this.$q.notify('error:', error)
        })
    },
    async lockCallback () {
      if (!this.locked) {
        await this.lockdown()
      }
    },
    async register () {
      const challenge = uuidv4()
      this.$q.notify('insert and press yubikey button')
      const r = await auth.register(challenge, application)
      console.log('response: ', r)
      this.$q.notify('yubikey registered')
      this.ykhstore = this.stronghold.getStore('yubikeyHandle', [])
      this.keyhandleLocation = Location.generic('yubikeyKeyhandle', 'value')
      await this.ykhstore.insert(this.keyhandleLocation, r)
      this.ykcstore = this.stronghold.getStore('yubikeyChallenge', [])
      this.challengeLocation = Location.generic('yubikeyChallenge', 'value')
      await this.ykcstore.insert(this.challengeLocation, challenge)
      await this.stronghold.save()
      this.yubikey.registered = true
    },
    async sign () {
      console.log('sign!')
      this.ykcstore = this.stronghold.getStore('yubikeyChallenge', [])
      this.challengeLocation = Location.generic('yubikeyChallenge', 'value')
      this.challenge = await this.ykcstore.get(this.challengeLocation)
      console.log(this.challenge)
      this.ykhstore = this.stronghold.getStore('yubikeyHandle', [])
      this.keyhandleLocation = Location.generic('yubikeyKeyhandle', 'value')
      this.ykhstore.get(this.keyhandleLocation).then(async kh => {
        console.log(this.kh)
        const r = await auth.sign(this.challenge, application, kh)
        this.$q.notify(`=> sign: ${r}`)
        this.yubikey.signedIn = true
      }).catch(e => {
        console.log(e)
      })
    },
    async chooseFile () {
      await save().then(async res => {
        this.path = await res
      })
    },
    async getComms () {
      this.comms = new Communication(this.path)
      this.status = await this.comms.getSwarmInfo()
      if (this.RELAY_PEER_ID) {
        this.comms.addPeer(this.RELAY_PEER_ID, this.RELAY_ADDR, 2)
      }
    },
    async unlock () {
      this.stronghold = new Stronghold(this.path, this.pwd)
      this.comms = await this.stronghold.spawnCommunication(this.path)

      // do it right
      this.status = await this.comms.getSwarmInfo()
      await this.comms.addPeer(this.RELAY_PEER_ID, this.RELAY_ADDR, 2)
      this.swarmInfo = await this.comms.getSwarmInfo()
      this.vault = this.stronghold.getVault('exampleVault', [])
      this.loggedIn = true
      this.ykhstore = this.stronghold.getStore('yubikeyHandle', [])
      this.keyhandleLocation = Location.generic('yubikeyKeyhandle', 'value')
      this.ykhstore.get(this.keyhandleLocation).then(kh => {
        this.yubikey.registered = kh
        console.log('keyHandle:', kh)
      }).catch(e => {
        console.log(e)
      })

      this.seedLocation = Location.generic('vault', 'seed')
      await this.vault.generateBIP39(this.seedLocation)
      const privateKeyLocation = Location.generic('vault', 'derived')
      await this.vault.deriveSLIP10([0, 0, 0], 'Seed', this.seedLocation, privateKeyLocation)
      const publicKey = await this.vault.getPublicKey(privateKeyLocation)
      this.$q.notify('got public key ' + publicKey)
      const message = 'Tauri + Stronghold!'
      const signature = await this.vault.sign(privateKeyLocation, message)
      this.$q.notify(`Signed "${message}" and got sig "${signature}"`)
      this.stronghold.save()

      /*
      invoke('unlock', {
        payload: {
          pwd: this.pwd,
          path: this.path
        }
      }).then(response => {
        // do something with the Ok() response
        const { message } = response
        this.setLocalPeerID(message) // this.myPeerID(message)
        this.$q.notify('Connected to Stronghold')
      }).catch(error => {
        // do something with the Err() response string
        this.$q.notify(`error: ${error}`)
      })
      */
    }
  }
}
</script>
<style lang="sass">
.q-chip__content
  font-size: 0.8em
  padding: 0 3px 0 2px
</style>
