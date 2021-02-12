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
              <q-btn @click="sign" v-if="yubikey.registered" label="Login with Yubikey" />
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
            <router-view />
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
// import { promisified } from 'tauri/api/tauri'
import { save } from 'tauri/api/dialog'
import { Stronghold, Location } from 'tauri-stronghold-api'
import { Authenticator } from 'tauri-authenticator'

import { mapState, mapActions, mapMutations } from 'vuex'
const _package = require('../../package.json')
const auth = new Authenticator()
const application = 'https://stronghold.iota.org'
const challenge = '471257143edcbd893de079a711a193c5' // 32
const challenge2 = '871257143edcbd893de079a711a193c5'

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
  components: { EssentialLink, InternalLink, LockTimer },
  data () {
    return {
      height: window.innerHeight,
      connectee: 'Not Connected',
      actionLinks: actionLinks,
      essentialLinks: linksData,
      version: _package.version,
      loggedIn: false,
      pwd: '',
      isPwd: true,
      path: '',
      yubikey: {
        registered: false
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
    })
  },
  methods: {
    ...mapActions('lockdown', ['lock', 'myPeerID']),
    ...mapMutations('lockdown', ['setLocalPeerID']),
    async lockCallback () {
      if (!this.locked) {
        await this.lockdown()
      }
    },
    async register () {
      auth.init() // initialize usb

      const r = await auth.register(challenge, application)
      this.$q.notify('yubikey registered')
      this.keyhandleLocation = Location.generic('store', 'yubikeyKeyhandle')
      this.challengeLocation = Location.generic('store', 'yubikeyChallenge')
      await this.store.insert(this.keyhandleLocation, r)
      await this.stronghold.save()
      this.yubikey.registered = true
    },
    sign () {
      auth.init() // initialize usb
      console.log('sign!')

      this.keyhandleLocation = Location.generic('store', 'yubikeyKeyhandle')
      this.store.get(this.keyhandleLocation).then(async kh => {
        // const b = Buffer.from(kh, 'base64')
        const r = await auth.sign(challenge2, application, kh)
        this.$q.notify(`=> sign: ${r}`)
      }).catch(e => {
        console.log(e)
      })
    },
    chooseFile () {
      save().then(res => {
        this.path = res
      })
    },
    async unlock () {
      this.stronghold = new Stronghold(this.path, this.pwd)
      this.vault = this.stronghold.getVault('exampleVault', [])
      this.loggedIn = true
      this.store = this.stronghold.getStore('exampleStore', [])
      this.keyhandleLocation = Location.generic('store', 'yubikeyKeyhandle')
      this.store.get(this.keyhandleLocation).then(kh => {
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
      promisified({
        cmd: 'unlock',
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
