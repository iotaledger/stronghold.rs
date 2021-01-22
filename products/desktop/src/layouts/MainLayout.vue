<template>
  <q-layout view="lHh Lpr lFf">
    <q-header elevated>
      <q-toolbar dark>
        <q-btn
          flat
          dense
          round
          aria-label="Menu"
          @click="leftDrawerOpen = !leftDrawerOpen"
        >
          <q-avatar>
            <img src="icon.png">
          </q-avatar>
        </q-btn>
        <q-toolbar-title class="text-weight-bolder">
          Stronghold
        </q-toolbar-title>
        <q-btn
          flat
          dense
          class="float-right q-mr-sm"
          :label="connectee"
          to="/"
        >
        </q-btn>
      </q-toolbar>
    </q-header>

    <q-drawer
      v-model="leftDrawerOpen"
      dark
      show-if-above
      bordered
    >
      <q-list>
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
      <q-list>
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
    </q-drawer>

    <q-page-container>
      <router-view />
    </q-page-container>
    <q-footer>
      <div class="full-width text-center">
        <div class="float-right q-mr-sm text-weight-light text-black">v{{ version }}</div>
      </div>
    </q-footer>
  </q-layout>
</template>

<script>
import EssentialLink from 'components/EssentialLink.vue'
import InternalLink from 'components/InternalLink.vue'
const _package = require('../../package.json')
const actionLinks = [
  {
    title: 'Dashboard',
    icon: 'fa fa-book',
    link: '/'
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
  components: { EssentialLink, InternalLink },
  data () {
    return {
      connectee: 'Not Connected',
      actionLinks: actionLinks,
      essentialLinks: linksData,
      version: _package.version,
      leftDrawerOpen: false
    }
  }
}
</script>
