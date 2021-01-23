<template>
  <q-circular-progress
    show-value
    class="text-white q-ma-md"
    :value="lock.value"
    :min="0"
    :max="lockMaxValue"
    size="64px"
    :thickness="0.18"
    :color="lockRingColor"
    track-color="transparent"
    style="margin:0 0 0 -5px;z-index:5000;position:absolute"
    @click="lockCallback"
  >
    <q-avatar id="lock" :icon="lockIcon" :color="lockBadgeColor" :text-color="lockTextColor" size="74px" font-size="0.25em">
      <img src="iota.png" class="quasar-turny-magic" />
    </q-avatar>
  </q-circular-progress>
</template>
<script>
import { mapState } from '../utils/mapper'
import { mapGetters, mapActions } from 'vuex'

export default {
  name: 'ComponentAuEditor',
  data () {
    return {
      interval: 0
    }
  },
  computed: {
    ...mapState('lockdown', { lock: 'lock' }),
    ...mapGetters('lockdown', { lockMaxValue: 'lockMaxValue' }),
    lockIcon () {
      return this.lock.enabled ? 'fas fa-lock' : 'fas fa-unlock'
    },
    lockBadgeColor () {
      return this.lock.enabled ? 'green' : 'orange'
    },
    lockTextColor () {
      return this.lock.enabled ? 'white' : 'black'
    },
    lockRingColor () {
      if (this.lock.enabled) {
        return 'white'
      }
      var value = this.lock.value * 100 / this.lockMaxValue
      switch (true) {
        case value <= 33: return 'red'
        case value <= 66: return 'yellow'
        default: return 'green'
      }
    }
  },
  methods: {
    ...mapActions('lockdown', ['lockup', 'lockdown']),
    async lockCallback () {
      if (!this.lock.enabled) {
        await this.lockdown()
      }
    }
  },
  mounted () {
    this.lock.value = this.lockMaxValue
  }
}
</script>
<style lang="sass">
  i.fa-lock::before, i.fa-unlock::before
    position: absolute
    top: 25px
  img.quasar-turny-magic
    postion: absolute
    margin-top: -20px
    animation: logo-rotate 180s linear infinite
    height: 66px
    width: 66px
  @keyframes logo-rotate
    100%
      transform: rotate(360deg)
      transform-origin: center center
</style>
