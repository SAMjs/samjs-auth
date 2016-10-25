<template lang="pug">
.card.black-text
  .card-content
    span.card-title.black-text Create root user
    .row
      input-field.s12(
        readonly
        label="Username"
        v-bind:value="userName"
      )
        icon.prefix(slot="icon" name="material-person")
      input-field.s12(
        autofocus
        v-bind:validate="validatePw"
        data-error="use at least 8 characters"
        label="Password"
        type="password"
        v-bind:value.sync="userPwd"
        @confirm="triggerNext"
      )
        icon.prefix(slot="icon" name="material-vpn_key")
  slot
</template>
<script lang="coffee">
module.exports =
  props: ["samjs"]
  components:
    icon: require("vmat/icon")
    inputField: require("vmat/input-field")
  data: ->
    userName: " "
    userPwd: ""
  methods:
    validatePw: (pw) ->
      @$emit "validity-changed", pw.length >= 8
    next: ->
      @samjs.auth.createRoot @userPwd
    triggerNext: -> @$emit "next"
  ready: ->
    @samjs.plugins require "samjs-auth-client"
    @samjs.install.isInConfigMode()
    .then (nsp) => @samjs.io.nsp(nsp).getter "auth.getInstallationInfo"
    .then (info) => @userName = info.rootUser
    @$emit "validity-changed", false
</script>
