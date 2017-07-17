ceri = require "ce/wrapper"
module.exports = ceri
  mixins: [
    require "ce/structure"
    require "ce/class"
    require "ce/#model"
    require "ce/computed"
  ]
  structure: template 1, """
    <span class="card-title black-text">Create root user</span>
    <div class=row>
      <div class="input-field col s12">
        <ceri-icon class=prefix name="ma-person"></ceri-icon>
        <input 
          #model=name 
          disabled
          />
        <label #ref=nameLabel class=active>Username</label>
      </div>

      <div class="input-field col s12">
        <ceri-icon class=prefix name="ma-vpn_key"></ceri-icon>
        <input 
          #ref=pwInput 
          #model=pw
          @keyup=onKeyup
          type="password"
          @focus=onActivePW
          @blur=onActivePW
          />
        <label style="pointer-events: none;" #ref=pwLabel>Password</label>
      </div>
    </div>
  """

  data: ->
    name: ""
    pw: ""
  computed:
    isValid: -> @pw.length >=8
    
  methods:
    next: -> @samjs.auth.createRoot @pw
    onActivePW: ->
      if @pwInput != document.activeElement and @pwInput.value == ""
        @$class.setStr @pwLabel, ""
      else
        @$class.setStr @pwLabel, "active"
    onKeyup: (e) ->
      return if e.keyCode != 13
      @finished()
    
  connectedCallback: ->
    @samjs.plugins require "samjs-auth-client"
    @samjs.install.isInConfigMode()
    .then (nsp) => @samjs.io.nsp(nsp).getter "auth.getInstallationInfo"
    .then (info) => @name = info.rootUser
    @pwInput.focus()