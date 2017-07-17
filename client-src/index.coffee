# out: ../lib/main.js
emitter = require("component-emitter");
module.exports = (samjs, options) -> samjs.auth = new class Auth
  constructor: ->
    socket = samjs.io.socket("/auth", options)
    @getter = samjs.wrapEmit(socket)
    @token = localStorage?.getItem?("token")
    emitter(@)
    socket.on "connect", => 
      @login().catch =>
        @token = null
        localStorage?.removeItem?("token")
    @setupReconnect(samjs.config.socket)
    return @
  createRoot: (password) ->
    samjs.install.configGetter("getInstallationInfo","auth")
    .then (info) ->
      userobj = {}
      userobj[info.username] = info.rootUser
      userobj[info.password] = password
      samjs.install.set("users",[userobj])
  setupReconnect: (socket) ->
    @on "changed", (user) ->
      if user?
        socket.disconnect()
        socket.connect()
  logout: ->
    @getter "unauth"
    .then =>
      @token = null
      localStorage?.removeItem?("token")
      @user = null
      @emit "changed"
  login: (user) ->
    return samjs.Promise.resolve(@user) if @user
    if user
      @getter "auth", user
      .then (result) =>
        @user = result
        @token = result.token
        @emit "changed", result
        localStorage?.setItem?("token",@token)
        delete result.token
        return result

    else if @token?
      @getter "auth.byToken", @token
      .then (result) =>
        @user = result
        @emit "changed", result
        return result
    else
      return samjs.Promise.reject(new Error "no auto login possible")
