# out: ../lib/interface.js
module.exports = (samjs, auth) ->
  if auth.develop
    getUserByToken = (token) ->
      samjs.configs.tokenStore._get()
      .then (value) -> return value && value[token]
    setTokenForUser = (token, user) ->
      samjs.configs.tokenStore._get()
      .then (value) ->
        value ?= {}
        value[token] = {user:user}
        return value
      .then samjs.configs.tokenStore._set
  else
    tokenStore = {}
    getUserByToken = (token) ->
      samjs.Promise.resolve(tokenStore[token]).then (storedItem) ->
        if storedItem?
          if storedItem.removeTimeout
            storedItem.removeTimeout()
          storedItem.resetLongTimeout()
        return storedItem
    setTokenForUser = (token, user) ->
      tokenStore[token] = {user:user}
      tokenStore[token].resetLongTimeout = () ->
        if timoutObj
          clearTimeout(timoutObj)
        timoutObj = setTimeout (() -> delete tokenStore[token]),
          samjs.options.tokenExpiration*50
      tokenStore[token].resetLongTimeout()

  return (socket) ->
    socket.on "disconnect", () ->
      if socket.client?.auth?.token?
        token = socket.client.auth.token
        if tokenStore?[token]
          timoutObj = setTimeout (() -> delete tokenStore[token]),
            samjs.options.tokenExpiration
          if tokenStore[token].removeTimeout
            tokenStore[token].removeTimeout()
          tokenStore[token].removeTimeout = () ->
            clearTimeout(timoutObj)

    socket.on "auth.byToken", (request) ->
      success = false
      content = false
      if request? and request.token? and request.content?
        token = request.content
        getUserByToken(token)
        .then (storedItem) ->
          if storedItem
            user = storedItem.user
            content = auth.userConverter(user)
            delete content[samjs.options.password]
            success = true
            socket.client.auth ?= {}
            socket.client.auth.user = user
            socket.client.auth.token = token
            auth._hooks.afterLogin(socket: socket, user: user)
          socket.emit "auth.byToken."+request.token,
            {success: success, content: content}
    socket.on "auth", (request) ->
      if request? and request.content? and
          request.content[samjs.options.username]? and
          request.content[samjs.options.password]? and
          request.token?
        auth.findUser(request.content[samjs.options.username])
        .then (user) ->
          throw new Error "user not found" unless user?
          auth.comparePassword user, request.content[samjs.options.password]
        .then (user) ->
          return samjs.helper.generateToken samjs.options.tokenSize
          .then (token) ->
            content = auth.userConverter(user)
            content.token = token
            delete content[samjs.options.password]
            setTokenForUser(token, user)
            socket.client.auth ?= {}
            socket.client.auth.user = user
            socket.client.auth.token = token
            auth._hooks.afterLogin(socket: socket, user: user)
            return content
        .then (content) -> success:true,  content: content
        .catch (e) ->      success:false, content: e?.message
        .then (response) ->
          socket.emit "auth."+request.token, response
      else
        socket.emit "auth" + request.token, {success:false, content: false}
