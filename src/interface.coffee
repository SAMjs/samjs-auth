# out: ../lib/interface.js
module.exports = (samjs, auth) ->
  tokenStore = {}

  return (socket) ->
    socket.on "disconnect", () ->
      if socket.client?.auth?.token?
        token = socket.client.auth.token
        if tokenStore[token]
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
        storedItem = tokenStore[token]
        if storedItem
          if storedItem.removeTimeout
            storedItem.removeTimeout()
          storedItem.resetLongTimeout()
          user = storedItem.user
          content = samjs.helper.clone user
          delete content[samjs.options.password]
          success = true
          socket.client.auth.user = user
          socket.client.auth.token = token
        socket.emit "auth.byToken."+request.token,
          {success: success, content: content}
    socket.on "auth", (request) ->
      if request? and request.content? and
          request.content[samjs.options.username]? and
          request.content[samjs.options.password]? and
          request.token?
        auth.findUser(request.content[samjs.options.username])
        .then (user) ->
          auth.comparePassword user, request.content[samjs.options.password]
        .then (user) ->
          return auth.crypto.generateToken samjs.options.tokenSize
          .then (token) ->
            success = true
            content = samjs.helper.clone user
            content.token = token
            delete content[samjs.options.password]
            tokenStore[token] = {user:user}
            tokenStore[token].resetLongTimeout = () ->
              if timoutObj
                clearTimeout(timoutObj)
              timoutObj = setTimeout (() -> delete tokenStore[token]),
                samjs.options.tokenExpiration*50
            tokenStore[token].resetLongTimeout()
            socket.client.auth.user = user
            socket.client.auth.token = token
            return content
        .then (content) -> success:true,  content: content
        .catch (e) ->      success:false, content: false
        .then (response) ->
          socket.emit "auth."+request.token, response
      else
        socket.emit "auth" + request.token, {success:false, content: false}
