# out: ../lib/interface.js
module.exports = (samjs, auth) =>
  getUserByToken = null
  setTokenForUser = null
  samjs.after.options.call (options) =>
    if options.dev
      getUserByToken = (token) =>
        {data} = await samjs.configs.tokenStore.get()
        return storedItem if data and (storedItem = data[token])
        throw new Error "Unsuccessfully"
      setTokenForUser = (token, user) =>
        {data} = await samjs.configs.tokenStore.get()
        data ?= {}
        data[token] = user
        samjs.configs.tokenStore.set(data: data)
    else
      tokenStore = {}
      timeouts = {}
      getUserByToken = (token) =>
        if (storedItem = tokenStore[token])?
          await timeouts[token]?() 
          return storedItem
        throw new Error "Unsuccessfully"
      setTokenForUser = (token, user) =>
        tokenStore[token] = user
        tmp = timeouts[token] = =>
          clearTimeout(tmp.timoutObj) if tmp.timoutObj
          tmp.timoutObj = setTimeout (=> delete tokenStore[token]), options.tokenExpiration
        tmp()

  return (socket) =>
    socket.on "unauth", (cb) =>
      socket.disconnect(true)
      cb()
    socket.on "auth.byToken", (request, cb) =>
      getUserByToken(request)
      .then (user) => 
        auth.after.login(socket: socket, user: user, token: request)
        success:true, content: auth.userCleaner(user)
      .catch (err) =>
        success:false, content:err?.message
      .then cb
    socket.on "auth", (request, cb) =>
      auth.findUser(request)
      .then (user) =>
        token = await samjs.helper.generateToken samjs.options.tokenSize
        setTokenForUser(token, user)
        cleaned = auth.userCleaner(user)
        cleaned.token = token
        auth.after.login(socket: socket, user: user, token: token)
        success:true, content: cleaned
      .catch (e) =>
        success:false, content: e?.message
      .then cb
