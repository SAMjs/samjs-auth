# out: ../lib/main.js
processAccess = (cb, o) =>
  return if cb == true
  throw new Error "not logged in" if o.socket? and not (user = o.socket.client.auth?.user)?
  cb(o) if user?

getCallback = (access, name, allow) =>
  return cb if (cb = access?[name])?
  return => throw new Error "forbidden" unless allow
  return false

hierarchy = [
              connect: 
                cmds: ["listen"]
                children:[
                  { write: cmds: ["set", "test"] }
                  { read: cmds: ["get"] }
                ]
              ]

module.exports = (samjs) =>
  debug = samjs.debug.auth

  auth = samjs.auth = require("./auth")(samjs)
  
  auth.parseAccess = (obj, hierarchy) =>
    gC = getCallback.bind null, obj.access
    before = obj.before
    parse = (currentLvl, allow) =>
      for o in currentLvl
        if samjs.util.isString(o)
          name = o
          o = {}
          o[name] = {}
        for acc, o2 of o
          if found = (cb = gC(acc, allow))?
            for cmd in (o2.cmds or [acc])
              before[cmd].call
                prio: samjs.prio.ACCESS
                hook: processAccess.bind(null,cb)
          if o2.children
            parse(o2.children, allow or found)
    parse(hierarchy, false)
        
  samjs.before.options.call
    prio: samjs.prio.ADD_DEFAULTS
    hook: (options) =>
      samjs.helper.merge options, 
        saltWorkFactor: 10
        tokenExpiration: 0x7FFFFFFF
        tokenSize: 48
        username: "name"
        password: "pwd"
        rootUser: "root"

  samjs.before.configs.call
    prio: samjs.prio.ADD_DEFAULTS
    hook: (configs) =>
      unless (configs.find (config) => config.name == "users")
        configs.push require("./users-config")(samjs, auth)
      if samjs.options.dev
        unless (configs.find (config) => config.name == "tokenStore")
          configs.push name: "tokenStore"
  
  samjs.after.configs.call
    prio: samjs.prio.POST_PROCESS
    hook: (configs) =>
      for name, config of configs
        unless ~config.plugins.indexOf("noAuth")
          auth.parseAccess config, hierarchy
          ###gC = getCallback.bind null, config.access
          if hasConnect = (cb = gC("connect"))?
            config.before.listen.call
              prio: samjs.prio.ACCESS
              hook: processAccess.bind(null,cb)
          if (cb = gC("write", hasConnect))?
            config.before.test.call
              prio: samjs.prio.ACCESS
              hook: processAccess.bind(null,cb)
            config.before.set.call
              prio: samjs.prio.ACCESS
              hook: processAccess.bind(null,cb)
          if (cb = gC("read", hasConnect))?
            config.before.get.call
              prio: samjs.prio.ACCESS
              hook: processAccess.bind(null,cb)###

  samjs.helper.hookInterface samjs, "auth", require("./interface")(samjs, auth)

  auth.after.login.call
    prio: samjs.prio.PREPARE
    hook: ({socket, user, token}) =>
      socket.client.auth = user: user, token:token