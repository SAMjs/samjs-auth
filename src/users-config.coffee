path = require "path"
module.exports = (samjs, auth) =>
  name: "users"
  installComp:
    paths: [path.resolve(__dirname, "./create-user")]
    icons: ["ma-person","ma-vpn_key"]
  isRequired: true
  test: ({data, oldData}) => 
    if data? and samjs.util.isArray(data) and data.length > 0
      rootUser = false
      for user in data
        unless user[samjs.options.username]?
          throw new Error "Username for all users required"
        else if user[samjs.options.username] == samjs.options.rootUser
          rootUser = true
        unless user[samjs.options.password]?
          found = false
          if oldData?
            for oldUser in oldData
              if oldUser[samjs.options.username] == user[samjs.options.username]
                found = true
                break
          unless found
            throw new Error "Password for all users required"
      unless rootUser
        throw new Error "No root user was set"
    else
      throw new Error "Provided users array invalid"
  installInterface: (socket) ->
    socket.on "auth.getInstallationInfo", (request) ->
      if request.token?
        obj =
          success: true
          content:
            rootUser: samjs.options.rootUser
            password: samjs.options.password
            username: samjs.options.username
        socket.emit "auth.getInstallationInfo.#{request.token}", obj
    return -> socket.removeAllListeners("auth.getInstallationInfo")
  hooks:
    set:
      before: 
        prio: samjs.prio.POST_PROCESS
        hook: (o) =>
          for user in o.data
            unless user[samjs.options.password]
              for oldUser in o.oldData
                if oldUser[samjs.options.username] == user[samjs.options.username]
                  user[samjs.options.password] = oldUser[samjs.options.password]
                  user.hashed = oldUser.hashed
                  break
            else
              await auth.crypto.generateHashedPassword(user)
    get:
      after: 
        prio: samjs.prio.PREPARE
        hook: (o) =>
          cleaned = []
          for user in o.data
            cleanUser = samjs.helper.clone user
            delete cleanUser[samjs.options.password]
            delete cleanUser.hashed
            cleaned.push cleanUser
          o.data = cleaned
