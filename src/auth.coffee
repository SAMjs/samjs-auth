# out: ../lib/auth.js
module.exports = (samjs) ->
  debug = samjs.debug("auth")
  return new class Auth
    constructor: ->
      @crypto = require("./crypto")(samjs)
      @name = "auth"
      @options =
        saltWorkFactor: 10
        tokenExpiration: 1000*60*30 # 30 minutes
        tokenSize: 48
        username: "name"
        password: "pwd"
        permissionChecker: "containsUser"
      @permissionCheckers =
        containsUser: (permission, user) ->
          if permission == true
            return true
          else if samjs.util.isString(permission)
            return true if permission == user[samjs.options.username]
          else if samjs.util.isArray(permission)
            return true if permission.indexOf(user[samjs.options.username]) > -1
          return false
      callPermissionChecker = (permission, user, permissionChecker) =>
        permissionChecker ?= samjs.options.permissionChecker
        if samjs.util.isArray(permissionChecker)
          allowed = 0
          for checker in permissionChecker
            allowed += 1 if callPermissionChecker(permission,user,checker)
          return (allowed == permissionChecker.length)
        else if samjs.util.isString(permissionChecker)
          unless @permissionCheckers[permissionChecker]?
            throw new Error("#{permissionChecker} not defined")
          return @permissionCheckers[permissionChecker](permission, user)
        else if samjs.util.isFunction(permissionChecker)
          return permissionChecker(permission, user)
        return false
      isAllowed = (client,permission,permissionCheckers) ->
        throw new Error("no permission") unless permission?
        throw new Error("invalid socket - no auth") unless client.auth?
        throw new Error("not logged in") unless user = client.auth.getUser()
        return if callPermissionChecker(permission,user,permissionCheckers)
        throw new Error("no permission")
      @isAllowed = isAllowed
      @configs = [{
          name: "users"
          isRequired: true
          read: ["root"]
          write: ["root"]
          test: (users, oldUsers) -> new samjs.Promise (resolve,reject) ->
            if users? and samjs.util.isArray(users) and users.length > 0
              for user in users
                unless user[samjs.options.username]?
                  reject(new Error ("Username for all users required"))
                  return
                unless user[samjs.options.password]?
                  found = false
                  if oldUsers?
                    for oldUser in oldUsers
                      if oldUser[samjs.options.username] == user[samjs.options.username]
                        found = true
                        break
                  unless found
                    reject(new Error ("Password for all users required"))
                    return
              resolve()
            else
              reject()
          hooks:
            before_Set: ({data,oldData}) =>
              return new samjs.Promise (resolve, reject) =>
                promises = []
                for user in data
                  unless user[samjs.options.password]
                    for oldUser in oldData
                      if oldUser[samjs.options.username] == user[samjs.options.username]
                        user[samjs.options.password] = oldUser[samjs.options.password]
                        user.hashed = oldUser.hashed
                  unless user.hashed
                    promise = new samjs.Promise (resolve, reject) =>
                      try
                        @crypto.generateHashedPassword(user,resolve)
                      catch e
                        reject e
                    promises.push promise
                samjs.Promise.all(promises)
                .then -> resolve data: data
                .catch reject
            after_Get: (users) ->
              newUsers = []
              for user in users
                newUser = samjs.helper.clone user
                delete newUser[samjs.options.password]
                delete newUser.hashed
                newUsers.push newUser
              return newUsers

        }]
      @hooks = configs:
        beforeTest: ({data, client}) ->
          isAllowed(client,@write,@permissionCheckers)
          return data: data, client:client
        beforeGet: ({client}) ->
          isAllowed(client,@read,@permissionCheckers)
          return client: client
        beforeSet: ({data, client}) ->
          isAllowed(client,@write,@permissionCheckers)
          return data: data, client:client
      @interfaces = auth: require("./interface")(samjs,@)
    findUser: (name) ->
      samjs.configs.users._getBare()
      .then (users) ->
        if users?
          for user in users
            if user[samjs.options.username] == name
              return user
    replaceUserHandler: (findUserFunc) =>
      @findUser = findUserFunc
      delete @configs
    comparePassword: (user, providedPassword) =>
      return @crypto.comparePassword providedPassword, user[samjs.options.password]
        .then -> return user
    debug: (name) ->
      samjs.debug("auth:#{name}")
    startup: ->
      debug "adding auth property to clients"
      samjs.io.use (socket,next) ->
        socket.client.auth ?= {}
        socket.client.auth.getUser = ->
          if socket.client.auth.user?
            return socket.client.auth.user
          else
            return false
        next()
