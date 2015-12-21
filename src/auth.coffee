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
          return @permissionCheckers[permissionChecker](permission, user)
        else if samjs.util.isFunction(permissionChecker)
          return permissionChecker(permission, user)
        return false
      isAllowed = (client,mode,permissionCheckers) ->
        throw new Error("no permission") unless permission = @[mode]
        throw new Error("invalid socket - no auth") unless client?.auth?.getUser?
        throw new Error("not logged in") unless user = client.auth.getUser()
        return if callPermissionChecker(permission,user)
        throw new Error("no permission")
      @isAllowed = isAllowed
      @configs = [{
          name: "users"
          isRequired: true
          read: ["root"]
          write: ["root"]
          test: (users) -> new samjs.Promise (resolve,reject) ->
            if users? and samjs.util.isArray(users) and users.length > 0
              for user in users
                unless user[samjs.options.username]? and user[samjs.options.password]?
                  reject(new Error ("Username and password required"))
                  return
              resolve()
            else
              reject()
          hooks:
            before_Set: ({data}) =>
              return new samjs.Promise (resolve, reject) =>
                promises = []
                for user in data
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
        }]
      @hooks = configs:
        beforeTest: ({data, client}) ->
          isAllowed.bind(@)(client,"write")
          return data: data, client:client
        beforeGet: ({client}) ->
          isAllowed.bind(@)(client,"read")
          return client: client
        beforeSet: ({data, client}) ->
          isAllowed.bind(@)(client,"write")
          return data: data, client:client
      @interfaces = auth: require("./interface")(samjs,@)
    findUser: (name) ->
      samjs.configs.users._get()
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
