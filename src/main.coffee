# out: ../lib/main.js
module.exports = (options) -> (samjs) ->
  debug = samjs.debug("auth")
  options ?= {}
  return new class Auth
    constructor: ->
      @crypto = require("./crypto")(samjs)
      @name = "auth"
      @develop = options.dev
      @options =
        saltWorkFactor: 10
        tokenExpiration: 1000*60*30 # 30 minutes
        tokenSize: 48
        username: "name"
        password: "pwd"
        rootUser: "root"
        permissionChecker: "containsUser"

      @permissionCheckers =
        containsUser: (permission, user) ->
          if permission == true
            return true
          else if user?
            if samjs.util.isString(permission)
              return true if permission == user[samjs.options.username]
            else if samjs.util.isArray(permission)
              return true if permission.indexOf(user[samjs.options.username]) > -1
          return false

      callPermissionChecker = (permission, user, permissionChecker) =>
        permissionChecker ?= samjs.options.permissionChecker
        if samjs.util.isArray(permissionChecker)
          # any
          for checker in permissionChecker
            return true if callPermissionChecker(permission,user,checker)
          # all
          # allowed = 0
          # for checker in permissionChecker
          #   allowed += 1 if callPermissionChecker(permission,user,checker)
          # return (allowed == permissionChecker.length)
        else if samjs.util.isString(permissionChecker)
          unless @permissionCheckers[permissionChecker]?
            throw new Error("#{permissionChecker} not defined")
          return @permissionCheckers[permissionChecker](permission, user)
        else if samjs.util.isFunction(permissionChecker)
          return permissionChecker(permission, user)
        return false

      getAllowance = (user,permission,permissionChecker) ->
        return "no permission" unless permission?
        return "" if callPermissionChecker(permission,user,permissionChecker)
        return "no permission"

      isAllowed = (client,permission,permissionChecker) ->
        throw new Error "invalid socket - no auth" unless client.auth?
        result = getAllowance(client.auth.user,permission,permissionChecker)
        return true if result == ""
        throw new Error(result)

      @isAllowed = isAllowed
      @getAllowance = getAllowance
      @configs = [{
          name: "users"
          isRequired: true
          test: (users, oldUsers) -> new samjs.Promise (resolve,reject) ->
            if users? and samjs.util.isArray(users) and users.length > 0
              rootUser = false
              for user in users
                unless user[samjs.options.username]?
                  reject(new Error ("Username for all users required"))
                  return
                else if user[samjs.options.username] == samjs.options.rootUser
                  rootUser = true
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
              unless rootUser
                reject(new Error("No root user was set"))
              resolve()
            else
              reject()
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
            afterCreate: (config) ->
              config.read ?= [samjs.options.rootUser]
              config.write ?= [samjs.options.rootUser]
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
      if @develop
        @configs.push {
          name: "tokenStore"
        }
      @hooks = configs:
        beforeTest: ({data, client}) ->
          isAllowed(client,@write,@permissionChecker)
          return data: data, client:client
        beforeGet: ({client}) ->
          isAllowed(client,@read,@permissionChecker)
          return client: client
        beforeSet: ({data, client}) ->
          isAllowed(client,@write,@permissionChecker)
          return data: data, client:client
      @interfaces = auth: require("./interface")(samjs,@)
    findUser: (name) ->
      samjs.configs.users._getBare()
      .then (users) ->
        if users?
          for user in users
            if user[samjs.options.username] == name
              return user
    userConverter: (user) -> samjs.helper.clone(user)
    afterAuth: []
    callAfterAuthHooks: (user) ->
      for authHook in @afterAuth
        authHook(user)
    replaceUserHandler: (findUserFunc, userConverter) =>
      @findUser = findUserFunc
      @userConverter = userConverter if userConverter?
      @configs.shift()
      if @configs.length == 0
        delete @configs
    comparePassword: (user, providedPassword) =>
      return @crypto.comparePassword providedPassword, user[samjs.options.password]
        .then -> return user
    debug: (name) ->
      samjs.debug("auth:#{name}")
