# out: ../lib/main.js
path = require "path"
module.exports = (options) -> (samjs) ->
  debug = samjs.debug("auth")
  options ?= {}
  options.dev ?= process.env.NODE_ENV != "production"
  return new class Auth
    constructor: ->
      @crypto = require("./crypto")(samjs)
      samjs.helper.initiateHooks @, [], ["afterLogin","afterLogout"]
      @name = "auth"
      @develop = options.dev
      @options =
        saltWorkFactor: 10
        tokenExpiration: 1000*60*30 # 30 minutes
        tokenSize: 48
        username: "name"
        password: "pwd"
        rootUser: "root"
        authOptions:
          authRequired: false
          permissionChecker: "containsUser"

      @permissionCheckers =
        containsUser: (user, permission, options) ->
          if options.getIdentifier
            if user?
              return user[samjs.options.username]
            else
              return "__public"
          if permission == true
            if !options.authRequired or user?
              return true
          else if user?
            if samjs.util.isString(permission)
              return true if permission == user[samjs.options.username]
            else if samjs.util.isArray(permission)
              return true if permission.indexOf(user[samjs.options.username]) > -1
          return false


      callPermissionChecker = (user, permission, options) =>
        options ?= {}
        pc = options.permissionChecker
        pc ?= samjs.options.authOptions.permissionChecker
        options.authRequired ?= samjs.options.authOptions.authRequired
        if samjs.util.isArray(pc)
          if options.getIdentifier
            return user[samjs.options.username]
          else if options.all
            allowed = 0
            for checker in pc
              allowed += 1 if callPermissionChecker(user, permission,
                Object.assign({permissionChecker:checker},options))
            return (allowed == pc.length)
          else
            for checker in pc
              return true if callPermissionChecker(user, permission,
                Object.assign({permissionChecker:checker},options))

        else if samjs.util.isString(pc)
          unless @permissionCheckers[pc]?
            throw new Error("#{pc} not defined")
          return @permissionCheckers[pc](user, permission, options)
        else if samjs.util.isFunction(pc)
          return pc(user, permission, options)
        return false

      getAllowance = (user, permission, options) ->
        return "no permission" unless permission?
        return "" if callPermissionChecker(user, permission, options)
        return "no permission"

      isAllowed = (socket, permission, options) ->
        throw new Error "invalid socket - no auth" unless socket.client?.auth?
        result = getAllowance(socket.client.auth.user, permission, options)
        return true if result == ""
        throw new Error(result)

      @isAllowed = isAllowed
      @getAllowance = getAllowance
      @callPermissionChecker = callPermissionChecker
      @configs = [{
          name: "users"
          installComp:
            paths: [path.resolve(__dirname, "./createUser")]
            icons: ["ma-person","ma-vpn_key"]
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
              config.access.read ?= [samjs.options.rootUser]
              config.access.write ?= [samjs.options.rootUser]
              return config
            before_Set: (obj) =>
              return new samjs.Promise (resolve, reject) =>
                promises = []
                for user in obj.data
                  unless user[samjs.options.password]
                    for oldUser in obj.oldData
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
                .then -> resolve obj
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
        beforeTest: (obj) ->
          isAllowed(obj.socket,@access.write,@authOptions)
          return obj
        beforeGet: (obj) ->
          isAllowed(obj.socket,@access.read,@authOptions)
          return obj
        beforeSet: (obj) ->
          isAllowed(obj.socket,@access.write,@authOptions)
          return obj
      @interfaces = auth: require("./interface")(samjs,@)
    findUser: (name) ->
      samjs.configs.users._getBare()
      .then (users) ->
        if users?
          for user in users
            if user[samjs.options.username] == name
              return user
    userConverter: (user) -> samjs.helper.clone(user)
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
    startup: (obj) ->
      if samjs.io?
        samjs.io.use (socket,next) ->
          socket.client.auth ?= {}
          next()
      return obj
