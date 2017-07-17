module.exports = (samjs) => new class Auth
  constructor: ->
    samjs.hookup @
    @hooks.register ["login","logout"]
    @crypto = require("./crypto")(samjs)
  findUser: (toFind) ->
    username = samjs.options.username
    users = await samjs.configs.users.getBare()
    users = users.data
    user = users?.find (user) => user[username] == toFind[username]
    throw new Error "not found" unless user?
    @crypto.comparePassword(toFind, user)
  userCleaner: (user) ->
    user = samjs.helper.clone(user)
    delete user[samjs.options.password]
    return user