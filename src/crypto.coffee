# out: ../lib/crypto.js

module.exports = (samjs) ->
  bcrypt = samjs.Promise.promisifyAll(require("bcryptjs"))
  return new class Crypto
    generateHashedPassword: (user,next) ->
      bcrypt.genSaltAsync samjs.options.saltWorkFactor
      .then (salt) ->
        return bcrypt.hashAsync user[samjs.options.password], salt
      .then (hash) ->
        user[samjs.options.password] = hash
        user.hashed = true
        next()
    comparePassword: (providedPassword,realPassword) ->
      return new samjs.Promise (resolve,reject) ->
        bcrypt.compareAsync providedPassword, realPassword
        .then (isMatch) ->
          if isMatch
            resolve()
          else
            reject()
