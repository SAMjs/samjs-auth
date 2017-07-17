# out: ../lib/crypto.js
bcrypt = require "bcrypt"
module.exports = ({options}) =>
  generateHashedPassword: (user) =>
    return if user.hashed
    hash = await bcrypt.hash user[options.password], options.saltWorkFactor
    user[options.password] = hash
    user.hashed = true
  comparePassword: (login, user) =>
    isMatch = await bcrypt.compare login[options.password], user[options.password]
    throw new Error "Wrong password" unless isMatch
    return user