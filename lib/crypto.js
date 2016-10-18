(function() {
  var randomBytes;

  randomBytes = require("crypto").randomBytes;

  module.exports = function(samjs) {
    var Crypto, bcrypt;
    bcrypt = samjs.Promise.promisifyAll(require("bcryptjs"));
    return new (Crypto = (function() {
      function Crypto() {}

      Crypto.prototype.generateHashedPassword = function(user, next) {
        return bcrypt.genSaltAsync(samjs.options.saltWorkFactor).then(function(salt) {
          return bcrypt.hashAsync(user[samjs.options.password], salt);
        }).then(function(hash) {
          user[samjs.options.password] = hash;
          user.hashed = true;
          return next();
        });
      };

      Crypto.prototype.comparePassword = function(providedPassword, realPassword) {
        return new samjs.Promise(function(resolve, reject) {
          return bcrypt.compareAsync(providedPassword, realPassword).then(function(isMatch) {
            if (isMatch) {
              return resolve();
            } else {
              return reject();
            }
          });
        });
      };

      Crypto.prototype.generateToken = function(size) {
        return new samjs.Promise(function(resolve, reject) {
          try {
            return resolve(randomBytes(size).toString("base64"));
          } catch (error) {
            return reject();
          }
        });
      };

      return Crypto;

    })());
  };

}).call(this);
