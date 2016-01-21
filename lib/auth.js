(function() {
  var bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; };

  module.exports = function(samjs) {
    var Auth, debug;
    debug = samjs.debug("auth");
    return new (Auth = (function() {
      function Auth() {
        this.comparePassword = bind(this.comparePassword, this);
        this.replaceUserHandler = bind(this.replaceUserHandler, this);
        var callPermissionChecker, isAllowed;
        this.crypto = require("./crypto")(samjs);
        this.name = "auth";
        this.options = {
          saltWorkFactor: 10,
          tokenExpiration: 1000 * 60 * 30,
          tokenSize: 48,
          username: "name",
          password: "pwd",
          permissionChecker: "containsUser"
        };
        this.permissionCheckers = {
          containsUser: function(permission, user) {
            if (permission === true) {
              return true;
            } else if (samjs.util.isString(permission)) {
              if (permission === user[samjs.options.username]) {
                return true;
              }
            } else if (samjs.util.isArray(permission)) {
              if (permission.indexOf(user[samjs.options.username]) > -1) {
                return true;
              }
            }
            return false;
          }
        };
        callPermissionChecker = (function(_this) {
          return function(permission, user, permissionChecker) {
            var allowed, checker, i, len;
            if (permissionChecker == null) {
              permissionChecker = samjs.options.permissionChecker;
            }
            if (samjs.util.isArray(permissionChecker)) {
              allowed = 0;
              for (i = 0, len = permissionChecker.length; i < len; i++) {
                checker = permissionChecker[i];
                if (callPermissionChecker(permission, user, checker)) {
                  allowed += 1;
                }
              }
              return allowed === permissionChecker.length;
            } else if (samjs.util.isString(permissionChecker)) {
              if (_this.permissionCheckers[permissionChecker] == null) {
                throw new Error(permissionChecker + " not defined");
              }
              return _this.permissionCheckers[permissionChecker](permission, user);
            } else if (samjs.util.isFunction(permissionChecker)) {
              return permissionChecker(permission, user);
            }
            return false;
          };
        })(this);
        isAllowed = function(client, permission, permissionCheckers) {
          var user;
          if (permission == null) {
            throw new Error("no permission");
          }
          if (client.auth == null) {
            throw new Error("invalid socket - no auth");
          }
          if (!(user = client.auth.getUser())) {
            throw new Error("not logged in");
          }
          if (callPermissionChecker(permission, user, permissionCheckers)) {
            return;
          }
          throw new Error("no permission");
        };
        this.isAllowed = isAllowed;
        this.configs = [
          {
            name: "users",
            isRequired: true,
            read: ["root"],
            write: ["root"],
            test: function(users, oldUsers) {
              return new samjs.Promise(function(resolve, reject) {
                var found, i, j, len, len1, oldUser, user;
                if ((users != null) && samjs.util.isArray(users) && users.length > 0) {
                  for (i = 0, len = users.length; i < len; i++) {
                    user = users[i];
                    if (user[samjs.options.username] == null) {
                      reject(new Error("Username for all users required"));
                      return;
                    }
                    if (user[samjs.options.password] == null) {
                      found = false;
                      if (oldUsers != null) {
                        for (j = 0, len1 = oldUsers.length; j < len1; j++) {
                          oldUser = oldUsers[j];
                          if (oldUser[samjs.options.username] === user[samjs.options.username]) {
                            found = true;
                            break;
                          }
                        }
                      }
                      if (!found) {
                        reject(new Error("Password for all users required"));
                        return;
                      }
                    }
                  }
                  return resolve();
                } else {
                  return reject();
                }
              });
            },
            hooks: {
              before_Set: (function(_this) {
                return function(arg) {
                  var data, oldData;
                  data = arg.data, oldData = arg.oldData;
                  return new samjs.Promise(function(resolve, reject) {
                    var i, j, len, len1, oldUser, promise, promises, user;
                    promises = [];
                    for (i = 0, len = data.length; i < len; i++) {
                      user = data[i];
                      if (!user[samjs.options.password]) {
                        for (j = 0, len1 = oldData.length; j < len1; j++) {
                          oldUser = oldData[j];
                          if (oldUser[samjs.options.username] === user[samjs.options.username]) {
                            user[samjs.options.password] = oldUser[samjs.options.password];
                            user.hashed = oldUser.hashed;
                          }
                        }
                      }
                      if (!user.hashed) {
                        promise = new samjs.Promise(function(resolve, reject) {
                          var e, error;
                          try {
                            return _this.crypto.generateHashedPassword(user, resolve);
                          } catch (error) {
                            e = error;
                            return reject(e);
                          }
                        });
                        promises.push(promise);
                      }
                    }
                    return samjs.Promise.all(promises).then(function() {
                      return resolve({
                        data: data
                      });
                    })["catch"](reject);
                  });
                };
              })(this),
              after_Get: function(users) {
                var i, len, newUser, newUsers, user;
                newUsers = [];
                for (i = 0, len = users.length; i < len; i++) {
                  user = users[i];
                  newUser = samjs.helper.clone(user);
                  delete newUser[samjs.options.password];
                  delete newUser.hashed;
                  newUsers.push(newUser);
                }
                return newUsers;
              }
            }
          }
        ];
        this.hooks = {
          configs: {
            beforeTest: function(arg) {
              var client, data;
              data = arg.data, client = arg.client;
              isAllowed(client, this.write, this.permissionCheckers);
              return {
                data: data,
                client: client
              };
            },
            beforeGet: function(arg) {
              var client;
              client = arg.client;
              isAllowed(client, this.read, this.permissionCheckers);
              return {
                client: client
              };
            },
            beforeSet: function(arg) {
              var client, data;
              data = arg.data, client = arg.client;
              isAllowed(client, this.write, this.permissionCheckers);
              return {
                data: data,
                client: client
              };
            }
          }
        };
        this.interfaces = {
          auth: require("./interface")(samjs, this)
        };
      }

      Auth.prototype.findUser = function(name) {
        return samjs.configs.users._getBare().then(function(users) {
          var i, len, user;
          if (users != null) {
            for (i = 0, len = users.length; i < len; i++) {
              user = users[i];
              if (user[samjs.options.username] === name) {
                return user;
              }
            }
          }
        });
      };

      Auth.prototype.replaceUserHandler = function(findUserFunc) {
        this.findUser = findUserFunc;
        return delete this.configs;
      };

      Auth.prototype.comparePassword = function(user, providedPassword) {
        return this.crypto.comparePassword(providedPassword, user[samjs.options.password]).then(function() {
          return user;
        });
      };

      Auth.prototype.debug = function(name) {
        return samjs.debug("auth:" + name);
      };

      Auth.prototype.startup = function() {
        debug("adding auth property to clients");
        return samjs.io.use(function(socket, next) {
          var base;
          if ((base = socket.client).auth == null) {
            base.auth = {};
          }
          socket.client.auth.getUser = function() {
            if (socket.client.auth.user != null) {
              return socket.client.auth.user;
            } else {
              return false;
            }
          };
          return next();
        });
      };

      return Auth;

    })());
  };

}).call(this);
