(function() {
  var bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; };

  module.exports = function(options) {
    return function(samjs) {
      var Auth, debug;
      debug = samjs.debug("auth");
      if (options == null) {
        options = {};
      }
      return new (Auth = (function() {
        function Auth() {
          this.comparePassword = bind(this.comparePassword, this);
          this.replaceUserHandler = bind(this.replaceUserHandler, this);
          var callPermissionChecker, getAllowance, isAllowed;
          this.crypto = require("./crypto")(samjs);
          this.name = "auth";
          this.develop = options.dev;
          this.options = {
            saltWorkFactor: 10,
            tokenExpiration: 1000 * 60 * 30,
            tokenSize: 48,
            username: "name",
            password: "pwd",
            rootUser: "root",
            permissionChecker: "containsUser"
          };
          this.permissionCheckers = {
            containsUser: function(permission, user) {
              if (permission === true) {
                return true;
              } else if (user != null) {
                if (samjs.util.isString(permission)) {
                  if (permission === user[samjs.options.username]) {
                    return true;
                  }
                } else if (samjs.util.isArray(permission)) {
                  if (permission.indexOf(user[samjs.options.username]) > -1) {
                    return true;
                  }
                }
              }
              return false;
            }
          };
          callPermissionChecker = (function(_this) {
            return function(permission, user, permissionChecker) {
              var checker, i, len;
              if (permissionChecker == null) {
                permissionChecker = samjs.options.permissionChecker;
              }
              if (samjs.util.isArray(permissionChecker)) {
                for (i = 0, len = permissionChecker.length; i < len; i++) {
                  checker = permissionChecker[i];
                  if (callPermissionChecker(permission, user, checker)) {
                    return true;
                  }
                }
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
          getAllowance = function(user, permission, permissionChecker) {
            if (permission == null) {
              return "no permission";
            }
            if (callPermissionChecker(permission, user, permissionChecker)) {
              return "";
            }
            return "no permission";
          };
          isAllowed = function(client, permission, permissionChecker) {
            var result;
            if (client.auth == null) {
              throw new Error("invalid socket - no auth");
            }
            result = getAllowance(client.auth.user, permission, permissionChecker);
            if (result === "") {
              return true;
            }
            throw new Error(result);
          };
          this.isAllowed = isAllowed;
          this.getAllowance = getAllowance;
          this.configs = [
            {
              name: "users",
              isRequired: true,
              test: function(users, oldUsers) {
                return new samjs.Promise(function(resolve, reject) {
                  var found, i, j, len, len1, oldUser, rootUser, user;
                  if ((users != null) && samjs.util.isArray(users) && users.length > 0) {
                    rootUser = false;
                    for (i = 0, len = users.length; i < len; i++) {
                      user = users[i];
                      if (user[samjs.options.username] == null) {
                        reject(new Error("Username for all users required"));
                        return;
                      } else if (user[samjs.options.username] === samjs.options.rootUser) {
                        rootUser = true;
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
                    if (!rootUser) {
                      reject(new Error("No root user was set"));
                    }
                    return resolve();
                  } else {
                    return reject();
                  }
                });
              },
              installInterface: function(socket) {
                socket.on("auth.getInstallationInfo", function(request) {
                  var obj;
                  if (request.token != null) {
                    obj = {
                      success: true,
                      content: {
                        rootUser: samjs.options.rootUser,
                        password: samjs.options.password,
                        username: samjs.options.username
                      }
                    };
                    return socket.emit("auth.getInstallationInfo." + request.token, obj);
                  }
                });
                return function() {
                  return socket.removeAllListeners("auth.getInstallationInfo");
                };
              },
              hooks: {
                afterCreate: function(config) {
                  if (config.read == null) {
                    config.read = [samjs.options.rootUser];
                  }
                  return config.write != null ? config.write : config.write = [samjs.options.rootUser];
                },
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
                            var e;
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
          if (this.develop) {
            this.configs.push({
              name: "tokenStore"
            });
          }
          this.hooks = {
            configs: {
              beforeTest: function(arg) {
                var client, data;
                data = arg.data, client = arg.client;
                isAllowed(client, this.write, this.permissionChecker);
                return {
                  data: data,
                  client: client
                };
              },
              beforeGet: function(arg) {
                var client;
                client = arg.client;
                isAllowed(client, this.read, this.permissionChecker);
                return {
                  client: client
                };
              },
              beforeSet: function(arg) {
                var client, data;
                data = arg.data, client = arg.client;
                isAllowed(client, this.write, this.permissionChecker);
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

        Auth.prototype.userConverter = function(user) {
          return samjs.helper.clone(user);
        };

        Auth.prototype.afterAuth = [];

        Auth.prototype.callAfterAuthHooks = function(user) {
          var authHook, i, len, ref, results;
          ref = this.afterAuth;
          results = [];
          for (i = 0, len = ref.length; i < len; i++) {
            authHook = ref[i];
            results.push(authHook(user));
          }
          return results;
        };

        Auth.prototype.replaceUserHandler = function(findUserFunc, userConverter) {
          this.findUser = findUserFunc;
          if (userConverter != null) {
            this.userConverter = userConverter;
          }
          this.configs.shift();
          if (this.configs.length === 0) {
            return delete this.configs;
          }
        };

        Auth.prototype.comparePassword = function(user, providedPassword) {
          return this.crypto.comparePassword(providedPassword, user[samjs.options.password]).then(function() {
            return user;
          });
        };

        Auth.prototype.debug = function(name) {
          return samjs.debug("auth:" + name);
        };

        return Auth;

      })());
    };
  };

}).call(this);
