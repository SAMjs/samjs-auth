(function() {
  var path,
    bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; };

  path = require("path");

  module.exports = function(options) {
    return function(samjs) {
      var Auth, debug;
      debug = samjs.debug("auth");
      if (options == null) {
        options = {};
      }
      if (options.dev == null) {
        options.dev = process.env.NODE_ENV !== "production";
      }
      return new (Auth = (function() {
        function Auth() {
          this.comparePassword = bind(this.comparePassword, this);
          this.replaceUserHandler = bind(this.replaceUserHandler, this);
          var callPermissionChecker, getAllowance, isAllowed;
          this.crypto = require("./crypto")(samjs);
          samjs.helper.initiateHooks(this, [], ["afterLogin", "afterLogout"]);
          this.name = "auth";
          this.develop = options.dev;
          this.options = {
            saltWorkFactor: 10,
            tokenExpiration: 1000 * 60 * 30,
            tokenSize: 48,
            username: "name",
            password: "pwd",
            rootUser: "root",
            authOptions: {
              authRequired: false,
              permissionChecker: "containsUser"
            }
          };
          this.permissionCheckers = {
            containsUser: function(user, permission, options) {
              if (options.getIdentifier) {
                if (user != null) {
                  return user[samjs.options.username];
                } else {
                  return "__public";
                }
              }
              if (permission === true) {
                if (!options.authRequired || (user != null)) {
                  return true;
                }
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
            return function(user, permission, options) {
              var allowed, checker, i, j, len, len1, pc;
              if (options == null) {
                options = {};
              }
              pc = options.permissionChecker;
              if (pc == null) {
                pc = samjs.options.authOptions.permissionChecker;
              }
              if (options.authRequired == null) {
                options.authRequired = samjs.options.authOptions.authRequired;
              }
              if (samjs.util.isArray(pc)) {
                if (options.getIdentifier) {
                  return user[samjs.options.username];
                } else if (options.all) {
                  allowed = 0;
                  for (i = 0, len = pc.length; i < len; i++) {
                    checker = pc[i];
                    if (callPermissionChecker(user, permission, Object.assign({
                      permissionChecker: checker
                    }, options))) {
                      allowed += 1;
                    }
                  }
                  return allowed === pc.length;
                } else {
                  for (j = 0, len1 = pc.length; j < len1; j++) {
                    checker = pc[j];
                    if (callPermissionChecker(user, permission, Object.assign({
                      permissionChecker: checker
                    }, options))) {
                      return true;
                    }
                  }
                }
              } else if (samjs.util.isString(pc)) {
                if (_this.permissionCheckers[pc] == null) {
                  throw new Error(pc + " not defined");
                }
                return _this.permissionCheckers[pc](user, permission, options);
              } else if (samjs.util.isFunction(pc)) {
                return pc(user, permission, options);
              }
              return false;
            };
          })(this);
          getAllowance = function(user, permission, options) {
            if (permission == null) {
              return "no permission";
            }
            if (callPermissionChecker(user, permission, options)) {
              return "";
            }
            return "no permission";
          };
          isAllowed = function(socket, permission, options) {
            var ref, result;
            if (((ref = socket.client) != null ? ref.auth : void 0) == null) {
              throw new Error("invalid socket - no auth");
            }
            result = getAllowance(socket.client.auth.user, permission, options);
            if (result === "") {
              return true;
            }
            throw new Error(result);
          };
          this.isAllowed = isAllowed;
          this.getAllowance = getAllowance;
          this.callPermissionChecker = callPermissionChecker;
          this.configs = [
            {
              name: "users",
              installComp: {
                paths: [path.resolve(__dirname, "./createUser")],
                icons: ["material-person", "material-vpn_key"]
              },
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
                  var base, base1;
                  if ((base = config.access).read == null) {
                    base.read = [samjs.options.rootUser];
                  }
                  if ((base1 = config.access).write == null) {
                    base1.write = [samjs.options.rootUser];
                  }
                  return config;
                },
                before_Set: (function(_this) {
                  return function(obj) {
                    return new samjs.Promise(function(resolve, reject) {
                      var i, j, len, len1, oldUser, promise, promises, ref, ref1, user;
                      promises = [];
                      ref = obj.data;
                      for (i = 0, len = ref.length; i < len; i++) {
                        user = ref[i];
                        if (!user[samjs.options.password]) {
                          ref1 = obj.oldData;
                          for (j = 0, len1 = ref1.length; j < len1; j++) {
                            oldUser = ref1[j];
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
                        return resolve(obj);
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
              beforeTest: function(obj) {
                isAllowed(obj.socket, this.access.write, this.authOptions);
                return obj;
              },
              beforeGet: function(obj) {
                isAllowed(obj.socket, this.access.read, this.authOptions);
                return obj;
              },
              beforeSet: function(obj) {
                isAllowed(obj.socket, this.access.write, this.authOptions);
                return obj;
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

        Auth.prototype.startup = function(obj) {
          if (samjs.io != null) {
            samjs.io.use(function(socket, next) {
              var base;
              if ((base = socket.client).auth == null) {
                base.auth = {};
              }
              return next();
            });
          }
          return obj;
        };

        return Auth;

      })());
    };
  };

}).call(this);
