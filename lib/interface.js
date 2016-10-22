(function() {
  module.exports = function(samjs, auth) {
    var getUserByToken, setTokenForUser, tokenStore;
    if (auth.develop) {
      getUserByToken = function(token) {
        return samjs.configs.tokenStore._get().then(function(value) {
          return value && value[token];
        });
      };
      setTokenForUser = function(token, user) {
        return samjs.configs.tokenStore._get().then(function(value) {
          if (value == null) {
            value = {};
          }
          value[token] = {
            user: user
          };
          return value;
        }).then(samjs.configs.tokenStore._set);
      };
    } else {
      tokenStore = {};
      getUserByToken = function(token) {
        return samjs.Promise.resolve(tokenStore[token]).then(function(storedItem) {
          if (storedItem != null) {
            if (storedItem.removeTimeout) {
              storedItem.removeTimeout();
            }
            storedItem.resetLongTimeout();
          }
          return storedItem;
        });
      };
      setTokenForUser = function(token, user) {
        tokenStore[token] = {
          user: user
        };
        tokenStore[token].resetLongTimeout = function() {
          var timoutObj;
          if (timoutObj) {
            clearTimeout(timoutObj);
          }
          return timoutObj = setTimeout((function() {
            return delete tokenStore[token];
          }), samjs.options.tokenExpiration * 50);
        };
        return tokenStore[token].resetLongTimeout();
      };
    }
    return function(socket) {
      socket.on("disconnect", function() {
        var ref, ref1, timoutObj, token;
        if (((ref = socket.client) != null ? (ref1 = ref.auth) != null ? ref1.token : void 0 : void 0) != null) {
          token = socket.client.auth.token;
          if (tokenStore != null ? tokenStore[token] : void 0) {
            timoutObj = setTimeout((function() {
              return delete tokenStore[token];
            }), samjs.options.tokenExpiration);
            if (tokenStore[token].removeTimeout) {
              tokenStore[token].removeTimeout();
            }
            return tokenStore[token].removeTimeout = function() {
              return clearTimeout(timoutObj);
            };
          }
        }
      });
      socket.on("auth.byToken", function(request) {
        var content, success, token;
        success = false;
        content = false;
        if ((request != null) && (request.token != null) && (request.content != null)) {
          token = request.content;
          return getUserByToken(token).then(function(storedItem) {
            var base, user;
            if (storedItem) {
              user = storedItem.user;
              content = auth.userConverter(user);
              delete content[samjs.options.password];
              success = true;
              if ((base = socket.client).auth == null) {
                base.auth = {};
              }
              socket.client.auth.user = user;
              socket.client.auth.token = token;
              auth._hooks.afterLogin({
                socket: socket,
                user: user
              });
            }
            return socket.emit("auth.byToken." + request.token, {
              success: success,
              content: content
            });
          });
        }
      });
      return socket.on("auth", function(request) {
        if ((request != null) && (request.content != null) && (request.content[samjs.options.username] != null) && (request.content[samjs.options.password] != null) && (request.token != null)) {
          return auth.findUser(request.content[samjs.options.username]).then(function(user) {
            if (user == null) {
              throw new Error("user not found");
            }
            return auth.comparePassword(user, request.content[samjs.options.password]);
          }).then(function(user) {
            return samjs.helper.generateToken(samjs.options.tokenSize).then(function(token) {
              var base, content;
              content = auth.userConverter(user);
              content.token = token;
              delete content[samjs.options.password];
              setTokenForUser(token, user);
              if ((base = socket.client).auth == null) {
                base.auth = {};
              }
              socket.client.auth.user = user;
              socket.client.auth.token = token;
              auth._hooks.afterLogin({
                socket: socket,
                user: user
              });
              return content;
            });
          }).then(function(content) {
            return {
              success: true,
              content: content
            };
          })["catch"](function(e) {
            return {
              success: false,
              content: e != null ? e.message : void 0
            };
          }).then(function(response) {
            return socket.emit("auth." + request.token, response);
          });
        } else {
          return socket.emit("auth" + request.token, {
            success: false,
            content: false
          });
        }
      });
    };
  };

}).call(this);
