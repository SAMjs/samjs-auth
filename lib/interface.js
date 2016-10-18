(function() {
  module.exports = function(samjs, auth) {
    var tokenStore;
    tokenStore = {};
    return function(socket) {
      socket.on("disconnect", function() {
        var ref, ref1, timoutObj, token;
        if (((ref = socket.client) != null ? (ref1 = ref.auth) != null ? ref1.token : void 0 : void 0) != null) {
          token = socket.client.auth.token;
          if (tokenStore[token]) {
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
        var base, content, storedItem, success, token, user;
        success = false;
        content = false;
        if ((request != null) && (request.token != null) && (request.content != null)) {
          token = request.content;
          storedItem = tokenStore[token];
          if (storedItem) {
            if (storedItem.removeTimeout) {
              storedItem.removeTimeout();
            }
            storedItem.resetLongTimeout();
            user = storedItem.user;
            content = auth.userConverter(user);
            delete content[samjs.options.password];
            success = true;
            if ((base = socket.client).auth == null) {
              base.auth = {};
            }
            socket.client.auth.user = user;
            socket.client.auth.token = token;
            auth.callAfterAuthHooks(user);
          }
          return socket.emit("auth.byToken." + request.token, {
            success: success,
            content: content
          });
        }
      });
      return socket.on("auth", function(request) {
        if ((request != null) && (request.content != null) && (request.content[samjs.options.username] != null) && (request.content[samjs.options.password] != null) && (request.token != null)) {
          return auth.findUser(request.content[samjs.options.username]).then(function(user) {
            console.log(user);
            if (user == null) {
              throw new Error("user not found");
            }
            return auth.comparePassword(user, request.content[samjs.options.password]);
          }).then(function(user) {
            return auth.crypto.generateToken(samjs.options.tokenSize).then(function(token) {
              var base, content;
              content = auth.userConverter(user);
              content.token = token;
              delete content[samjs.options.password];
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
              tokenStore[token].resetLongTimeout();
              if ((base = socket.client).auth == null) {
                base.auth = {};
              }
              socket.client.auth.user = user;
              socket.client.auth.token = token;
              auth.callAfterAuthHooks(user);
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
