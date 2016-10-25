module.exports = {
  props: ["samjs"],
  components: {
    icon: require("vmat/icon"),
    inputField: require("vmat/input-field")
  },
  data: function() {
    return {
      userName: " ",
      userPwd: ""
    };
  },
  methods: {
    validatePw: function(pw) {
      return this.$emit("validity-changed", pw.length >= 8);
    },
    next: function() {
      return this.samjs.auth.createRoot(this.userPwd);
    },
    triggerNext: function() {
      return this.$emit("next");
    }
  },
  ready: function() {
    this.samjs.plugins(require("samjs-auth-client"));
    this.samjs.install.isInConfigMode().then((function(_this) {
      return function(nsp) {
        return _this.samjs.io.nsp(nsp).getter("auth.getInstallationInfo");
      };
    })(this)).then((function(_this) {
      return function(info) {
        return _this.userName = info.rootUser;
      };
    })(this));
    return this.$emit("validity-changed", false);
  }
};

if (module.exports.__esModule) module.exports = module.exports.default
;(typeof module.exports === "function"? module.exports.options: module.exports).template = "<div class=\"card black-text\"><div class=\"card-content\"><span class=\"card-title black-text\">Create root user</span><div class=\"row\"><input-field class=\"s12\" readonly=\"readonly\" label=\"Username\" v-bind:value=\"userName\"><icon class=\"prefix\" slot=\"icon\" name=\"material-person\"></icon></input-field><input-field class=\"s12\" autofocus=\"autofocus\" v-bind:validate=\"validatePw\" data-error=\"use at least 8 characters\" label=\"Password\" type=\"password\" v-bind:value.sync=\"userPwd\" @confirm=\"triggerNext\"><icon class=\"prefix\" slot=\"icon\" name=\"material-vpn_key\"></icon></input-field></div></div><slot></slot></div>"
if (module.hot) {(function () {  module.hot.accept()
  var hotAPI = require("vue-hot-reload-api")
  hotAPI.install(require("vue"), true)
  if (!hotAPI.compatible) return
  if (!module.hot.data) {
    hotAPI.createRecord("_v-7f6fbb2c", module.exports)
  } else {
    hotAPI.update("_v-7f6fbb2c", module.exports, (typeof module.exports === "function" ? module.exports.options : module.exports).template)
  }
})()}