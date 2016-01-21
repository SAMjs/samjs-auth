# out: ../lib/main.js
module.exports = (samjs) ->
  auth = require("./auth")(samjs)
  plugin = {}
  plugin.name = auth.name
  plugin.obj = auth
  plugin.options = auth.options
  plugin.configs = auth.configs
  plugin.hooks = auth.hooks
  plugin.startup = auth.startup
  plugin.interfaces = auth.interfaces
  return plugin
