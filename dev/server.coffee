samjs = require "samjs"
path = require "path"
chokidar = require "chokidar"
fs = samjs.Promise.promisifyAll(require("fs"))
testConfigFile = "test/testConfig.json"
fs.unlinkAsync testConfigFile
.catch -> return true
.finally -> samjs.bootstrap (samjs) ->
  samjs
  .plugins([
    require("samjs-install")(),
    require("../src/main.coffee")()
    ])
  .options({config:testConfigFile})
  .configs()
  .models()
  .startup()

chokidar.watch([
  "./src/main.coffee"
  "./src/crypto.coffee"
  "./src/interface.coffee"
  ],{ignoreInitial: true})
  .on "all", (ev,relPath) ->
    absPath = path.resolve(relPath)
    if require.cache[absPath]
      delete require.cache[absPath]
    samjs.reload()
