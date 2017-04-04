chai = require "chai"
should = chai.should()
chai.use require "chai-as-promised"
samjs = require "samjs"
samjsAuth = require("../src/main")
samjsClient = require "samjs-client"
samjsAuthClient = require "samjs-auth-client"

fs = samjs.Promise.promisifyAll(require("fs"))
port = 3050
url = "http://localhost:"+port+"/"
testConfigFile = "test/testConfig.json"

describe "samjs", ->
  client = null
  opt = null
  before ->
    fs.unlinkAsync testConfigFile
    .catch -> return true
    .then ->
      samjs.reset().then ->
        samjs.plugins(samjsAuth())
        .options({config:testConfigFile})
        .configs({name:"testConfig",access:{read:"root",write:"root"}})
        .models()
        opt = samjs.configs.testConfig

  describe "auth", ->
    opt = null
    users = null
    describe "configs", ->
      it "should reject get", ->
        opt.get().should.be.rejected
      it "should reject set", ->
        opt.set().should.be.rejected
      it "should reject test", ->
        opt.test().should.be.rejected
      it "should have users config", ->
        should.exist(samjs.configs.users)
    describe "startup", ->
      it "should not configure when no password is supplied",  ->
        samjs.startup().io.listen(port)
        client = samjsClient({
          url: url
          ioOpts:
            autoConnect: false
          })().plugins(samjsAuthClient)
        client.install.onceConfigure
        .then -> client.auth.createRoot()
        .should.be.rejected
      it "should configure", ->
        client.auth.createRoot "rootroot"
        .then (response) ->
          should.not.exist response[0].pwd
      it "should be started up", (done) ->
        @timeout(3000)
        samjs.state.onceStarted
        .then ->
          client.io.socket.once "reconnect", -> done()
        .catch done
        return null
      it "should reject config.set", ->
        client.config.set("testConfig","value")
        .should.be.rejected
      it "should reject config.get", ->
        client.config.get("testConfig")
        .should.be.rejected
      it "should auth", ->
        client.auth.login {name:"root",pwd:"rootroot"}
        .then (result) ->
          result.name.should.equal "root"

      describe "once authenticated", ->
        it "should config.set", ->
          client.config.set("testConfig","value")

        it "should config.get",  ->
          client.config.get("testConfig")
          .then (result) ->
            result.should.equal "value"

        it "should be able to add a user",  ->
          client.config.get("users")
          .then (result) ->
            result[0].name.should.equal "root"
            should.not.exist result[0].pwd
            result.push name:"root2",pwd:"rootroot"
            client.config.set("users",result)
          .then samjs.configs.users._getBare
          .then (result) ->
            result[0].name.should.equal "root"
            result[1].name.should.equal "root2"
            should.exist result[0].pwd
            should.exist result[1].hashed
            should.exist result[0].pwd
            should.exist result[1].hashed

        it "should be able to remove a user",  ->
          client.config.get("users")
          .then (result) ->
            result[1].name.should.equal "root2"
            result.splice 1,1
            client.config.set("users",result)
          .then samjs.configs.users._getBare
          .then (result) ->
            result[0].name.should.equal "root"
            should.exist result[0].pwd
            should.exist result[0].hashed
            should.not.exist result[1]
  after ->
    if samjs.shutdown?
      if samjs.models.users?
        model = samjs.models.users?.dbModel
        return model.remove {group:"root"}
      else
        return samjs.shutdown()
