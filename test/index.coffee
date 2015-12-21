chai = require "chai"
should = chai.should()
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
  before (done) ->
    fs.unlinkAsync testConfigFile
    .catch -> return true
    .finally ->
      samjs.reset()
      .plugins(samjsAuth)
      .options({config:testConfigFile})
      .configs({name:"testConfig",read:true,write:true})
      .models()
      opt = samjs.configs.testConfig
      done()



  describe "auth", ->
    opt = null
    users = null
    describe "configs", ->
      it "should reject get", (done) ->
        opt.get()
        .then console.log
        .catch -> done()
      it "should reject set", (done) ->
        opt.set()
        .catch -> done()
      it "should reject test", (done) ->
        opt.test()
        .catch -> done()
      it "should have users config", ->
        should.exist(samjs.configs.users)
    describe "startup", ->
      it "should not configure when false user is supplied", (done) ->
        samjs.startup().io.listen(port)
        client = samjsClient({
          url: url
          ioOpts:
            autoConnect: false
          })().plugins(samjsAuthClient)
        client.install.onceInConfigMode
        .return client.auth.createRoot name:"root"
        .catch (e) ->
          e.message.should.equal "Username and password required"
          done()
      it "should configure", (done) ->
        client.auth.createRoot name:"root",pwd:"rootroot"
        .then -> done()
        .catch done
      it "should be started up", (done) ->
        @timeout(2000)
        samjs.state.onceStarted
        .then ->
          client.io.socket.once "reconnect", -> done()
        .catch done
      it "should reject config.set", (done) ->
        client.config.set("testConfig","value")
        .catch (e) ->
          e.message.should.equal "not logged in"
          done()
      it "should reject config.get", (done) ->
        client.config.get("testConfig")
        .catch (e) ->
          e.message.should.equal "not logged in"
          done()
      it "should auth", (done) ->

        client.auth.login {name:"root",pwd:"rootroot"}
        .then (result) ->
          result.name.should.equal "root"
          done()
        .catch done
      describe "once authenticated", ->
        it "should config.set", (done) ->
          client.config.set("testConfig","value")
          .then -> done()
          .catch done
        it "should config.get", (done) ->
          client.config.get("testConfig")
          .then (result) ->
            result.should.equal "value"
            done()
          .catch done

  after (done) ->
    if samjs.shutdown?
      if samjs.models.users?
        model = samjs.models.users?.dbModel
        model.remove {group:"root"}
        .then -> done()
      else
        samjs.shutdown().then -> done()
    else
      done()
