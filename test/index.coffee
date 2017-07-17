chai = require "chai"
should = chai.should()
chai.use require "chai-as-promised"
requireAny = require "try-require-multiple"
Samjs = requireAny "samjs/src", "samjs"
SamjsClient = requireAny "samjs/client-src", "samjs/client"
samjsAuth = require "../src"
samjsAuthClient = require "../client-src"

port = 3050
url = "http://localhost:"+port+"/"
testConfigFile = "test/testConfig.json"

describe "samjs", =>
  describe "auth", =>
    samjs = samjsClient = null

    before =>
      samjs = new Samjs
        plugins: samjsAuth
        options: config: testConfigFile
        configs:[{
          name: "testConfig"
          access: connect: true
          },{
          name: "testConfig2"
          data: "preset"
          access: 
            connect: =>
        }]
      await samjs.fs.remove testConfigFile
      samjs.finished.then (io) => io.listen(port)
    after => 
      samjs.shutdown()
      samjsClient?.close()

    describe "configs", =>
      it "should reject get", =>
        samjs.configs.testConfig.get(socket: {}).should.be.rejected
      it "should reject set", =>
        samjs.configs.testConfig.set(socket: {}).should.be.rejected
      it "should reject test", =>
        samjs.configs.testConfig.test(socket: {}).should.be.rejected
      it "should have users config", =>
        should.exist(samjs.configs.users)
      it "should write proper users", =>
        result = await samjs.configs.users.set(data:[{name:"root",pwd:"rootroot"}])
        result.data[0].hashed.should.be.true
    describe "client", =>
      it "should plugin",  =>
        samjsClient = new SamjsClient
          plugins: [samjsAuthClient]
          url: url
          io: reconnection:false
        should.exist samjsClient.auth
        samjsClient.finished
      it "should reject config.set", =>
        samjsClient.config.set("testConfig","value").should.be.rejected
      it "should reject config.get", =>
        samjsClient.config.get("testConfig").should.be.rejected
      it "should not connect to testConfig2", (done) =>
        samjsClient.config.get("testConfig2").should.be.rejected
        setTimeout done, 100
      it "should auth", =>
        samjsClient.auth.login {name:"root",pwd:"rootroot"}
        .then (result) =>
          result.name.should.equal "root"
      
      it "should auth by token", =>
        delete samjsClient.auth.user
        samjsClient.auth.login()

      describe "once authenticated", =>
        it "should config.set", =>
          samjsClient.config.set("testConfig","value")

        it "should config.get",  =>
          samjsClient.config.get("testConfig")
          .then (result) =>
            result.should.equal "value"
        
        it "should reconnect to testConfig2",  =>
          samjsClient.config.get("testConfig2")
        
        it "should set testConfig2", =>
          samjsClient.config.set("testConfig2","value").should.eventually.equal "value"