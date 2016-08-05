# samjs-auth

Adds a configs-based user management, authentification mechanismen and authorization system for configs.

Client: [samjs-auth-client](https://github.com/SAMjs/samjs-auth-client)

## Getting Started
```sh
npm install --save samjs-auth
npm install --save-dev samjs-auth-client
```

## Usage

```js
// server-side
samjs
.plugins(require("samjs-auth"))
.options()
.configs({name:"item", read:true ,write:"root"})
.models()
.startup(server)

// client-side
samjs.plugins(require("samjs-auth-client"))

// one-time configuration
samjs.auth.createRoot("somePWD")

samjs.config.set("item","someValue") // will fail
// authentication
samjs.auth.login({name:"root",pwd:"somePWD"})
.then(function() {
  // success
  // will add a token to browser store to automatically login next time
  samjs.config.set("item","someValue") // will work
  samjs.auth.logout() // to logout and close session (token will be deleted)
})

// will use a token from the browser store to authenticate,
// works when session is still alive
samjs.auth.login()
```

### default options

```coffee
saltWorkFactor: 10 # see bcrypt (security)
tokenExpiration: 1000*60*30 # 30 minutes / server-side session length
tokenSize: 48 # (security)
username: "name" # name of the name prop of a user
password: "pwd" # name of the password prop of a user
rootUser: "root" # name of root user
permissionChecker: "containsUser" # default permissionChecker
```

### permissionCheckers

per default only has `containsUser`, this permission checker will allow acced for username `root`, when the permission is
`true`, `"root"` or `["root"]`

Add your own permission checker:
```js
samjs.auth.permissionCheckers.simple = function(permission, user){
  if (permission == true) {
    return true
  }
  return false
}
```

### default config

samjs-auth adds a `users` config object, which gives `rootUser` read and write access

## API: replaceUserHandler

to replace the user management. Will remove the `users` config object.
(see [samjs-auth-mongo](https://github.com/SAMjs/samjs-auth-mongo) for an example)
```js
samjs.auth.replaceUserHandler(function(username){
  // somehow get a user object by username
  return user
})
```
