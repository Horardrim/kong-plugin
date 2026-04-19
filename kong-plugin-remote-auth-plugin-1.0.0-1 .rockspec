-- kong-plugin-remote-auth-1.0.0-1.rockspec
package = "kong-plugin-remote-auth"
version = "1.0.0-1"
source = {
  url = "https://github.com/yourusername/kong-plugin-remote-auth",
  tag = "v1.0.0"
}
description = {
  summary = "Kong plugin for remote authentication",
  detailed = [[
    A Kong authentication plugin that validates requests against a remote
    authentication server. Supports caching, JWT forwarding, and configurable
    request headers.
  ]],
  homepage = "https://github.com/yourusername/kong-plugin-remote-auth",
  license = "MIT"
}
dependencies = {
  "lua >= 5.1",
  "lua-resty-http >= 0.16.1",
}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.remote-auth.handler"] = "kong/plugins/remote-auth/handler.lua",
    ["kong.plugins.remote-auth.schema"] = "kong/plugins/remote-auth/schema.lua",
  }
}
