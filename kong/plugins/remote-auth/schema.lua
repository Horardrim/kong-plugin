-- kong/plugins/remote-auth/schema.lua
local typedefs = require "kong.db.schema.typedefs"

local PLUGIN_NAME = "remote-auth"

local schema = {
  name = PLUGIN_NAME,
  fields = {
    -- 认证插件通常不能配置在 consumer 上
    { consumer = typedefs.no_consumer },
    -- 仅支持 HTTP 协议
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          -- 必需：认证服务器 URL
          { auth_server_url = typedefs.url({ required = true }) },
          
          -- 必需：请求头名称
          { request_header_name = typedefs.header_name({ 
              required = true,
              default = "Authorization" 
          }) },
          
          -- 可选：请求头值（如果不配置，使用原始请求中的值）
          { request_header_value = { type = "string", required = false } },
          
          -- 可选：缓存 TTL（秒），0 表示不缓存
          { cache_ttl = { 
              type = "integer", 
              required = true, 
              default = 60,
              between = { 0, 3600 }
          } },
          
          -- 可选：JWT 响应头名称（从远程服务器响应中提取）
          { jwt_response_header = { 
              type = "string", 
              required = false 
          } },
          
          -- 可选：转发到上游的 JWT 头名称
          { upstream_jwt_header = typedefs.header_name({ 
              required = false,
              default = "X-Auth-Token"
          }) },
          
          -- 可选：超时时间（毫秒）
          { timeout = { 
              type = "integer", 
              required = true, 
              default = 5000,
              between = { 1000, 30000 }
          } },
          
          -- 可选：重试次数
          { retries = { 
              type = "integer", 
              required = true, 
              default = 0,
              between = { 0, 3 }
          } },
        },
        entity_checks = {
          -- 如果配置了 jwt_response_header，则必须配置 upstream_jwt_header
          { conditional = {
              if_field = "jwt_response_header", 
              if_match = { required = true },
              then_field = "upstream_jwt_header", 
              then_match = { required = true }
          }},
        },
      },
    },
  },
}

return schema
