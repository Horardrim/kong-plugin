-- kong/plugins/remote-auth/handler.lua
local http = require "resty.http"
local cjson = require "cjson"
local cache = require "kong.cache"

local plugin = {
  PRIORITY = 1000,  -- 高优先级，确保在代理前执行
  VERSION = "1.0.0",
}

-- 缓存键生成函数
local function generate_cache_key(conf, header_value)
  return string.format("remote-auth:%s:%s:%s", 
    conf.auth_server_url, 
    conf.request_header_name,
    ngx.md5(header_value or "")
  )
end

-- 从远程服务器获取认证
local function authenticate_with_remote(conf, header_value)
  local httpc = http.new()
  
  -- 设置超时
  httpc:set_timeout(conf.timeout)
  
  -- 准备请求头
  local headers = {
    [conf.request_header_name] = header_value,
    ["Content-Type"] = "application/json",
  }
  
  -- 发起请求
  local res, err = httpc:request_uri(conf.auth_server_url, {
    method = "GET",
    headers = headers,
    ssl_verify = false,  -- 生产环境应配置为 true
  })
  
  if not res then
    kong.log.err("Failed to reach auth server: ", err)
    return nil, "auth_server_unreachable"
  end
  
  -- 解析响应体
  local body = res.body
  local jwt_token = nil
  
  if body and conf.jwt_response_header then
    -- 尝试解析 JSON 响应
    local ok, parsed = pcall(cjson.decode, body)
    if ok and type(parsed) == "table" then
      jwt_token = parsed[conf.jwt_response_header]
    end
  end
  
  return {
    status = res.status,
    jwt_token = jwt_token,
  }, nil
end

-- 主访问阶段处理
function plugin:access(conf)
  kong.log.notice("I'm in")
  -- 获取请求头值
  local header_value = conf.request_header_value
  
  -- 如果没有配置固定值，从请求中获取
  if not header_value then
    header_value = kong.request.get_header(conf.request_header_name)
  end
  
  -- 如果没有提供认证信息
  if not header_value then
    return kong.response.exit(401, {
      message = "Unauthorized: missing authentication header"
    }, {
      ["Content-Type"] = "application/json"
    })
  end
  
  local auth_result
  local cache_key
  
  -- 检查是否启用缓存
  if conf.cache_ttl > 0 then
    cache_key = generate_cache_key(conf, header_value)
    
    -- 尝试从缓存获取
    local cached, err = kong.cache:get(cache_key, {
      ttl = conf.cache_ttl,
    }, function()
      -- 缓存未命中，调用远程服务器
      local result, err = authenticate_with_remote(conf, header_value)
      if err then
        return nil  -- 缓存 nil 表示认证失败
      end
      -- 只缓存成功的认证
      if result.status == 200 then
        return result
      end
      return nil
    end)
    
    if err then
      kong.log.err("Cache error: ", err)
      -- 缓存出错，直接进行远程认证
      auth_result, err = authenticate_with_remote(conf, header_value)
      if err then
        return kong.response.exit(503, {
          message = "Service Unavailable: authentication service error"
        })
      end
    else
      auth_result = cached
    end
  else
    -- 不启用缓存，直接请求
    local err
    auth_result, err = authenticate_with_remote(conf, header_value)
    if err then
      return kong.response.exit(503, {
        message = "Service Unavailable: authentication service error"
      })
    end
  end
  
  -- 检查认证结果
  if not auth_result or auth_result.status ~= 200 then
    local status = auth_result and auth_result.status or 401
    
    -- 根据远程服务器返回的状态码返回相应的 4xx 错误
    if status >= 400 and status < 500 then
      return kong.response.exit(status, {
        message = "Unauthorized: authentication failed"
      }, {
        ["Content-Type"] = "application/json"
      })
    else
      -- 远程服务器返回 5xx，返回 401 给客户端
      return kong.response.exit(401, {
        message = "Unauthorized: authentication service unavailable"
      }, {
        ["Content-Type"] = "application/json"
      })
    end
  end
  
  -- 认证成功，如果配置了 JWT 转发，设置请求头
  if conf.jwt_response_header and auth_result.jwt_token then
    kong.service.request.set_header(conf.upstream_jwt_header, auth_result.jwt_token)
    kong.log.debug("Set upstream JWT header: ", conf.upstream_jwt_header)
  end
  
  -- 可选：在请求头中标记认证状态
  kong.service.request.set_header("X-Remote-Auth-Status", "authenticated")
end

-- 初始化 worker 时清理缓存
function plugin:init_worker()
  kong.log.info("Remote Auth plugin initialized")
end

return plugin
