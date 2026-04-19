-- spec/remote-auth/01-integration_spec.lua
local helpers = require "spec.helpers"
local http_mock = require "spec.helpers.http_mock"
local cjson = require "cjson"

for _, strategy in helpers.each_strategy() do
  describe("remote-auth" .. ": (access) [#" .. strategy .. "]", function()
    local proxy_client
    local admin_client
    local upstream_mock
    local mock_upstream_port
    local mock_auth_server

    lazy_setup(function()
      local bp = helpers.get_db_utils(strategy, {
        "routes",
        "services",
        "plugins",
      }, { "remote-auth" })

      -- 创建上游服务（模拟后端）
      mock_upstream_port = helpers.get_available_port()
      print("upstream port " .. mock_upstream_port)
      upstream_mock = assert(http_mock.new(mock_upstream_port, {
      ["/"] = {
        access = [[
          ngx.status = 200
          ngx.header["Content-Type"] = "application/json"
          ngx.say('{"upstream": "ok"}')
        ]]
        }
      }, {
        prefix = "servroot_upstream_mock",
      }))
      assert(upstream_mock:start())
      
      mock_service = bp.services:insert({
        name = "upstream_mock",
        url = "http://127.0.0.1:" .. mock_upstream_port,
      })
      
      -- 创建路由
      local route = bp.routes:insert({
        service = { id = mock_service.id },
        hosts = { "test.com" },
        paths = { "/api/test" },
      })

      local mock_auth_server_port = helpers.get_available_port()
      print("Mock auth server will run on port: " .. mock_auth_server_port)
      mock_auth_server = assert(http_mock.new(mock_auth_server_port, {
        -- 定义路由和响应
        ["/auth/verify"] = {
          access = [[
            -- 获取请求头
            local auth_header = ngx.req.get_headers()["Authorization"]
            
            if auth_header == "Bearer valid-token" then
              -- 认证成功
              ngx.status = 200
              ngx.header["Content-Type"] = "application/json"
              ngx.say('{"authenticated": true, "user_id": "user123", "roles": ["admin"]}')
            else
              -- 认证失败
              ngx.status = 401
              ngx.header["Content-Type"] = "application/json"
              ngx.say('{"authenticated": false, "error": "Invalid token"}')
            end
          ]]
        }
      }, {
        prefix = "servroot_auth_mock",
      }))
      assert(mock_auth_server:start())
      -- 配置 remote-auth 插件
      bp.plugins:insert({
        name = "remote-auth",
        route = { id = route.id },
        config = {
          auth_server_url = "http://127.0.0.1:" .. mock_auth_server_port .. "/auth/verify",
          request_header_name = "Authorization",
          cache_ttl = 0,  -- 测试时禁用缓存
          timeout = 2000,
        },
      })
      
      -- 启动 Kong
      assert(helpers.start_kong({
        database = strategy,
        plugins = "bundled,remote-auth",
        --nginx_conf = "spec/fixtures/custom_nginx.template",
      }))
      
      -- 启动模拟认证服务器
      -- helpers.tcp_server(mock_auth_server_port, {
      --   requests = 10,  -- 处理 10 个请求
      -- })
    end)
    
    lazy_teardown(function()
      if upstream_mock then upstream_mock:stop() end
      if mock_auth_server then mock_auth_server:stop() end
      if proxy_client then
        proxy_client:close()
      end
      if admin_client then
        admin_client:close()
      end
      helpers.stop_kong()
    end)
    
    before_each(function()
      proxy_client = helpers.proxy_client()
      admin_client = helpers.admin_client()
    end)
    
    after_each(function()
      if proxy_client then
        proxy_client:close()
      end
      if admin_client then
        admin_client:close()
      end
    end)
    
    describe("Authentication", function()
      it("returns 401 when Authorization header is missing", function()
        local res = assert(proxy_client:send({
          method = "GET",
          path = "/api/test",
          headers = {
            ["Host"] = "test.com",
          },
        }))
        
        assert.res_status(401, res)
        local body = assert.res_status(401, res)
        assert.matches("Unauthorized", body)
      end)
      
      it("returns 401 when remote server returns 401", function()
        local res = assert(proxy_client:send({
          method = "GET",
          path = "/api/test",
          headers = {
            ["Host"] = "test.com",
            ["Authorization"] = "invalid-token",
          },
        }))
        
        assert.res_status(401, res)
      end)
      
      it("proxies request when authentication succeeds", function()
        local res = assert(proxy_client:send({
          method = "GET",
          path = "/api/test",
          headers = {
            ["Host"] = "test.com",
            ["Authorization"] = "Bearer valid-token",
          },
        }))

        assert.res_status(200, res)
      end)
    end)
    
    describe("Configuration", function()
      it("validates required fields", function()
        local res = assert(admin_client:send({
          method = "POST",
          path = "/plugins",
          headers = {
            ["Content-Type"] = "application/json",
          },
          body = {
            name = "remote-auth",
            config = {
              -- 缺少 auth_server_url
              request_header_name = "Authorization",
            },
          },
        }))
        
        assert.res_status(400, res)
      end)
      
      it("accepts valid configuration", function()
        local res = assert(admin_client:send({
          method = "POST",
          path = "/plugins",
          headers = {
            ["Content-Type"] = "application/json",
          },
          body = {
            name = "remote-auth",
            config = {
              auth_server_url = "http://auth.example.com/verify",
              request_header_name = "X-Auth-Token",
              cache_ttl = 120,
              timeout = 3000,
            },
          },
        }))
        local body = cjson.decode(assert.res_status(201, res))
        assert.equal(120, body.config.cache_ttl)
        assert(admin_client:send({
          method = "DELETE",
          path = "/plugins/" .. body.id,
        }))
      end)
    end)
    
    describe("JWT forwarding", function()
      it("forwards JWT to upstream when configured", function()
        -- 这个测试需要更复杂的 mock server 来返回 JWT
        -- 简化版本：验证配置可以正确设置
        local res = assert(admin_client:send({
          method = "POST",
          path = "/plugins",
          headers = {
            ["Content-Type"] = "application/json",
          },
          body = {
            name = "remote-auth",
            config = {
              auth_server_url = "http://auth.example.com/verify",
              request_header_name = "Authorization",
              jwt_response_header = "token",
              upstream_jwt_header = "X-JWT-Token",
            },
          },
        }))
        local body = cjson.decode(assert.res_status(201, res))
        assert.equal("token", body.config.jwt_response_header)
        assert(admin_client:send({
          method = "DELETE",
          path = "/plugins/" .. body.id,
        }))
      end)
    end)
    
    describe("Caching", function()
      it("respects cache_ttl configuration", function()
        local res = assert(admin_client:send({
          method = "POST",
          path = "/plugins",
          headers = {
            ["Content-Type"] = "application/json",
          },
          body = {
            name = "remote-auth",
            config = {
              auth_server_url = "http://auth.example.com/verify",
              request_header_name = "Authorization",
              cache_ttl = 300,
            },
          },
        }))
        
        local body = cjson.decode(assert.res_status(201, res))
        assert.equal(300, body.config.cache_ttl)
        assert(admin_client:send({
          method = "DELETE",
          path = "/plugins/" .. body.id,
        }))
      end)
    end)
  end)
end
