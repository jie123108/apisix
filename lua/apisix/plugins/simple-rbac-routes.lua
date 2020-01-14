local core     = require("apisix.core")
local radix = require("resty.radixtree")
local ngx_re = require("ngx.re")

local _M = {}
function _M.new(self, config)
  local mt = { __index = _M }
  return setmetatable({ config = config }, mt)
end


function _M.checkConfig(self)
  local config = self.config;

  local users = config.users or {}
  local roles = config.roles or {}
  -- parse user permissions
  for username, user_config in pairs(users) do
    local permissions = {}
    local user_roles = user_config.roles or {}
    for _, role in ipairs(user_roles) do
      if not roles[role] then
        return 'role [' .. role ..'] not found'
      end
      local role_permissions = roles[role]
      for _, permission in ipairs(role_permissions) do
        permissions[permission] = true
      end
    end
    user_config.permissions = permissions
    user_config.password = tostring(user_config.password)
  end

  -- create radixtree.
  local routes = {}
  for _, routeString in ipairs(config.routes or {}) do
    local res, err = ngx_re.split(routeString, "[ \t]", nil, nil, 3)
    if err or not res then
      return "route [" .. routeString .. "] is invalid"
    elseif #res == 3 then
      local method = res[1]
      if method == 'ALL' then
        method = nil
      end
      local path = res[2]
      local permission = res[3]
      local methods = nil
      if method then
        methods = { method }
      end
      core.table.insert(routes, {
        paths = { path },
        methods = methods,
        metadata = {permission = permission},
      })
    else
      return "route [" .. routeString .. "] is invalid"
    end
  end
  self.routes = routes
end

function _M.init(self)
  local err = self:checkConfig()
  if err then
    return err
  end
  self.radix = radix.new(self.routes)
  return
end


function _M.get_user(self, username)
  local config = self.config
  local users = config.users or {}
  local user_info = users[username]
  if not user_info then
    return nil, 'user not found'
  end
  return user_info
end

function _M.match(self, method, path)
  if not self.radix then
    return nil, "routes not init"
  end
  local route = self.radix:match(path, {method=method})
  return route
end

return _M
