
local simple_rbac_routes = require("apisix.plugins.simple-rbac-routes")
local core     = require("apisix.core")
local jwt      = require("resty.jwt")
local ck       = require("resty.cookie")
local consumer = require("apisix.consumer")
local json     = require("apisix.core.json")
local yaml     = require("tinyyaml")
local resty_sha1 = require "resty.sha1"
local str       = require "resty.string"
local lfs      = require("lfs")
local ipairs   = ipairs
local ngx      = ngx
local ngx_time = ngx.time
local plugin_name = "simple-rbac"
local algorithm = 'HS256'

local schema = {
    type = "object",
    properties = {
        apiname = {type = "string"},
        secret = {type = "string"},
        exp = {type = "integer", minimum = 1},
        simple_rbac_yaml = {type = "string"},
        password_encode = {type = 'boolean'},
        password_salt = {type = 'string'},
    }
}


local _M = {
    version = 0.1,
    priority = 2400,
    type = 'auth',
    name = plugin_name,
    schema = schema,
}

local create_consume_cache
do
    local consumer_ids = {}

    function create_consume_cache(consumers)
        core.table.clear(consumer_ids)

        for _, consumer in ipairs(consumers.nodes) do
            core.log.info("consumer node: ", core.json.delay_encode(consumer))
            consumer_ids[consumer.auth_conf.apiname] = consumer
        end

        return consumer_ids
    end

end -- do

local function password_hash(password, salt)
    local sha1 = resty_sha1:new()
    if not sha1 then
        core.log.error("failed to create the sha1 object")
        return password
    end
    if salt then
        password = salt .. password
    end
    sha1:update(password)
    return str.to_hex(sha1:final())
end

local function read_simple_rbac_yaml(rbac_yaml, last_change_time)
    local simple_rbac_yaml = ngx.config.prefix() .. rbac_yaml
    local pre_mtime = last_change_time

    local attributes, err = lfs.attributes(simple_rbac_yaml)
    if not attributes then
        core.log.error("failed to fetch ", simple_rbac_yaml, " attributes: ", err)
        return false, err
    end

    -- log.info("change: ", json.encode(attributes))
    local last_change_time = attributes.change
    if pre_mtime == last_change_time then
        core.log.info("simple rbac yaml file [", simple_rbac_yaml, "] not changed..")
        return true
    end

    local f, err = io.open(simple_rbac_yaml, "r")
    if not f then
        core.log.error("failed to open file ", simple_rbac_yaml, " : ", err)
        return false, err
    end

    local yaml_config = f:read("*a")
    f:close()

    local simple_rbac_config = yaml.parse(yaml_config)
    if not simple_rbac_config then
        core.log.error("failed to parse the content of file", simple_rbac_yaml)
        return false, "parse yaml file failed"
    end

    core.log.info("--------- update rbac info from file ", simple_rbac_yaml, " ---------")

    local rbac_routes = simple_rbac_routes:new(simple_rbac_config)
    local err = rbac_routes:checkConfig()
    if err then
        core.log.error("rbac_routes:checkConfig failed! err:", err)
        return false, err
    else
        core.log.info("rbac_routes:checkConfig ok")
    end

    return true, simple_rbac_config, last_change_time
end

-- config value schema: {simple_rbac_config, last_change_time}
_M.file_infos = {}

local function recheck_yaml_config(simple_rbac_yaml)
    local file_info = _M.file_infos[simple_rbac_yaml] or {}
    local ok, simple_rbac_config, last_change_time = read_simple_rbac_yaml(simple_rbac_yaml, file_info.last_change_time)
    if ok and simple_rbac_config and last_change_time then
        _M.file_infos[simple_rbac_yaml] = {simple_rbac_config=simple_rbac_config, last_change_time=last_change_time}
    end
    return ok, simple_rbac_config, last_change_time
end

local function create_rbac_routes(simple_rbac_config) 
    local rbac_routes = simple_rbac_routes:new(simple_rbac_config)
    local err = rbac_routes:init()
    if err then
        core.log.error("rbac_routes:init failed! err:", err)
        return nil, err
    else
        core.log.info("rbac_routes:init ok")
    end
    return rbac_routes
end

function _M.rbac_routes(simple_rbac_yaml)
    local file_info = _M.file_infos[simple_rbac_yaml] or {}
    local last_change_time = file_info.last_change_time
    local simple_rbac_config = file_info.simple_rbac_config
    if not last_change_time then
        local ok = false
        ok, simple_rbac_config, last_change_time = recheck_yaml_config(simple_rbac_yaml)
        ngx.timer.every(5, function()
            recheck_yaml_config(simple_rbac_yaml)
        end)
        if not ok then
            return nil
        end
    end
    return core.lrucache.global("/rbac_routes/" .. simple_rbac_yaml, last_change_time, create_rbac_routes, simple_rbac_config)
end

function _M.check_schema(conf)
    core.log.info("input conf: ", core.json.delay_encode(conf))

    local ok, err = core.schema.check(schema, conf)
    if not ok then
        return false, err
    end

    if not conf.apiname then
        conf.apiname = 'unset'
    end

    if not conf.secret then
        conf.secret = core.id.gen_uuid_v4()
    end

    if not conf.exp then
        conf.exp = 60 * 60 * 24
    end

    if not conf.simple_rbac_yaml then
        conf.simple_rbac_yaml = "conf/simple-rbac.yaml"
    end

    local ok, err = read_simple_rbac_yaml(conf.simple_rbac_yaml, conf.last_change_time)
    if not ok then
        return false, err
    end

    return true
end

local function fetch_jwt_token()
    local args = ngx.req.get_uri_args()
    if args and args.rbac_token then
        return args.rbac_token
    end

    local headers = ngx.req.get_headers()
    if headers.Authorization then
        return headers.Authorization
    end
    if headers['rbac-token'] then
        return headers['rbac-token']
    end
    local cookie, err = ck:new()
    if not cookie then
        return nil, err
    end
    local val, err = cookie:get("rbac-token")
    return val, err
end


function _M.rewrite(conf, ctx)
    local jwt_token, err = fetch_jwt_token()
    if not jwt_token then
        return 401, {ok=false, reason = "请先登陆, 没有找到Token"}
    end

    local jwt_obj = jwt:load_jwt(jwt_token)
    core.log.info("jwt object: ", core.json.delay_encode(jwt_obj))
    if not jwt_obj.valid then
        return 401, {ok=false, reason = jwt_obj.reason}
    end

    local payload = jwt_obj.payload
    local apiname = payload.apiname
    local username = payload.username
    if not apiname or not username then
        return 401, {ok=false, reason = "Token非法"}
    end

    local consumer_conf = consumer.plugin(plugin_name)
    if not consumer_conf then
        return 401, {ok=false, reason = "Missing related consumer"}
    end

    local consumers = core.lrucache.plugin(plugin_name, "consumers_key",
            consumer_conf.conf_version,
            create_consume_cache, consumer_conf)
    core.log.info("customers", core.json.delay_encode(consumers))

    local consumer = consumers[apiname]
    if not consumer then
        return 401, {ok=false, reason = "Invalid apiname in JWT token"}
    end
    core.log.info("consumer: ", core.json.delay_encode(consumer))

    jwt_obj = jwt:verify_jwt_obj(consumer.auth_conf.secret, jwt_obj)
    core.log.info("jwt verify object: ", core.json.delay_encode(jwt_obj))
    if not jwt_obj.verified then
        return 401, {ok=false, reason = jwt_obj.reason}
    end

    local simple_rbac_yaml = consumer.auth_conf.simple_rbac_yaml
    if not simple_rbac_yaml then
        return 500, {ok=false, reason = "simple_rbac_yaml is nil"}
    end

    local rbac_routes = _M.rbac_routes(simple_rbac_yaml)
    if not rbac_routes then
        core.log.error("init rbac routes failed!")
        return 500, {ok=false, reason="初始化rbac routes出错了"}
    end

    local user_info, err = rbac_routes:get_user(username)
    if err then
        core.log.error("user [", username, "] is missing! ", err)
        return 401, {ok = false, reason="用户已不存在"}
    end

    local method = ctx.var.request_method
    local path = ctx.var.uri
    core.log.info("rbac_routes:match(method: ", method, ", path: ", path, ")")
    local route = rbac_routes:match(method, path)
    if not route then
        core.log.warn("rbac_routes:match(method: ", method, ", path: ", path, ") not found any route")
        return 401, {ok=false, reason="请求的url配置rbac规则"}
    end
    core.log.info("rbac_routes:match(method: ", method, ", path: ", path, ") route: ", core.json.delay_encode(route))
    local permission = route.permission
    if permission == 'ALLOW_ALL' then
        core.log.info('resource {method: ', method, ', path: ', path, '} permission is [', permission, '], allow all user to access!')
    elseif permission == 'DENY_ALL' then
        core.log.info('resource {method: ', method, ', path: ', path, '} permission is [', permission, '], not allow any user to access!')
        return 401, {ok=false, reason="你没有权限执行此操作"}
    elseif user_info.permissions[permission] then
        core.log.info('user [',username,'] have permission [', permission, '] to access {method: ', method, ', path: ', path, '}')
    else
        core.log.info('user [',username,'] have no permission [', permission, '] to access {method: ', method, ', path: ', path, '}')
        return 401, {ok=false, reason="你没有权限执行此操作, 需要的权限为:" .. permission}
    end
    core.request.set_header('rbac-username', username)

    core.log.info("simple-rbac check ok")
end

local function get_args(name, kind)
    local args
    ngx.req.read_body()
    if string.find(ngx.req.get_headers()["Content-Type"] or "",
                    "application/json", 0) then
        args = json.decode(ngx.req.get_body_data())
    else
        args = ngx.req.get_post_args()
    end
    return args;
end

local function login()
    local args = get_args()
    if not args or not args.username or not args.password then
        return core.response.exit(400, {ok=false, reason="参数错误, 用户名或密码缺失"})
    end
    core.log.info("args: ", core.json.delay_encode(args))

    local apiname = args.apiname
    local username = args.username
    local password = args.password
    core.log.info("plugin_name::", plugin_name)

    local consumer_conf = consumer.plugin(plugin_name)
    if not consumer_conf then
        return core.response.exit(404, {ok=false, reason="missing config."})
    end

    local consumers = core.lrucache.plugin(plugin_name, "consumers_key",
            consumer_conf.conf_version,
            create_consume_cache, consumer_conf)

    core.log.info("consumers: ", core.json.delay_encode(consumers))
    local consumer = consumers[apiname]
    if not consumer then
        core.log.info("request apiname [", apiname, "] not found")
        return core.response.exit(404, {ok=false, reason="apiname not found"})
    end

    local rbac_conf = consumer.auth_conf

    local rbac_routes = _M.rbac_routes(rbac_conf.simple_rbac_yaml)
    if not rbac_routes then
        core.log.error("init rbac routes failed!")
        return core.response.exit(500, {ok=false, reason="初始化rbac routes出错了"})
    end

    core.log.info("consumer: ", core.json.delay_encode(consumer))
    local user_info, err = rbac_routes:get_user(username)
    if err then
        core.log.info("user ", username, " login failed! ", err)
        core.response.exit(401, {ok = false, reason="用户不存在"})
    end

    if rbac_conf.password_encode then
        password = password_hash(password, rbac_conf.password_salt)
    end
    core.log.info("request password:", password, " user.pasword:", user_info.password)

    if password ~= user_info.password  then
        core.log.info("user ", username, " login failed! wrong password")
        core.response.exit(401, {ok = false, reason="密码不正确"})
    end

    local token = jwt:sign(
        rbac_conf.secret,
        {
            header={
                typ = "JWT",
                alg = algorithm
            },
            payload={
                apiname = apiname,
                username = username,
                exp = ngx_time() + rbac_conf.exp
            }
        }
    )

    core.response.exit(200, {token=token})
end

function _M.api()
    return {
        {
            methods = {"POST"},
            uri = "/apisix/plugin/simple-rbac/login",
            handler = login,
        }
    }
end


return _M
