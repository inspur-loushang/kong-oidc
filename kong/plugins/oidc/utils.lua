local M = {}

local function parseFilters(csvFilters)
  local filters = {}
  if (not (csvFilters == nil)) then
    for pattern in string.gmatch(csvFilters, "[^,]+") do
      table.insert(filters, pattern)
    end
  end
  return filters
end

function M.get_redirect_uri_path(ngx)
  local function drop_query()
    local uri = ngx.var.request_uri
    local x = uri:find("?")
    if x then
      return uri:sub(1, x - 1)
    else
      return uri
    end
  end

  local function tackle_slash(path)
    local args = ngx.req.get_uri_args()
    if args and args.code then
      return path
    elseif path == "/" then
      return "/cb"
    elseif path:sub(-1) == "/" then
      return path:sub(1, -2)
    else
      return path .. "/"
    end
  end

  return tackle_slash(drop_query())
end

function M.get_options(config, ngx)
  return {
    client_id = config.client_id,
    client_secret = config.client_secret,
    discovery = config.discovery,
    introspection_endpoint = config.introspection_endpoint,
    redirect_uri_path = M.get_redirect_uri_path(ngx),
    scope = config.scope,
    response_type = config.response_type,
    ssl_verify = config.ssl_verify,
    token_endpoint_auth_method = config.token_endpoint_auth_method,
    recovery_page_path = config.recovery_page_path,
    filters = parseFilters(config.filters)
  }
end

function M.adapt_multi_tenant(config, ngx)
  local tmp_config = config
  local uri = ngx.var.request_uri
  local x = uri:find("?realm")
  if x then
    local c = uri:sub(x + 1)
    local d = c:find("=")
    local realm = c:sub(d + 1)
    local introspection_endpoint = tmp_config.introspection_endpoint
    local discovery = tmp_config.discovery
    local mrealm = "realms/" .. realm .. "/"
    local n_introspection_endpoint = string.gsub(introspection_endpoint, "realms/%w+/", mrealm)
    local n_discovery = string.gsub(discovery, "realms/%w+/", mrealm)
    tmp_config.introspection_endpoint = n_introspection_endpoint
    tmp_config.discovery = n_discovery
  else
    return config
  end
  return tmp_config
end

function M.exit(httpStatusCode, message, ngxCode)
  ngx.status = httpStatusCode
  ngx.say(message)
  ngx.exit(ngxCode)
end

function M.injectUser(user)
  local tmp_user = user
  tmp_user.id = user.sub
  tmp_user.username = user.preferred_username
  ngx.ctx.authenticated_consumer = tmp_user
end

function M.has_bearer_access_token()
  local header =  ngx.req.get_headers()['Authorization']
  if header and header:find(" ") then
    local divider = header:find(' ')
    if string.lower(header:sub(0, divider-1)) == string.lower("Bearer") then
      return true
    end
  end
  return false
end

return M
