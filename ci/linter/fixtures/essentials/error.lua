-- Fixture: one error-severity essentials hit (lua-http-client-verify-disabled).
local httpc = require("resty.http").new()
local res = httpc:request_uri("https://example.invalid/", { ssl_verify = false })
return res
