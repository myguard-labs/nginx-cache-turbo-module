-- Fixture: no essentials hit of any severity.
local httpc = require("resty.http").new()
local res = httpc:request_uri("https://example.invalid/", { ssl_verify = true })
return res
