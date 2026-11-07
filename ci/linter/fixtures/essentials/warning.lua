-- Fixture: warning severity only (lua-cjson-decode-unprotected); must NOT block.
local cjson = require("cjson")
local obj = cjson.decode(ngx.var.http_x_payload)
return obj
