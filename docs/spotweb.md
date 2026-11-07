# Spotweb + cache-turbo

_Last researched: 2026-10-06 (Spotweb develop)._

**There is no `spotweb` preset.** Spotweb is a poor fit for a shared page cache
and a preset would only suggest otherwise.

## Why there is no preset

Spotweb sets `spotsession=<sid>.<uid>` on **every** non-API request, including
anonymous ones (user id 1), and issues a **fresh session id on each anonymous
request**. So every browser response carries a `Set-Cookie`, and the module's
storage floor refuses to store a response that sets a cookie. A preset bypassing
on `spotsession=` would bypass 100% of traffic; one that does not bypass would
still store nothing.

The API is cookie-free: it authenticates with the `apikey` arg (and
`nzbhandlerapikey` for the NZB handler). Everything goes through the single
entry point `index.php?page=`, so a URI rule cannot separate public from private
pages either.

Upstream marks the HTML, `rss`, `newznabapi` and `getnzb` responses `private`;
only static files, `catsjson` and `getimage` are `public`.

## What to do instead

Cache only the static file directories (`/images/`, `/js/`, `/css/`) and leave
the application uncached. The `getimage` endpoint is also `public`, but it is a
`page=` route on `index.php` that sets the session cookie, so it stays with the
application:

```nginx
location ~ ^/(images|js|css)/ {
    cache_turbo         ct;
    cache_turbo_valid   1h;
    proxy_pass          http://127.0.0.1:8080;
}

location / {
    cache_turbo off;
    proxy_pass  http://127.0.0.1:8080;
}
```

Same class of rejection as [NodeBB](nodebb.md): an identifier issued to guests
cannot mean "logged in". See also [README.md](README.md#apps-we-deliberately-do-not-ship-a-preset-for).
