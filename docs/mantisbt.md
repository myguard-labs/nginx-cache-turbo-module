# MantisBT + cache-turbo

_Last researched: 2026-07-26 (MantisBT `master`)._

MantisBT (`cache_turbo_backend mantisbt;`, with `mantis` as an alias) has
cacheable public issues and changelogs, but several kinds of visitor state. The
preset errs toward bypass for project/filter preferences.

## Preset rules

<!-- markdownlint-disable MD013 -->

| Check | Values |
| --- | --- |
| Cookie-name suffix, non-empty | `_STRING_COOKIE`, `_PROJECT_COOKIE`, `_VIEW_ALL_COOKIE`, `_BUG_LIST_COOKIE`, `_collapse_settings` |
| Cookie substring | `PHPSESSID=` |
| URI prefixes | login/signup/account/form entry points, `/admin/`, `/api/` |

<!-- markdownlint-enable MD013 -->

Mantis prepends `$g_cookie_prefix` (default `MANTIS`) to the symbolic names in
[`config_defaults_inc.php`](https://github.com/mantisbt/mantisbt/blob/master/config_defaults_inc.php),
so exact defaults are unsafe. Suffix matching survives a renamed install.
`_STRING_COOKIE` is issued only by the successful auth path in
[`authentication_api.php`](https://github.com/mantisbt/mantisbt/blob/master/core/authentication_api.php).

Form-security tokens are stored in a lazily created native PHP session by
[`form_api.php`](https://github.com/mantisbt/mantisbt/blob/master/core/form_api.php).
That session uses PHP's default `PHPSESSID`, and Mantis sets
`session_cache_limiter('private_no_expire')` in
[`session_api.php`](https://github.com/mantisbt/mantisbt/blob/master/core/session_api.php).
The cookie rule plus implied `Cache-Control` honor provide both request- and
response-side protection.

## Vhost core

```nginx
location / {
    try_files $uri $uri/ /index.php$is_args$args;
}

location ~ \.php$ {
    cache_turbo         ct;
    cache_turbo_backend mantisbt;
    cache_turbo_key     $host$request_uri;
    cache_turbo_valid   30s;
    cache_turbo_preset  conservative;

    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_pass unix:/run/php/php-fpm.sock;
}
```

## Verify and caveats

```bash
# Public issue: MISS then HIT.
curl -s -o /dev/null -D- 'https://bugs.example.com/view.php?id=1' | grep -i x-cache
curl -s -o /dev/null -D- 'https://bugs.example.com/view.php?id=1' | grep -i x-cache

# Custom cookie prefix and anonymous form session: BYPASS.
curl -s -o /dev/null -D- -H 'Cookie: ACME_STRING_COOKIE=token' \
  'https://bugs.example.com/view.php?id=1' | grep -i x-cache
curl -s -o /dev/null -D- -H 'Cookie: PHPSESSID=token' \
  'https://bugs.example.com/view.php?id=1' | grep -i x-cache
```

- If PHP's `session.name` is not `PHPSESSID`, add the configured name with both
  `cache_turbo_bypass` and `cache_turbo_no_store`. The origin's `private`
  limiter is a safety net, but do not deliberately leave the request invisible.
- The suffix rules survive a changed `$g_cookie_prefix`; they cannot discover a
  completely custom `$g_string_cookie`, `$g_project_cookie`, or other individual
  cookie-name setting. Add both directives for every such renamed cookie.
- Custom plugins and SOAP/REST mounts need their own URI review.
- Keep `cache_turbo_cache_control honor`; changing it to `ignore` discards
  Mantis's own private-session protection.
