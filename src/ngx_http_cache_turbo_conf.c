/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * http-cache-turbo — location-config merge + L2 backend directive handlers.
 *
 * Split out of ngx_http_cache_turbo_module.c (MAINT-C1): merge_loc_conf and
 * the cache_turbo_redis / cache_turbo_memcached directive handlers were the
 * three highest-complexity functions in that file. Behaviour-preserving move
 * + local decomposition only — merge_loc_conf's per-group helpers below run
 * in the exact same relative order as the original single-function body,
 * because later conjuncts read fields earlier ones set (preset -> band
 * resolution -> defaults; redis_tls/tls_verify/tls_ca -> SSL context build).
 */

#include "ngx_http_cache_turbo_module.h"

#if (NGX_SSL)
#include <ngx_event_openssl.h>
#endif


/* AUD-MC1: validate an operator-supplied L2 key prefix at config time, for both
 * backends. The composed key is prefix + a hex digest, and the module documents
 * it as printable, space-free and <=250 bytes -- an invariant only the digest
 * half ever honoured. On memcached a space or CRLF in the prefix splits the
 * delimiter-framed command outright; on Redis it merely makes keys that no
 * operator can type back into redis-cli. There is no attacker path (every
 * request-controlled byte terminates at the digest), so this is a config typo
 * that used to fail silently, degrading the location to L1-only.
 *
 * `name` is the directive, so the error names the line the operator wrote. */
static char *
ngx_http_cache_turbo_check_l2_prefix(ngx_conf_t *cf, ngx_str_t *prefix,
    const char *name)
{
    size_t  i;

    if (prefix->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo: empty prefix= is not allowed "
            "(an all-purge would match the whole L2 keyspace)");
        return NGX_CONF_ERROR;
    }

    for (i = 0; i < prefix->len; i++) {
        if (prefix->data[i] <= 0x20 || prefix->data[i] >= 0x7f) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "%s: prefix= contains byte 0x%02Xd at offset %uz; the L2 key "
                "must be printable and free of spaces and control characters",
                name, prefix->data[i], i);
            return NGX_CONF_ERROR;
        }
    }

    if (prefix->len + NGX_HTTP_CACHE_TURBO_L2_KEY_SUFFIX_MAX
        > NGX_HTTP_CACHE_TURBO_L2_KEY_MAX)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "%s: prefix= is %uz bytes; at most %uz are usable, because the "
            "module appends up to %d bytes of key and an L2 key may not "
            "exceed %d bytes",
            name, prefix->len,
            (size_t) (NGX_HTTP_CACHE_TURBO_L2_KEY_MAX
                      - NGX_HTTP_CACHE_TURBO_L2_KEY_SUFFIX_MAX),
            NGX_HTTP_CACHE_TURBO_L2_KEY_SUFFIX_MAX,
            NGX_HTTP_CACHE_TURBO_L2_KEY_MAX);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * "cache_turbo_redis <dsn|host:port> [prefix=] [timeout=] [password=] [user=]
 *  [db=] [tls=on|off] [tls_verify=on|off] [tls_ca=<file>] [tls_name=<host>]
 *  [scan_deadline=];"
 *
 * The DSN is redis://[user:pass@]host:port/db ; rediss:// selects TLS. Bare
 * host:port still works (legacy). Trailing params override whatever the DSN
 * carried. The address is resolved at config time; settable at http/server/
 * location level and merged down, so a whole http{} block can share one L2.
 */
char *
ngx_http_cache_turbo_redis_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t   *value, s, hostport, arg1;
    ngx_url_t    u;
    ngx_uint_t   i;
    ngx_int_t    t;
    u_char      *rest, *last, *at, *slash, *colon;

    value = cf->args->elts;
    arg1 = value[1];

    if (clcf->memcached == 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_redis: an L2 backend (cache_turbo_memcached) is already "
            "configured in this block; the two are mutually exclusive");
        return NGX_CONF_ERROR;
    }

    /* --- 1. split the DSN (scheme / userinfo / host:port / db) ------------- */
    hostport = arg1;

    if (arg1.len > sizeof("rediss://") - 1
        && ngx_strncasecmp(arg1.data, (u_char *) "rediss://",
                           sizeof("rediss://") - 1) == 0)
    {
        clcf->redis_tls = 1;
        rest = arg1.data + sizeof("rediss://") - 1;

    } else if (arg1.len > sizeof("redis://") - 1
               && ngx_strncasecmp(arg1.data, (u_char *) "redis://",
                                  sizeof("redis://") - 1) == 0)
    {
        rest = arg1.data + sizeof("redis://") - 1;

    } else {
        rest = NULL;        /* bare host:port */
    }

    if (rest != NULL) {
        last = arg1.data + arg1.len;

        at = ngx_strlchr(rest, last, '@');
        if (at != NULL) {
            colon = ngx_strlchr(rest, at, ':');
            if (colon != NULL) {
                clcf->redis_user.data = rest;
                clcf->redis_user.len = colon - rest;
                clcf->redis_password.data = colon + 1;
                clcf->redis_password.len = at - (colon + 1);
            } else {
                clcf->redis_user.data = rest;
                clcf->redis_user.len = at - rest;
            }
            rest = at + 1;
        }

        slash = ngx_strlchr(rest, last, '/');
        if (slash != NULL) {
            if (last - (slash + 1) > 0) {
                clcf->redis_db = ngx_atoi(slash + 1,
                                          last - (slash + 1));
                if (clcf->redis_db == NGX_ERROR || clcf->redis_db < 0) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "cache_turbo_redis: bad db in DSN \"%V\"", &arg1);
                    return NGX_CONF_ERROR;
                }
                if (clcf->redis_db > NGX_HTTP_CACHE_TURBO_REDIS_DB_MAX) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "cache_turbo_redis: db in DSN \"%V\" exceeds the "
                        "maximum %d", &arg1,
                        NGX_HTTP_CACHE_TURBO_REDIS_DB_MAX);
                    return NGX_CONF_ERROR;
                }
            }
            hostport.data = rest;
            hostport.len = slash - rest;
        } else {
            hostport.data = rest;
            hostport.len = last - rest;
        }
    }

    /* --- 2. resolve the host:port ----------------------------------------- */
    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = hostport;
    u.default_port = 6379;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "cache_turbo_redis: %s in \"%V\"", u.err, &u.url);
        }
        return NGX_CONF_ERROR;
    }
    if (u.naddrs == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "cache_turbo_redis: no addresses for \"%V\"", &u.url);
        return NGX_CONF_ERROR;
    }

    clcf->redis_addr = u.addrs[0];
    clcf->redis_host = u.host;        /* default SNI / verify name */

    /* --- 3. trailing params override the DSN ------------------------------ */
    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "prefix=", 7) == 0) {
            clcf->redis_prefix.data = value[i].data + 7;
            clcf->redis_prefix.len = value[i].len - 7;
            if (ngx_http_cache_turbo_check_l2_prefix(cf, &clcf->redis_prefix,
                                                     "cache_turbo_redis")
                != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }

        } else if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
            s.data = value[i].data + 8;
            s.len = value[i].len - 8;
            t = ngx_parse_time(&s, 0);   /* milliseconds */
            if (t == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "cache_turbo_redis: bad timeout \"%V\"", &s);
                return NGX_CONF_ERROR;
            }
            if (t == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "cache_turbo_redis: timeout must be > 0");
                return NGX_CONF_ERROR;
            }
            clcf->redis_timeout = (ngx_msec_t) t;

        } else if (ngx_strncmp(value[i].data, "keepalive=", 10) == 0) {
            clcf->redis_keepalive = ngx_atoi(value[i].data + 10,
                                             value[i].len - 10);
            if (clcf->redis_keepalive == NGX_ERROR
                || clcf->redis_keepalive < 0)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_redis: bad keepalive \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }
            /* STAB-5: bound N so the pool's N*sizeof(item) alloc can't overflow. */
            if (clcf->redis_keepalive > NGX_HTTP_CACHE_TURBO_KEEPALIVE_MAX) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_redis: keepalive %V exceeds the maximum %d",
                    &value[i], NGX_HTTP_CACHE_TURBO_KEEPALIVE_MAX);
                return NGX_CONF_ERROR;
            }

        } else if (ngx_strncmp(value[i].data, "keepalive_timeout=", 18) == 0) {
            s.data = value[i].data + 18;
            s.len = value[i].len - 18;
            t = ngx_parse_time(&s, 0);   /* milliseconds */
            if (t == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_redis: bad keepalive_timeout \"%V\"", &s);
                return NGX_CONF_ERROR;
            }
            clcf->redis_keepalive_timeout = (ngx_msec_t) t;

        } else if (ngx_strncmp(value[i].data, "connect_backoff=", 16) == 0) {
            s.data = value[i].data + 16;
            s.len = value[i].len - 16;
            t = ngx_parse_time(&s, 0);   /* milliseconds; 0 = disabled */
            if (t == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_redis: bad connect_backoff \"%V\"", &s);
                return NGX_CONF_ERROR;
            }
            clcf->redis_connect_backoff = (ngx_msec_t) t;

        } else if (ngx_strncmp(value[i].data, "password=", 9) == 0) {
            clcf->redis_password.data = value[i].data + 9;
            clcf->redis_password.len = value[i].len - 9;

        } else if (ngx_strncmp(value[i].data, "user=", 5) == 0) {
            clcf->redis_user.data = value[i].data + 5;
            clcf->redis_user.len = value[i].len - 5;

        } else if (ngx_strncmp(value[i].data, "db=", 3) == 0) {
            clcf->redis_db = ngx_atoi(value[i].data + 3, value[i].len - 3);
            if (clcf->redis_db == NGX_ERROR || clcf->redis_db < 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "cache_turbo_redis: bad db \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }
            if (clcf->redis_db > NGX_HTTP_CACHE_TURBO_REDIS_DB_MAX) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "cache_turbo_redis: db \"%V\" exceeds the "
                                   "maximum %d", &value[i],
                                   NGX_HTTP_CACHE_TURBO_REDIS_DB_MAX);
                return NGX_CONF_ERROR;
            }

        } else if (ngx_strncmp(value[i].data, "tls=", 4) == 0) {
            s.data = value[i].data + 4;
            s.len = value[i].len - 4;
            if (s.len == 2 && ngx_strncmp(s.data, "on", 2) == 0) {
                clcf->redis_tls = 1;
            } else if (s.len == 3 && ngx_strncmp(s.data, "off", 3) == 0) {
                clcf->redis_tls = 0;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "cache_turbo_redis: tls must be on|off");
                return NGX_CONF_ERROR;
            }

        } else if (ngx_strncmp(value[i].data, "tls_verify=", 11) == 0) {
            s.data = value[i].data + 11;
            s.len = value[i].len - 11;
            if (s.len == 2 && ngx_strncmp(s.data, "on", 2) == 0) {
                clcf->redis_tls_verify = 1;
            } else if (s.len == 3 && ngx_strncmp(s.data, "off", 3) == 0) {
                clcf->redis_tls_verify = 0;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "cache_turbo_redis: tls_verify must be on|off");
                return NGX_CONF_ERROR;
            }

        } else if (ngx_strncmp(value[i].data, "tls_ca=", 7) == 0) {
            clcf->redis_tls_ca.data = value[i].data + 7;
            clcf->redis_tls_ca.len = value[i].len - 7;

        } else if (ngx_strncmp(value[i].data, "tls_name=", 9) == 0) {
            clcf->redis_tls_name.data = value[i].data + 9;
            clcf->redis_tls_name.len = value[i].len - 9;

        } else if (ngx_strncmp(value[i].data, "scan_deadline=", 14) == 0) {
            /* S231-L2-SCANTIME: wall-clock ceiling on one all-purge SCAN walk,
             * on top of the fixed SCAN_MAX_PAGES page cap. "0" disables it
             * (page-cap-only, legacy behaviour) rather than being rejected
             * like a zero connect timeout: the page cap alone is a legitimate,
             * if generous, non-termination guard. */
            s.data = value[i].data + 14;
            s.len = value[i].len - 14;
            t = ngx_parse_time(&s, 0);   /* milliseconds */
            if (t == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_redis: bad scan_deadline \"%V\"", &s);
                return NGX_CONF_ERROR;
            }
            clcf->redis_scan_deadline = (ngx_msec_t) t;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "cache_turbo_redis: invalid parameter \"%V\"",
                               &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    /* The client TLS context is built in merge_loc_conf (COR-6), once
     * redis_tls / tls_verify / tls_ca are resolved — not here, where an
     * inherited verify flag or CA would not yet be visible. */

    clcf->redis_enable = 1;
    /* Pin the backend choice for this block to Redis. Without this the flag
     * stays UNSET and merge_loc_conf would inherit a parent's memcached=1,
     * selecting the memcached driver for this block's redis:// address. */
    clcf->memcached = 0;

    return NGX_CONF_OK;
}


/*
 * "cache_turbo_memcached <host:port> [prefix=] [timeout=];"  (v13)
 *
 * Selects the memcached L2 backend instead of Redis. Reuses the redis_addr/
 * redis_prefix/redis_timeout/redis_enable fields (the two backends are mutually
 * exclusive — one L2 per location) and sets clcf->memcached so the merge step
 * wires the memcached vtable. No DSN/auth/db/TLS: memcached's text protocol has
 * no AUTH/SELECT and we keep the driver plain-TCP.
 */
char *
ngx_http_cache_turbo_memcached_conf(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t   *value, s;
    ngx_url_t    u;
    ngx_uint_t   i;
    ngx_int_t    t;

    value = cf->args->elts;

    if (clcf->redis_enable == 1 && clcf->memcached != 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_memcached: an L2 backend (cache_turbo_redis) is already "
            "configured in this block; the two are mutually exclusive");
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = value[1];
    u.default_port = 11211;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_memcached: %s in \"%V\"", u.err, &u.url);
        }
        return NGX_CONF_ERROR;
    }
    if (u.naddrs == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_memcached: no addresses for \"%V\"", &u.url);
        return NGX_CONF_ERROR;
    }

    clcf->redis_addr = u.addrs[0];

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "prefix=", 7) == 0) {
            clcf->redis_prefix.data = value[i].data + 7;
            clcf->redis_prefix.len = value[i].len - 7;
            if (ngx_http_cache_turbo_check_l2_prefix(cf, &clcf->redis_prefix,
                                                     "cache_turbo_memcached")
                != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }

        } else if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
            s.data = value[i].data + 8;
            s.len = value[i].len - 8;
            t = ngx_parse_time(&s, 0);   /* milliseconds */
            if (t == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_memcached: bad timeout \"%V\"", &s);
                return NGX_CONF_ERROR;
            }
            if (t == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_memcached: timeout must be > 0");
                return NGX_CONF_ERROR;
            }
            clcf->redis_timeout = (ngx_msec_t) t;

        } else if (ngx_strncmp(value[i].data, "keepalive=", 10) == 0) {
            s.data = value[i].data + 10;
            s.len = value[i].len - 10;
            clcf->memcached_keepalive = ngx_atoi(s.data, s.len);
            if (clcf->memcached_keepalive == NGX_ERROR
                || clcf->memcached_keepalive < 0)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_memcached: bad keepalive \"%V\"", &s);
                return NGX_CONF_ERROR;
            }
            if (clcf->memcached_keepalive > NGX_HTTP_CACHE_TURBO_KEEPALIVE_MAX) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_memcached: keepalive must be <= %d",
                    NGX_HTTP_CACHE_TURBO_KEEPALIVE_MAX);
                return NGX_CONF_ERROR;
            }

        } else if (ngx_strncmp(value[i].data, "keepalive_timeout=", 18) == 0) {
            s.data = value[i].data + 18;
            s.len = value[i].len - 18;
            t = ngx_parse_time(&s, 0);
            if (t == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_memcached: bad keepalive_timeout \"%V\"", &s);
                return NGX_CONF_ERROR;
            }
            clcf->memcached_keepalive_timeout = (ngx_msec_t) t;

        } else if (ngx_strncmp(value[i].data, "connect_backoff=", 16) == 0) {
            s.data = value[i].data + 16;
            s.len = value[i].len - 16;
            t = ngx_parse_time(&s, 0);   /* milliseconds; 0 = disabled */
            if (t == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_memcached: bad connect_backoff \"%V\"", &s);
                return NGX_CONF_ERROR;
            }
            clcf->redis_connect_backoff = (ngx_msec_t) t;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_memcached: invalid parameter \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
    }

    clcf->redis_enable = 1;
    clcf->memcached = 1;

    return NGX_CONF_OK;
}


/* ---------------------------------------------------------------------- *
 * merge_loc_conf decomposition (MAINT-C1). ⚠ ORDERING-SENSITIVE: each
 * helper below is called from ngx_http_cache_turbo_merge_loc_conf() in the
 * exact same relative order the original single function ran its
 * statements in, because later groups read fields earlier groups resolve
 * (e.g. the preset/band group must run before anything reads conf->valid /
 * conf->stale_mult / conf->min_uses; the L2 identity group must run before
 * the SSL-context group, which must run before the vtable-resolve group).
 * Do not reorder the calls in ngx_http_cache_turbo_merge_loc_conf().
 * ---------------------------------------------------------------------- */

/* Group 1: basic scalars + backend_presets inheritance. */
static void
ngx_http_cache_turbo_merge_basic(ngx_http_cache_turbo_loc_conf_t *conf,
    ngx_http_cache_turbo_loc_conf_t *prev)
{
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_size_value(conf->max_size, prev->max_size, 1024 * 1024);
    ngx_conf_merge_value(conf->suppress_native, prev->suppress_native, 0);

    /* backend_presets is an accumulated bitmask (0 = unset), so the standard
     * UNSET-sentinel merge can't be used; inherit the parent's set when this
     * location named no backend of its own (an explicit backend fully
     * overrides, it does not OR with the parent's).
     *
     * `cache_turbo_backend none;` is what makes that overridable downward: it
     * sets the NONE sentinel bit, so the mask is non-zero, so we do NOT inherit
     * — and since NONE matches no registry row, the location ends up with no
     * preset at all. Without it, a server-level preset could never be switched
     * off for a single location. */
    if (conf->backend_presets == 0) {
        conf->backend_presets = prev->backend_presets;
    }
}

/* Group 2: presets + band-resolved knobs (valid/beta/lock_ttl/stale_mult/
 * min_uses) + the S8 scan-resistant flag, which must resolve before the band
 * block only insofar as it does not depend on it (kept in original order). */
static void
ngx_http_cache_turbo_merge_presets(ngx_http_cache_turbo_loc_conf_t *conf,
    ngx_http_cache_turbo_loc_conf_t *prev)
{
    /*
     * Presets (v3-2). Two-stage so a location's preset can still set the band
     * defaults even when an ANCESTOR already resolved its own effective knobs:
     *
     *  1. Inherit the preset enum down the tree.
     *  2. Inherit the *explicit* (raw) knob values with NGX_CONF_UNSET as the
     *     fallback — NOT a literal. A knob therefore stays UNSET unless a real
     *     cache_turbo_valid/_beta/_lock_ttl directive set it at some level. This
     *     is the crucial bit: if we filled a literal/band default here, that
     *     value would no longer look UNSET to a descendant, so the descendant's
     *     own preset could never override it (the classic merge-poisoning trap).
     *  3. Resolve the effective knob: explicit raw value if set, else this
     *     level's resolved-preset band value. All four knobs (valid, beta,
     *     lock_ttl, stale_mult) follow this same raw/effective split.
     *
     * Net effect: an explicit directive beats a preset; a nearer preset beats a
     * farther one; nothing leaks a band default into the inheritance chain.
     */
    if (conf->preset == NGX_CONF_UNSET) {
        conf->preset = prev->preset;
    }

    /* S8: deliberately NOT band-resolved. No preset enables scan resistance --
     * it is a behaviour change with a keyspace-shape trade-off, so it is opt-in
     * per location and nothing else. Plain inherit, then default to 0 = OFF.
     * An explicit `off` stores 0 (not UNSET), so it correctly overrides an
     * inherited `on` rather than re-inheriting it here. */
    if (conf->scan_resistant_pct == (ngx_uint_t) NGX_CONF_UNSET) {
        conf->scan_resistant_pct = prev->scan_resistant_pct;
    }
    if (conf->scan_resistant_pct == (ngx_uint_t) NGX_CONF_UNSET) {
        conf->scan_resistant_pct = 0;
    }

    {
        ngx_int_t                          p;
        const ngx_http_cache_turbo_band_t  *band;

        p = (conf->preset == NGX_CONF_UNSET)
                ? NGX_HTTP_CACHE_TURBO_PRESET_DEFAULT : conf->preset;
        band = &ngx_http_cache_turbo_bands[p];

        ngx_conf_merge_sec_value(conf->valid_raw, prev->valid_raw,
                                 NGX_CONF_UNSET);
        ngx_conf_merge_value(conf->beta_raw, prev->beta_raw, NGX_CONF_UNSET);
        ngx_conf_merge_sec_value(conf->lock_ttl_raw, prev->lock_ttl_raw,
                                 NGX_CONF_UNSET);
        ngx_conf_merge_value(conf->stale_mult_raw, prev->stale_mult_raw,
                             NGX_CONF_UNSET);
        ngx_conf_merge_value(conf->min_uses_raw, prev->min_uses_raw,
                             NGX_CONF_UNSET);

        conf->valid = (conf->valid_raw == NGX_CONF_UNSET)
                          ? band->valid : conf->valid_raw;
        conf->beta = (conf->beta_raw == NGX_CONF_UNSET)
                          ? band->beta : conf->beta_raw;
        conf->lock_ttl = (conf->lock_ttl_raw == NGX_CONF_UNSET)
                          ? band->lock_ttl : conf->lock_ttl_raw;
        conf->stale_mult = (conf->stale_mult_raw == NGX_CONF_UNSET)
                          ? band->stale_mult : conf->stale_mult_raw;
        conf->min_uses = (conf->min_uses_raw == NGX_CONF_UNSET)
                          ? band->min_uses : conf->min_uses_raw;
    }
}

/* Group 3: L2 negative memo, keep_stale, use_stale, and the circuit breaker's
 * own tunables (enable/threshold/window/open/retry_after). */
static void
ngx_http_cache_turbo_merge_breaker(ngx_http_cache_turbo_loc_conf_t *conf,
    ngx_http_cache_turbo_loc_conf_t *prev)
{
    /* L2 negative memo (L13). Deliberately NOT a preset band column: the memo
     * trades L2 coherence for a saved round-trip, and that must be opted into
     * per location rather than inherited from a preset name. Defaults to 0
     * (off) at every preset, so this is inert unless explicitly configured. */
    ngx_conf_merge_sec_value(conf->l2_negative_ttl, prev->l2_negative_ttl, 0);

    /* cache_turbo_keep_stale (S2.1). Not a preset band column, but shipped ON
     * by default (S231-DEFAULTS): outage resilience -- serving a stale object
     * past its normal window beats a hard miss when the origin is down, and
     * an operator who wants the old strict-off behavior still has
     * `cache_turbo_keep_stale off` to get it back explicitly. 86400 (24h)
     * matches the approved default value. Consulted on the store path, where
     * a non-zero value widens sie_window (S2.2). */
    ngx_conf_merge_sec_value(conf->keep_stale, prev->keep_stale, 86400);

    /* cache_turbo_use_stale (S4.1). Plain inherit/default, same shape as
     * keep_stale above. Default is USE_STALE_DEFAULT (HTTP_500|502|503|504 +
     * ANY_5XX), which reproduces today's unconditional "any 5xx" trigger at
     * ngx_http_cache_turbo_header_filter byte-for-byte -- see the header
     * comment on NGX_HTTP_CACHE_TURBO_USE_STALE_DEFAULT for why the ANY_5XX
     * bit is required to make that true. Consulted on the request path by the
     * stale-if-error gate in ngx_http_cache_turbo_header_filter (S4.2). */
    ngx_conf_merge_uint_value(conf->use_stale, prev->use_stale,
                              NGX_HTTP_CACHE_TURBO_USE_STALE_DEFAULT);

    /* O4.4: the breaker's own on/off switch, independent of clcf->enable and
     * of the threshold/window off-switches below -- see
     * ngx_http_cache_turbo_breaker_should_consult(). Shipped ON by default
     * (S231-DEFAULTS): outage resilience -- a flapping/dead origin should
     * trip the breaker out of the box, not only after an operator discovers
     * and opts into it. `cache_turbo_breaker off` (or either off-switch
     * below at 0) restores the old fully-disabled behavior explicitly. */
    ngx_conf_merge_value(conf->breaker_enable, prev->breaker_enable, 1);

    /* P6/O4.2 breaker tuning. Shipped ON by default (S231-DEFAULTS) alongside
     * breaker_enable above: 5 failures within a 10s window is a reasonable
     * out-of-the-box trip point for a flapping origin, tight enough to react
     * fast, loose enough not to trip on ordinary transient errors. An
     * explicit 0 on either one still fully disables tripping/window
     * accounting in _breaker_record(). */
    ngx_conf_merge_uint_value(conf->breaker_threshold,
                              prev->breaker_threshold, 5);
    ngx_conf_merge_sec_value(conf->breaker_window, prev->breaker_window, 10);

    /* P6/O4.3. ⚠ breaker_open merges to a NON-ZERO default, unlike every other
     * breaker field. 0 is not "off" for this one -- it is the one value that
     * WEDGES the breaker: _breaker_state() guards its timed reopen on
     * `open_for > 0`, so with 0 an OPEN breaker never promotes a probe, and
     * since nobody contacts the origin while OPEN no success can ever be
     * recorded to close it either. The breaker would stay open until reload.
     *
     * The feature is now ON by default (S231-DEFAULTS: breaker_enable=1,
     * breaker_threshold=5, breaker_window=10s), so this default takes effect
     * out of the box, not only once an operator opts in. An operator who sets
     * breaker_threshold to 0 (or breaker_enable off) still skips the state
     * call outright, same as before. cache_turbo_breaker_open's
     * custom handler REJECTS an explicit 0 at parse time rather than accept
     * it as a disable -- tracked as O4.3-a -- so 0 can never reach this merge
     * from an explicit directive; NGX_CONF_UNSET is the only way through.
     *
     * 30s is the usual circuit-breaker recovery probe interval: long enough
     * that a dead origin is not re-probed hard, short enough that a recovered
     * one is picked up quickly. */
    ngx_conf_merge_sec_value(conf->breaker_open, prev->breaker_open, 30);

    /* Advisory only; 0 = send no Retry-After at all. cache_turbo_breaker_open
     * is rejected at 0 (see above) but the fully-merged breaker_open here can
     * still legitimately be a small operator-chosen value, so the effective
     * value should track the EFFECTIVE (post-merge) breaker_open rather than
     * a hardcoded constant, keeping the hint in sync with the actual probe
     * interval by default. A `cache_turbo_breaker_retry_after` directive, if
     * given explicitly, always wins -- the auto-track fallback applies only
     * when it was left unset everywhere.
     *
     * BRK-RA1: this merge must NOT default to conf->breaker_open here. nginx
     * merges the enclosing server{} block against http FIRST, before any
     * location merge runs. If nothing sets breaker_retry_after at server
     * scope, that level would resolve to http's breaker_open default (30)
     * -- not NGX_CONF_UNSET -- and every child location leaving it unset
     * would then inherit prev->breaker_retry_after == 30 instead of UNSET,
     * so the location's own breaker_open (e.g. 2s) would never be consulted.
     * Keep this merge plain (prev, else UNSET) so breaker_retry_after stays
     * NGX_CONF_UNSET when nobody set it anywhere; the actual fallback to the
     * effective breaker_open is resolved lazily at request time in
     * ngx_http_cache_turbo_breaker_unavailable(), where clcf is fully merged
     * and request-scoped, so merge order can no longer poison it. */
    ngx_conf_merge_sec_value(conf->breaker_retry_after,
                             prev->breaker_retry_after, NGX_CONF_UNSET);
}

/* Group 4: per-status TTL list, bypass/no_store predicates, Cache-Control
 * mode, auto_vary, and the TEST_FAULTS block. */
static void
ngx_http_cache_turbo_merge_cc_and_bypass(
    ngx_http_cache_turbo_loc_conf_t *conf,
    ngx_http_cache_turbo_loc_conf_t *prev)
{
    /* Per-status TTLs (v6): inherit the rule list if this level set none. */
    if (conf->valid_status == NULL) {
        conf->valid_status = prev->valid_status;
    }

    /* Bypass / no-store predicates (v9). */
    ngx_conf_merge_ptr_value(conf->bypass, prev->bypass, NULL);
    ngx_conf_merge_ptr_value(conf->no_store, prev->no_store, NULL);

    /* Response Cache-Control mode (cache_turbo_cache_control). Default respect.
     * Auto-classify defaults it to "honor" (unless explicitly set in this block)
     * so a backend plugin's own Cache-Control: no-cache on an anon page
     * self-excludes at store time. Done before the merge so an explicit
     * `cache_turbo_cache_control respect;` still wins. honor_cc/ignore_cc are
     * derived from the resolved mode and are what the request path reads. */
    if (NGX_HTTP_CACHE_TURBO_HAS_BACKEND(conf->backend_presets)
        && conf->cc_mode == NGX_CONF_UNSET_UINT)
    {
        conf->cc_mode = NGX_HTTP_CACHE_TURBO_CC_HONOR;
    }
    ngx_conf_merge_uint_value(conf->cc_mode, prev->cc_mode,
                              NGX_HTTP_CACHE_TURBO_CC_RESPECT);
    conf->honor_cc  = (conf->cc_mode == NGX_HTTP_CACHE_TURBO_CC_HONOR);
    conf->ignore_cc = (conf->cc_mode == NGX_HTTP_CACHE_TURBO_CC_IGNORE);
    /* S231-VARY: shipped default is ON. Off, the Vary: Cookie veto in
     * ngx_http_cache_turbo_header_filter never fires, so a response that
     * varies per-user could be served to a different cookie on the
     * stale-serve path -- the one privacy defect that path had.
     * Explicit `cache_turbo_auto_vary off;` still disables it. */
    ngx_conf_merge_value(conf->auto_vary, prev->auto_vary, 1);
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    ngx_conf_merge_value(conf->test_restore_alloc_fail,
                         prev->test_restore_alloc_fail, 0);
    ngx_conf_merge_value(conf->test_force_file_buf,
                         prev->test_force_file_buf, 0);
    ngx_conf_merge_value(conf->test_store_fail,
                         prev->test_store_fail, 0);
    ngx_conf_merge_value(conf->test_scan_max_pages,
                         prev->test_scan_max_pages, 0);
    ngx_conf_merge_value(conf->test_l2_promote_hold_ms,
                         prev->test_l2_promote_hold_ms, 0);
    ngx_conf_merge_value(conf->test_midbody_abort,
                         prev->test_midbody_abort, 0);
#endif
}

/* Group 5: PURGE/surrogate_key, background_update, cold-miss lock, autotune,
 * and the shm_zone/key null-inherit. min_uses is deliberately NOT re-merged
 * here -- see the comment inside, preserved verbatim from the original. */
static void
ngx_http_cache_turbo_merge_zone_and_lock(
    ngx_http_cache_turbo_loc_conf_t *conf,
    ngx_http_cache_turbo_loc_conf_t *prev)
{
    /* PURGE method (v14): off by default. */
    ngx_conf_merge_value(conf->purge, prev->purge, 0);
    ngx_conf_merge_value(conf->surrogate_key, prev->surrogate_key, 0);

    /* v8: background update / SWR defaults ON — the dice-winner serves stale and
     * refreshes in the background rather than blocking on origin. */
    ngx_conf_merge_value(conf->background_update, prev->background_update, 1);

    /* v10: cold-miss single-flight defaults ON — concurrent first-hits for one
     * cold key collapse to a single origin fetch; the rest wait up to
     * lock_timeout (default 5s) and serve the filled entry. */
    ngx_conf_merge_value(conf->lock, prev->lock, 1);
    ngx_conf_merge_msec_value(conf->lock_timeout, prev->lock_timeout, 5000);

    /* min_uses (v15) is resolved in the preset block above (H3c): it inherits as
     * min_uses_raw with an UNSET fallback and resolves against the band, exactly
     * like valid/beta/lock_ttl/stale_mult. Do NOT merge it to a literal here —
     * that would overwrite the band-resolved value and re-poison the inheritance
     * chain the raw/effective split exists to keep clean. The old `< 1` clamp is
     * gone too: ngx_http_cache_turbo_min_uses() range-checks at parse, and every
     * band value is >= 1, so the gate's `> 1` test cannot see a stray 0. */

    /* Live autotune (v4-3): off by default; default recompute cadence when on. */
    ngx_conf_merge_value(conf->autotune, prev->autotune, 0);
    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }
    if (conf->key == NULL) {
        conf->key = prev->key;
    }
}

/* Group 6: cross-location breaker-policy divergence warning (O4.4-d). Needs
 * shm_zone/key resolved from Group 5 and breaker_* resolved from Group 3. */
static void
ngx_http_cache_turbo_merge_breaker_policy_warn(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *conf)
{
    /* O4.4-d: the breaker's STATE and counters live in the ZONE (shared
     * across every location bound to it), but breaker_enable/threshold/
     * window/open/retry_after above are all per-LOCATION. Sibling locations
     * sharing one zone can therefore feed one state machine different
     * policies -- reopen timing becomes "whichever location last called
     * _breaker_state() decides". This is legal (nothing rejects it) and
     * already documented in the README; this block only detects it at
     * config time and warns -- see the O4.4-d ledger entry for the
     * rejected alternatives (main_conf sees unmerged sentinels; a
     * postconfiguration location-tree walk misses named/regex locations,
     * which ngx_http_init_locations() queue_splits off before any walk
     * could reach them).
     *
     * Guarded the same way the request path decides the breaker is live
     * for this location, to avoid a false positive from a server{} block
     * that binds the zone but whose own effective tuple no request ever
     * consults (every location under it overrides the breaker itself). */
    if (conf->shm_zone != NULL
        && ngx_http_cache_turbo_breaker_should_consult(conf))
    {
        ngx_http_cache_turbo_zone_t  *zctx = conf->shm_zone->data;

        /* NULL when the zone is referenced before its cache_turbo_zone
         * directive appears textually -- skip rather than dereference. */
        if (zctx != NULL) {
            /* BRK-RA1: conf->breaker_retry_after can now be NGX_CONF_UNSET
             * (auto-track: nobody set it anywhere). Compare/store/print the
             * EFFECTIVE value -- resolved the same way the request path
             * resolves it, unset falling back to this location's own
             * breaker_open -- not the raw field. Otherwise two locations
             * that both auto-track but have different breaker_open would
             * compare UNSET == UNSET and wrongly look identical, while a
             * spurious -1 could reach the log format string. */
            time_t  eff_retry_after =
                (conf->breaker_retry_after != NGX_CONF_UNSET)
                ? conf->breaker_retry_after
                : conf->breaker_open;

            if (!zctx->policy_seen) {
                zctx->policy_seen         = 1;
                zctx->policy_threshold    = conf->breaker_threshold;
                zctx->policy_window       = conf->breaker_window;
                zctx->policy_open         = conf->breaker_open;
                zctx->policy_retry_after  = eff_retry_after;
            } else if (zctx->policy_threshold != conf->breaker_threshold
                       || zctx->policy_window != conf->breaker_window
                       || zctx->policy_open != conf->breaker_open
                       || zctx->policy_retry_after != eff_retry_after)
            {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                    "cache_turbo circuit breaker: this location's effective "
                    "policy (threshold=%ui window=%T open=%T "
                    "retry_after=%T) diverges from another location sharing "
                    "the same cache_turbo_zone (threshold=%ui window=%T "
                    "open=%T retry_after=%T); breaker STATE is per-zone but "
                    "policy is per-location, so whichever location last "
                    "calls the state machine decides effective reopen "
                    "timing for the whole zone",
                    conf->breaker_threshold, conf->breaker_window,
                    conf->breaker_open, eff_retry_after,
                    zctx->policy_threshold, zctx->policy_window,
                    zctx->policy_open, zctx->policy_retry_after);
            }
        }
    }
}

/* Group 7: default cache key compile, tag inherit, require_header. Needs
 * conf->enable (Group 1) and conf->key (Group 5) already resolved. */
static char *
ngx_http_cache_turbo_merge_key_and_tag(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *conf,
    ngx_http_cache_turbo_loc_conf_t *prev)
{
    /* Default cache key (no explicit cache_turbo_key) for an enabled location:
     * $host$uri$cache_turbo_normalized_args — tracking params stripped + args
     * sorted out of the box. Compiled lazily here; the normalized_args variable
     * was registered in preconfiguration. For a raw, no-strip/sort key (e.g. an
     * origin that does not reliably mark per-user responses private), set it
     * explicitly: cache_turbo_key $scheme$host$request_uri; */
    if (conf->key == NULL && conf->enable) {
        ngx_str_t                         defkey =
            ngx_string("$host$uri$cache_turbo_normalized_args");
        ngx_http_compile_complex_value_t  ccv;

        conf->key = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (conf->key == NULL) {
            return NGX_CONF_ERROR;
        }
        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
        ccv.cf = cf;
        ccv.value = &defkey;
        ccv.complex_value = conf->key;
        if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    if (conf->tag == NULL) {
        conf->tag = prev->tag;
    }

    ngx_conf_merge_str_value(conf->require_header, prev->require_header,
                             "");

    return NGX_CONF_OK;
}

/* Group 8: L2 backend selection + connection knobs, identity/credential
 * inherit-or-replace, SSL context build, vtable resolution, and the
 * tag-without-Redis warning. Must run after Group 5 (shm_zone/key) and
 * before nothing else depends on it within merge_loc_conf. */
static char *
ngx_http_cache_turbo_merge_l2_backend(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *conf,
    ngx_http_cache_turbo_loc_conf_t *prev)
{
    /* L2 backend selection + connection knobs. These are behavioural tunables,
     * not backend identity, so they inherit independently as before. */
    ngx_conf_merge_value(conf->redis_enable, prev->redis_enable, 0);
    ngx_conf_merge_value(conf->memcached, prev->memcached, 0);
    ngx_conf_merge_msec_value(conf->redis_timeout, prev->redis_timeout, 250);

    /* S231-L2-SCANTIME: default 30s wall-clock ceiling on one all-purge SCAN
     * walk. Generous for any real keyspace (SCAN_MAX_PAGES already tolerates
     * ~268M keys at COUNT 256), but far below the ~72h an adversarial or
     * pathological L2 could otherwise park a purge request for by returning a
     * non-zero cursor just under redis_timeout on every page. 0 disables it
     * (page-cap-only, pre-S231-L2-SCANTIME behaviour). */
    ngx_conf_merge_msec_value(conf->redis_scan_deadline,
                              prev->redis_scan_deadline, 30000);
    /* S231: safe non-zero small default. 0 = disabled (never back off).
     * 2s comfortably outlasts a single connect() timeout/RST so a worker
     * doesn't immediately re-hammer a peer that just refused, but is short
     * enough that a recovered backend is back in rotation within a couple of
     * requests worth of wall clock. */
    ngx_conf_merge_msec_value(conf->redis_connect_backoff,
                              prev->redis_connect_backoff, 2000);
    ngx_conf_merge_value(conf->redis_keepalive, prev->redis_keepalive, 0);
    ngx_conf_merge_msec_value(conf->redis_keepalive_timeout,
                              prev->redis_keepalive_timeout, 60000);
    ngx_conf_merge_value(conf->memcached_keepalive, prev->memcached_keepalive, 0);
    ngx_conf_merge_msec_value(conf->memcached_keepalive_timeout,
                              prev->memcached_keepalive_timeout, 60000);

    if (conf->redis_addr.sockaddr != NULL) {
        /* COR-6: this block ran its own cache_turbo_redis — a complete backend
         * in its own right (address set at parse). Treat its identity /
         * credential / db / TLS fields as a FULL REPLACEMENT of the parent's:
         * never inherit them field-by-field, or a child pointed at a different
         * server would silently reuse the parent's password, database, and CA.
         * Anything this directive left unset takes the built-in default. */
        if (conf->redis_prefix.data == NULL) {
            ngx_str_set(&conf->redis_prefix,
                        NGX_HTTP_CACHE_TURBO_REDIS_PREFIX);
        }
        /* nginx has no ngx_conf_init_str_value; self-merge applies the default
         * when unset without consulting the parent. */
        ngx_conf_merge_str_value(conf->redis_user, conf->redis_user, "");
        ngx_conf_merge_str_value(conf->redis_password, conf->redis_password, "");
        ngx_conf_init_value(conf->redis_db, 0);
        ngx_conf_init_value(conf->redis_tls, 0);
        ngx_conf_init_value(conf->redis_tls_verify, 1);
        ngx_conf_merge_str_value(conf->redis_tls_ca, conf->redis_tls_ca, "");
        ngx_conf_merge_str_value(conf->redis_tls_name, conf->redis_tls_name, "");
        /* redis_host was set from the DSN at parse; redis_ssl is built below,
         * post-merge, so it can never carry the parent's TLS context. */

    } else {
        /* No own backend: inherit the parent's entire profile (address + all
         * identity/credential/TLS fields + the already-built TLS context) so an
         * http/server-level backend applies to every nested location. */
        conf->redis_addr = prev->redis_addr;
        if (conf->redis_prefix.data == NULL) {
            if (prev->redis_prefix.data) {
                conf->redis_prefix = prev->redis_prefix;
            } else {
                ngx_str_set(&conf->redis_prefix,
                            NGX_HTTP_CACHE_TURBO_REDIS_PREFIX);
            }
        }
        ngx_conf_merge_str_value(conf->redis_user, prev->redis_user, "");
        ngx_conf_merge_str_value(conf->redis_password, prev->redis_password, "");
        ngx_conf_merge_value(conf->redis_db, prev->redis_db, 0);
        ngx_conf_merge_value(conf->redis_tls, prev->redis_tls, 0);
        ngx_conf_merge_value(conf->redis_tls_verify, prev->redis_tls_verify, 1);
        ngx_conf_merge_str_value(conf->redis_tls_ca, prev->redis_tls_ca, "");
        ngx_conf_merge_str_value(conf->redis_tls_name, prev->redis_tls_name, "");
        ngx_conf_merge_str_value(conf->redis_host, prev->redis_host, "");
#if (NGX_SSL)
        conf->redis_ssl = prev->redis_ssl;   /* reuse parent's built context */
#endif
    }

#if (NGX_SSL)
    /* COR-6: build the client TLS context HERE, after redis_tls / tls_verify /
     * tls_ca are fully resolved — not at directive-parse time, when a tls=on
     * backend that inherits its verify flag or CA would build the context from
     * unmerged (default) values. Own backends build a fresh context; inherited
     * backends already copied prev->redis_ssl above (guard skips the rebuild). */
    if (conf->redis_enable && conf->redis_tls == 1 && conf->redis_ssl == NULL) {
        if (ngx_http_cache_turbo_redis_build_ssl(cf, conf) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
    }
#else
    if (conf->redis_enable && conf->redis_tls == 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_redis: TLS (rediss:// / tls=on) requires nginx built "
            "with --with-http_ssl_module");
        return NGX_CONF_ERROR;
    }
#endif

    /* Resolve the backend vtables (v4-1). l1 is a stateless dispatch table, so
     * it is always wired (the zone is an argument, not driver state). backend is
     * the remote L2 driver, present only when cache_turbo_redis was configured;
     * call sites guard on it being non-NULL. */
    conf->l1 = &ngx_http_cache_turbo_shm_backend;
    conf->backend = conf->redis_enable
                        ? (conf->memcached
                               ? &ngx_http_cache_turbo_memcached_backend
                               : &ngx_http_cache_turbo_redis_backend)
                        : NULL;

    /* COR-0: the tag INDEX (purge-by-tag) lives only in a Redis L2 (the memcached
     * backend has no atomic tag set: tag_add == NULL). A cache_turbo_tag with no L2,
     * or with the memcached backend, cannot be purged by tag — warn at config time
     * rather than let the operator believe purge-by-tag will work. EXCEPTION:
     * cache_turbo_surrogate_key gives the tag list a SECOND, Redis-free consumer
     * (downstream Surrogate-Key emission for a fronting CDN), so the tag is NOT
     * inert then; only the local purge-by-tag index is unavailable, and that is a
     * deliberate, documented Redis-free mode — no warning. */
    if (conf->tag != NULL
        && !conf->surrogate_key
        && (conf->backend == NULL || conf->backend->tag_add == NULL))
    {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "cache_turbo_tag has no effect here: tag indexing requires a Redis "
            "L2 (cache_turbo_redis); it is unavailable with %s "
            "(cache_turbo_surrogate_key still emits the tags downstream)",
            conf->backend == NULL ? "no L2 backend" : "the memcached backend");
    }

    return NGX_CONF_OK;
}

/* Group 9: normalize_strip / bypass_uri / bypass_stale_uri / backend_prefix /
 * key_cookies / normalize_vary -- all plain UNSET-only inherits, independent
 * of everything above. */
static void
ngx_http_cache_turbo_merge_normalize(ngx_http_cache_turbo_loc_conf_t *conf,
    ngx_http_cache_turbo_loc_conf_t *prev)
{
    /* Key normalize: inherit the extra-pattern list. */
    if (conf->normalize_strip == NGX_CONF_UNSET_PTR) {
        conf->normalize_strip = prev->normalize_strip;
    }
    /* DIY bypass-URI and key-cookie lists: inherit UNSET-only, same as
     * normalize_strip (a location that sets its own fully replaces the parent's
     * — matching how the append happens within a level, not across). */
    if (conf->bypass_uri == NGX_CONF_UNSET_PTR) {
        conf->bypass_uri = prev->bypass_uri;
    }
    if (conf->bypass_stale_uri == NGX_CONF_UNSET_PTR) {
        conf->bypass_stale_uri = prev->bypass_stale_uri;
    }
    if (conf->backend_prefix == NGX_CONF_UNSET_PTR) {
        conf->backend_prefix = prev->backend_prefix;
    }
    if (conf->key_cookies == NGX_CONF_UNSET_PTR) {
        conf->key_cookies = prev->key_cookies;
    }
    /* Vary suffix bitmask: inherit UNSET-only; the variable handler reads UNSET
     * as 0 (off), so v3-1 keys are unchanged unless a directive opts in. */
    if (conf->normalize_vary == NGX_CONF_UNSET) {
        conf->normalize_vary = prev->normalize_vary;
    }
}

char *
ngx_http_cache_turbo_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_cache_turbo_loc_conf_t  *prev = parent;
    ngx_http_cache_turbo_loc_conf_t  *conf = child;

    ngx_http_cache_turbo_merge_basic(conf, prev);
    ngx_http_cache_turbo_merge_presets(conf, prev);
    ngx_http_cache_turbo_merge_breaker(conf, prev);
    ngx_http_cache_turbo_merge_cc_and_bypass(conf, prev);
    ngx_http_cache_turbo_merge_zone_and_lock(conf, prev);
    ngx_http_cache_turbo_merge_breaker_policy_warn(cf, conf);

    if (ngx_http_cache_turbo_merge_key_and_tag(cf, conf, prev) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_cache_turbo_merge_l2_backend(cf, conf, prev) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_http_cache_turbo_merge_normalize(conf, prev);

    return NGX_CONF_OK;
}
