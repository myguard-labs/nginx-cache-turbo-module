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
#include "ngx_http_cache_turbo_internal.h"

/* Log config error and return NGX_CONF_ERROR. Replaces the idiomatic
 * ngx_conf_log_error(...); return NGX_CONF_ERROR; pattern to reduce noise
 * at call sites. Defined here, above every use: a macro has no forward
 * declaration, so a definition placed later in the file is invisible to
 * the call sites above it.
 *
 * This does not interact with the NGX_HTTP_CACHE_TURBO_PARAM_NOMATCH
 * sentinel-aliasing hazard documented further down: the macro yields
 * NGX_CONF_ERROR itself, so a rejecting handler returns exactly what it
 * returned before. */
#define NGX_HTTP_CACHE_TURBO_CONF_ERROR(level, cf, err, ...) \
    ((void) (ngx_conf_log_error(level, cf, err, __VA_ARGS__)), NGX_CONF_ERROR)

#if (NGX_SSL)
#include <ngx_event_openssl.h>

/* Forward decl: defined far below with the directive setters (MAINT-SPLIT
 * step H); merge_l2_backend_tls() above it in this file is its only caller. */
static char *ngx_http_cache_turbo_redis_build_ssl(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *clcf);
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
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo: empty prefix= is not allowed "
            "(an all-purge would match the whole L2 keyspace)");
    }

    for (i = 0; i < prefix->len; i++) {
        if (prefix->data[i] <= 0x20 || prefix->data[i] >= 0x7f) {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "%s: prefix= contains byte 0x%02Xd at offset %uz; the L2 key "
                "must be printable and free of spaces and control characters",
                name, prefix->data[i], i);
        }
    }

    if (prefix->len + NGX_HTTP_CACHE_TURBO_L2_KEY_SUFFIX_MAX
        > NGX_HTTP_CACHE_TURBO_L2_KEY_MAX)
    {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "%s: prefix= is %uz bytes; at most %uz are usable, because the "
            "module appends up to %d bytes of key and an L2 key may not "
            "exceed %d bytes",
            name, prefix->len,
            (size_t) (NGX_HTTP_CACHE_TURBO_L2_KEY_MAX
                      - NGX_HTTP_CACHE_TURBO_L2_KEY_SUFFIX_MAX),
            NGX_HTTP_CACHE_TURBO_L2_KEY_SUFFIX_MAX,
            NGX_HTTP_CACHE_TURBO_L2_KEY_MAX);
    }

    return NGX_CONF_OK;
}


/* MAINT-C1b: ngx_http_cache_turbo_redis_conf decomposition. ⚠ ORDER- AND
 * PRECEDENCE-SENSITIVE: each helper below runs in the exact same relative
 * order the original single function ran its statements in (DSN split ->
 * host:port resolve -> trailing-param loop, each param literal tested in
 * the same sequence, each error string unchanged verbatim) — a config-time
 * error message is part of the directive's contract, and a DSN userinfo/db
 * would be silently overridden by a differently-ordered trailing param.
 * Do not reorder the calls in ngx_http_cache_turbo_redis_conf().
 */

/* Split the DSN into scheme (-> redis_tls), userinfo (-> redis_user/password),
 * db (-> redis_db) and the bare host:port left in *hostport for the resolver.
 * Bare "host:port" (no scheme) is legacy syntax: hostport is left == *arg1
 * and every optional piece stays untouched. */
static char *
ngx_http_cache_turbo_redis_split_dsn(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_str_t *arg1,
    ngx_str_t *hostport)
{
    u_char  *rest, *last, *at, *slash, *colon;

    *hostport = *arg1;

    if (arg1->len > sizeof("rediss://") - 1
        && ngx_strncasecmp(arg1->data, (u_char *) "rediss://",
                           sizeof("rediss://") - 1) == 0)
    {
        clcf->redis_tls = 1;
        rest = arg1->data + sizeof("rediss://") - 1;

    } else if (arg1->len > sizeof("redis://") - 1
               && ngx_strncasecmp(arg1->data, (u_char *) "redis://",
                                  sizeof("redis://") - 1) == 0)
    {
        rest = arg1->data + sizeof("redis://") - 1;

    } else {
        rest = NULL;        /* bare host:port */
    }

    if (rest == NULL) {
        return NGX_CONF_OK;
    }

    last = arg1->data + arg1->len;

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
            clcf->redis_db = ngx_atoi(slash + 1, last - (slash + 1));
            if (clcf->redis_db == NGX_ERROR || clcf->redis_db < 0) {
                return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_redis: bad db in DSN");
            }
            if (clcf->redis_db > NGX_HTTP_CACHE_TURBO_REDIS_DB_MAX) {
                return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_redis: db in DSN exceeds the maximum %d",
                    NGX_HTTP_CACHE_TURBO_REDIS_DB_MAX);
            }
        }
        hostport->data = rest;
        hostport->len = slash - rest;
    } else {
        hostport->data = rest;
        hostport->len = last - rest;
    }

    return NGX_CONF_OK;
}

/* Resolve the split-out host:port and set redis_addr/redis_host. */
static char *
ngx_http_cache_turbo_redis_resolve(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_str_t *hostport)
{
    ngx_url_t  u;

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = *hostport;
    u.default_port = 6379;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "cache_turbo_redis: %s in \"%V\"", u.err, &u.url);
        }
        return NGX_CONF_ERROR;
    }
    if (u.naddrs == 0) {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                           "cache_turbo_redis: no addresses for \"%V\"", &u.url);
    }

    clcf->redis_addr = u.addrs[0];
    clcf->redis_host = u.host;        /* default SNI / verify name */

    return NGX_CONF_OK;
}

/* Sentinel: split_dsn/pool/tls param handlers return this to say "the
 * parameter name did not match any literal I test" so the caller can try
 * the next handler in the chain, preserving the original single-loop's
 * left-to-right literal match order across the split. */
/* ⚠ Must NOT alias NGX_CONF_ERROR, which nginx defines as (void *) -1: a
 * handler that REJECTS a parameter it did own (bad timeout=, prefix=,
 * keepalive=, db=) returns NGX_CONF_ERROR, and a (char *) -1 sentinel would
 * make the dispatcher read that rejection as "no match" and fall through to
 * the next handler, replacing the specific diagnostic with the generic
 * "invalid parameter". A unique object address collides with nothing. */
static char  ngx_http_cache_turbo_param_nomatch_obj;
#define NGX_HTTP_CACHE_TURBO_PARAM_NOMATCH \
    (&ngx_http_cache_turbo_param_nomatch_obj)

/* First third of the trailing "name=value" parameters, in the same order the
 * original loop tested them: prefix, timeout, keepalive. */
static char *
ngx_http_cache_turbo_redis_param_pool_a(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_str_t *value)
{
    ngx_str_t  s;
    ngx_int_t  t;

    if (ngx_strncmp(value->data, "prefix=", 7) == 0) {
        clcf->redis_prefix.data = value->data + 7;
        clcf->redis_prefix.len = value->len - 7;
        if (ngx_http_cache_turbo_check_l2_prefix(cf, &clcf->redis_prefix,
                                                 "cache_turbo_redis")
            != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }

    } else if (ngx_strncmp(value->data, "timeout=", 8) == 0) {
        s.data = value->data + 8;
        s.len = value->len - 8;
        t = ngx_parse_time(&s, 0);   /* milliseconds */
        if (t == NGX_ERROR) {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                               "cache_turbo_redis: bad timeout \"%V\"", &s);
        }
        if (t == 0) {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                               "cache_turbo_redis: timeout must be > 0");
        }
        clcf->redis_timeout = (ngx_msec_t) t;

    } else if (ngx_strncmp(value->data, "keepalive=", 10) == 0) {
        clcf->redis_keepalive = ngx_atoi(value->data + 10, value->len - 10);
        if (clcf->redis_keepalive == NGX_ERROR || clcf->redis_keepalive < 0) {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_redis: bad keepalive \"%V\"", value);
        }
        /* STAB-5: bound N so the pool's N*sizeof(item) alloc can't overflow. */
        if (clcf->redis_keepalive > NGX_HTTP_CACHE_TURBO_KEEPALIVE_MAX) {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_redis: keepalive %V exceeds the maximum %d",
                value, NGX_HTTP_CACHE_TURBO_KEEPALIVE_MAX);
        }

    } else {
        return NGX_HTTP_CACHE_TURBO_PARAM_NOMATCH;
    }

    return NGX_CONF_OK;
}

/* Second third: keepalive_timeout, connect_backoff, password, user, db —
 * tried only after param_pool_a reports no match. */
static char *
ngx_http_cache_turbo_redis_param_pool_b(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_str_t *value)
{
    ngx_str_t  s;
    ngx_int_t  t;

    if (ngx_strncmp(value->data, "keepalive_timeout=", 18) == 0) {
        s.data = value->data + 18;
        s.len = value->len - 18;
        t = ngx_parse_time(&s, 0);   /* milliseconds */
        if (t == NGX_ERROR) {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_redis: bad keepalive_timeout \"%V\"", &s);
        }
        clcf->redis_keepalive_timeout = (ngx_msec_t) t;

    } else if (ngx_strncmp(value->data, "connect_backoff=", 16) == 0) {
        s.data = value->data + 16;
        s.len = value->len - 16;
        t = ngx_parse_time(&s, 0);   /* milliseconds; 0 = disabled */
        if (t == NGX_ERROR) {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_redis: bad connect_backoff \"%V\"", &s);
        }
        clcf->redis_connect_backoff = (ngx_msec_t) t;

    } else if (ngx_strncmp(value->data, "password=", 9) == 0) {
        clcf->redis_password.data = value->data + 9;
        clcf->redis_password.len = value->len - 9;

    } else if (ngx_strncmp(value->data, "user=", 5) == 0) {
        clcf->redis_user.data = value->data + 5;
        clcf->redis_user.len = value->len - 5;

    } else if (ngx_strncmp(value->data, "db=", 3) == 0) {
        clcf->redis_db = ngx_atoi(value->data + 3, value->len - 3);
        if (clcf->redis_db == NGX_ERROR || clcf->redis_db < 0) {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                               "cache_turbo_redis: bad db \"%V\"", value);
        }
        if (clcf->redis_db > NGX_HTTP_CACHE_TURBO_REDIS_DB_MAX) {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                               "cache_turbo_redis: db \"%V\" exceeds the "
                               "maximum %d", value,
                               NGX_HTTP_CACHE_TURBO_REDIS_DB_MAX);
        }

    } else {
        return NGX_HTTP_CACHE_TURBO_PARAM_NOMATCH;
    }

    return NGX_CONF_OK;
}

/* First two-thirds: try param_pool_a then param_pool_b, in that order. */
static char *
ngx_http_cache_turbo_redis_param_pool(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_str_t *value)
{
    char  *rc;

    rc = ngx_http_cache_turbo_redis_param_pool_a(cf, clcf, value);
    if (rc != NGX_HTTP_CACHE_TURBO_PARAM_NOMATCH) {
        return rc;
    }

    return ngx_http_cache_turbo_redis_param_pool_b(cf, clcf, value);
}

/* Second half: tls, tls_verify, tls_ca, tls_name, scan_deadline — tried only
 * after the pool-param handler reports no match, so the combined order is
 * identical to the original single if/else-if chain. */
static char *
ngx_http_cache_turbo_redis_param_tls(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_str_t *value)
{
    ngx_str_t  s;
    ngx_int_t  t;

    if (ngx_strncmp(value->data, "tls=", 4) == 0) {
        s.data = value->data + 4;
        s.len = value->len - 4;
        if (s.len == 2 && ngx_strncmp(s.data, "on", 2) == 0) {
            clcf->redis_tls = 1;
        } else if (s.len == 3 && ngx_strncmp(s.data, "off", 3) == 0) {
            clcf->redis_tls = 0;
        } else {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                               "cache_turbo_redis: tls must be on|off");
        }

    } else if (ngx_strncmp(value->data, "tls_verify=", 11) == 0) {
        s.data = value->data + 11;
        s.len = value->len - 11;
        if (s.len == 2 && ngx_strncmp(s.data, "on", 2) == 0) {
            clcf->redis_tls_verify = 1;
        } else if (s.len == 3 && ngx_strncmp(s.data, "off", 3) == 0) {
            clcf->redis_tls_verify = 0;
        } else {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                               "cache_turbo_redis: tls_verify must be on|off");
        }

    } else if (ngx_strncmp(value->data, "tls_ca=", 7) == 0) {
        clcf->redis_tls_ca.data = value->data + 7;
        clcf->redis_tls_ca.len = value->len - 7;

    } else if (ngx_strncmp(value->data, "tls_name=", 9) == 0) {
        clcf->redis_tls_name.data = value->data + 9;
        clcf->redis_tls_name.len = value->len - 9;

    } else if (ngx_strncmp(value->data, "scan_deadline=", 14) == 0) {
        /* S231-L2-SCANTIME: wall-clock ceiling on one all-purge SCAN walk,
         * on top of the fixed SCAN_MAX_PAGES page cap. "0" disables it
         * (page-cap-only, legacy behaviour) rather than being rejected
         * like a zero connect timeout: the page cap alone is a legitimate,
         * if generous, non-termination guard. */
        s.data = value->data + 14;
        s.len = value->len - 14;
        t = ngx_parse_time(&s, 0);   /* milliseconds */
        if (t == NGX_ERROR) {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_redis: bad scan_deadline \"%V\"", &s);
        }
        clcf->redis_scan_deadline = (ngx_msec_t) t;

    } else {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                           "cache_turbo_redis: invalid parameter \"%V\"",
                           value);
    }

    return NGX_CONF_OK;
}

/* One trailing "name=value" parameter: try the pool group, then the TLS
 * group, in that order — identical left-to-right precedence to the original
 * single if/else-if chain. */
static char *
ngx_http_cache_turbo_redis_param(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_str_t *value)
{
    char  *rc;

    rc = ngx_http_cache_turbo_redis_param_pool(cf, clcf, value);
    if (rc != NGX_HTTP_CACHE_TURBO_PARAM_NOMATCH) {
        return rc;
    }

    return ngx_http_cache_turbo_redis_param_tls(cf, clcf, value);
}

/*
 * "cache_turbo_redis <dsn|host:port> [prefix=] [timeout=] [password=] [user=]
 *  [db=] [keepalive=] [keepalive_timeout=] [connect_backoff=] [tls=on|off]
 *  [tls_verify=on|off] [tls_ca=<file>] [tls_name=<host>] [scan_deadline=];"
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

    ngx_str_t   *value, hostport, arg1;
    ngx_uint_t   i;
    char        *rc;

    value = cf->args->elts;
    arg1 = value[1];

    if (clcf->memcached == 1) {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_redis: an L2 backend (cache_turbo_memcached) is already "
            "configured in this block; the two are mutually exclusive");
    }

    /* --- 1. split the DSN (scheme / userinfo / host:port / db) ------------- */
    rc = ngx_http_cache_turbo_redis_split_dsn(cf, clcf, &arg1, &hostport);
    if (rc != NGX_CONF_OK) {
        return rc;
    }

    /* --- 2. resolve the host:port ----------------------------------------- */
    rc = ngx_http_cache_turbo_redis_resolve(cf, clcf, &hostport);
    if (rc != NGX_CONF_OK) {
        return rc;
    }

    /* --- 3. trailing params override the DSN ------------------------------ */
    for (i = 2; i < cf->args->nelts; i++) {
        rc = ngx_http_cache_turbo_redis_param(cf, clcf, &value[i]);
        if (rc != NGX_CONF_OK) {
            return rc;
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


/* MAINT-C1b: ngx_http_cache_turbo_memcached_conf decomposition. Same
 * ordering-sensitivity rule as the redis_conf split above: resolve ->
 * trailing-param loop, param literals tested in the same sequence, error
 * strings unchanged verbatim. Do not reorder the calls below. */

/* One trailing "name=value" parameter. */
static char *
ngx_http_cache_turbo_memcached_param(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_str_t *value)
{
    ngx_str_t  s;
    ngx_int_t  t;

    if (ngx_strncmp(value->data, "prefix=", 7) == 0) {
        clcf->redis_prefix.data = value->data + 7;
        clcf->redis_prefix.len = value->len - 7;
        if (ngx_http_cache_turbo_check_l2_prefix(cf, &clcf->redis_prefix,
                                                 "cache_turbo_memcached")
            != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }

    } else if (ngx_strncmp(value->data, "timeout=", 8) == 0) {
        s.data = value->data + 8;
        s.len = value->len - 8;
        t = ngx_parse_time(&s, 0);   /* milliseconds */
        if (t == NGX_ERROR) {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_memcached: bad timeout \"%V\"", &s);
        }
        if (t == 0) {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_memcached: timeout must be > 0");
        }
        clcf->redis_timeout = (ngx_msec_t) t;

    } else if (ngx_strncmp(value->data, "keepalive=", 10) == 0) {
        s.data = value->data + 10;
        s.len = value->len - 10;
        clcf->memcached_keepalive = ngx_atoi(s.data, s.len);
        if (clcf->memcached_keepalive == NGX_ERROR
            || clcf->memcached_keepalive < 0)
        {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_memcached: bad keepalive \"%V\"", &s);
        }
        if (clcf->memcached_keepalive > NGX_HTTP_CACHE_TURBO_KEEPALIVE_MAX) {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_memcached: keepalive must be <= %d",
                NGX_HTTP_CACHE_TURBO_KEEPALIVE_MAX);
        }

    } else if (ngx_strncmp(value->data, "keepalive_timeout=", 18) == 0) {
        s.data = value->data + 18;
        s.len = value->len - 18;
        t = ngx_parse_time(&s, 0);
        if (t == NGX_ERROR) {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_memcached: bad keepalive_timeout \"%V\"", &s);
        }
        clcf->memcached_keepalive_timeout = (ngx_msec_t) t;

    } else if (ngx_strncmp(value->data, "connect_backoff=", 16) == 0) {
        s.data = value->data + 16;
        s.len = value->len - 16;
        t = ngx_parse_time(&s, 0);   /* milliseconds; 0 = disabled */
        if (t == NGX_ERROR) {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_memcached: bad connect_backoff \"%V\"", &s);
        }
        clcf->redis_connect_backoff = (ngx_msec_t) t;

    } else {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_memcached: invalid parameter \"%V\"", value);
    }

    return NGX_CONF_OK;
}

/*
 * "cache_turbo_memcached <host:port> [prefix=] [timeout=] [keepalive=]
 *  [keepalive_timeout=] [connect_backoff=];"  (v13)
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

    ngx_str_t   *value;
    ngx_url_t    u;
    ngx_uint_t   i;
    char        *rc;

    value = cf->args->elts;

    if (clcf->redis_enable == 1 && clcf->memcached != 1) {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_memcached: an L2 backend (cache_turbo_redis) is already "
            "configured in this block; the two are mutually exclusive");
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
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_memcached: no addresses for \"%V\"", &u.url);
    }

    clcf->redis_addr = u.addrs[0];

    for (i = 2; i < cf->args->nelts; i++) {
        rc = ngx_http_cache_turbo_memcached_param(cf, clcf, &value[i]);
        if (rc != NGX_CONF_OK) {
            return rc;
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

    /* S8/P3-1: deliberately NOT band-resolved -- no preset enables or disables
     * scan resistance, it is a plain per-location default. Plain inherit, then
     * fall back to ON at the standard protected_pct (80) when nothing in the
     * chain set it explicitly. An explicit `off` stores 0 (not UNSET), so it
     * correctly overrides an inherited `on` rather than re-inheriting it here.
     *
     * P3-1 flipped this from 0 (OFF) to PROTECTED_PCT_DEFAULT (80, ON):
     * scanbench.sh measured flat LRU at 0.0% hot-set survival across a
     * crawler/sitemap/scanner scan vs 82.0% with segmented LRU at the SAME 80%
     * cap -- a stock install with the old default had zero scan resistance and
     * any crawl flushed the hot set. 80 is not a new number invented for this
     * flip: it is the existing PROTECTED_PCT_DEFAULT the `on` directive itself
     * has always used when protected_pct is omitted, so "on by default" and
     * "on explicitly with no tuning" are now the same effective config. See
     * README's Upgrading section for the eviction-behaviour-changes migration
     * note and how to restore the pre-P3-1 flat LRU with an explicit
     * `cache_turbo_scan_resistant off`. */
    if (conf->scan_resistant_pct == (ngx_uint_t) NGX_CONF_UNSET) {
        conf->scan_resistant_pct = prev->scan_resistant_pct;
    }
    if (conf->scan_resistant_pct == (ngx_uint_t) NGX_CONF_UNSET) {
        conf->scan_resistant_pct = NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_DEFAULT;
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
    ngx_conf_merge_value(conf->test_scan_page_hold_ms,
                         prev->test_scan_page_hold_ms, 0);
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

    /* P3-6: miss_count window resets (seconds). 0 = OFF (default, v15
     * behavior: counter persists until LRU eviction). 1..86400 = enabled,
     * reset miss_count when now - last_access > window. */
    ngx_conf_merge_sec_value(conf->min_uses_window, prev->min_uses_window, 0);

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

/* Merge L2 connection knobs: redis_enable, memcached, timeouts, keepalive.
 * CCN 1: pure linear merge sequence. */
static void
ngx_http_cache_turbo_merge_l2_connknobs(
    ngx_http_cache_turbo_loc_conf_t *conf,
    ngx_http_cache_turbo_loc_conf_t *prev)
{
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
}


/* Merge Redis address and identity fields. Own backend (redis_addr set) takes
 * prefix + credentials from self; inherited backend takes all from parent.
 * CCN 1: single if-else with no nested branches. */
static void
ngx_http_cache_turbo_merge_l2_backend_identity(
    ngx_http_cache_turbo_loc_conf_t *conf,
    ngx_http_cache_turbo_loc_conf_t *prev)
{
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
}


/* Build Redis TLS context after identity merge completes. Runs after
 * merge_l2_backend_identity so redis_tls/tls_verify/tls_ca are resolved.
 * CCN 2: check NGX_SSL guard, check redis_enable/redis_tls/redis_ssl conditions. */
static char *
ngx_http_cache_turbo_merge_l2_backend_tls(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *conf)
{
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
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_redis: TLS (rediss:// / tls=on) requires nginx built "
            "with --with-http_ssl_module");
    }
#endif

    return NGX_CONF_OK;
}


/* Resolve backend vtables: l1 (always set) and backend (conditional on
 * redis_enable + memcached). CCN 1: single assignment sequence. */
static void
ngx_http_cache_turbo_merge_l2_backend_vtables(
    ngx_http_cache_turbo_loc_conf_t *conf)
{
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
}


/* Warn if cache_turbo_tag is set but the L2 backend cannot index tags.
 * Runs after merge_l2_backend_vtables so conf->backend is resolved.
 * CCN 2: check tag != NULL, check surrogate_key, check backend availability. */
static void
ngx_http_cache_turbo_check_l2_tag_usage(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *conf)
{
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
}


/* Group 8: L2 backend selection + connection knobs, identity/credential
 * inherit-or-replace, SSL context build, vtable resolution, and the
 * tag-without-Redis warning. Must run after Group 5 (shm_zone/key) and
 * before nothing else depends on it within merge_loc_conf.
 *
 * Decomposed into ordered helpers: connknobs → identity → tls → vtables → tag.
 * Ordering is critical (tls runs after identity, vtables before tag check). */
static char *
ngx_http_cache_turbo_merge_l2_backend(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *conf,
    ngx_http_cache_turbo_loc_conf_t *prev)
{
    ngx_http_cache_turbo_merge_l2_connknobs(conf, prev);
    ngx_http_cache_turbo_merge_l2_backend_identity(conf, prev);

    if (ngx_http_cache_turbo_merge_l2_backend_tls(cf, conf) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_http_cache_turbo_merge_l2_backend_vtables(conf);
    ngx_http_cache_turbo_check_l2_tag_usage(cf, conf);

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
    /* cache_turbo_vary_ignore (P3-3): inherit UNSET-only, same as
     * normalize_strip -- a location that sets its own list fully replaces the
     * parent's rather than appending to it. */
    if (conf->vary_ignore == NGX_CONF_UNSET_PTR) {
        conf->vary_ignore = prev->vary_ignore;
    }
    /* Vary suffix bitmask: inherit UNSET-only; the variable handler reads UNSET
     * as 0 (off), so v3-1 keys are unchanged unless a directive opts in. */
    if (conf->normalize_vary == NGX_CONF_UNSET) {
        conf->normalize_vary = prev->normalize_vary;
    }
}


/* P1-7: config-time warning for double-partitioned axes.
 *
 * If cache_turbo_auto_vary is on (the default) and cache_turbo_normalize_vary
 * enables a bucket for the SAME axis (encoding or device), the cache splits on
 * that axis TWICE -- once via the auto-detected Vary header (in vary_bits),
 * once via the normalized-args key suffix. This multiplies the slot count for
 * the same partitioning, wasting space with no benefit.
 *
 * Warn at config merge time, naming the doubled axis and suggesting to pick
 * one mechanism. The config still loads (a warning, not an error). */
static void
ngx_http_cache_turbo_warn_double_partition(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *conf)
{
    /* Only warn if caching is enabled at this location. */
    if (!conf->enable) {
        return;
    }

    /* auto_vary defaults to ON (1). Only warn if it is actually on. */
    if (!conf->auto_vary) {
        return;
    }

    /* No normalize_vary set (0), so no overlap. */
    if (conf->normalize_vary == 0 || conf->normalize_vary == NGX_CONF_UNSET) {
        return;
    }

    /* Check each axis that can be double-partitioned:
     * - VARY_ENCODING (0x1): auto_vary can set it from Accept-Encoding header,
     *   and normalize_vary can set it from "encoding" token.
     * - VARY_DEVICE (0x2): auto_vary can set it from User-Agent header,
     *   and normalize_vary can set it from "device" token. */

    if (conf->normalize_vary & NGX_HTTP_CACHE_TURBO_VARY_ENCODING) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "cache_turbo_auto_vary is on (default) and cache_turbo_normalize_vary "
            "includes 'encoding': the 'encoding' axis is partitioned TWICE "
            "(once by auto-detected Vary, once by the normalized-args suffix), "
            "multiplying slot count for no benefit. Pick one: remove 'encoding' "
            "from cache_turbo_normalize_vary, or set cache_turbo_auto_vary off");
    }

    if (conf->normalize_vary & NGX_HTTP_CACHE_TURBO_VARY_DEVICE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "cache_turbo_auto_vary is on (default) and cache_turbo_normalize_vary "
            "includes 'device': the 'device' axis is partitioned TWICE "
            "(once by auto-detected Vary, once by the normalized-args suffix), "
            "multiplying slot count for no benefit. Pick one: remove 'device' "
            "from cache_turbo_normalize_vary, or set cache_turbo_auto_vary off");
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
    ngx_http_cache_turbo_warn_double_partition(cf, conf);

    return NGX_CONF_OK;
}


/* ------------------------------------------------------------------ */
/* Directive setters + conf lifecycle tail moved from
 * ngx_http_cache_turbo_module.c (MAINT-SPLIT step H, final step of the
 * module.c split). ngx_http_cache_turbo_commands[], ngx_http_module_t,
 * ngx_module_t, ngx_http_cache_turbo_create_loc_conf() and
 * ngx_http_cache_turbo_init() stay in module.c: they, and the phase-
 * handler/module registration ngx_http_cache_turbo_init() performs, are
 * conventionally kept with the module definition. All setters below are
 * non-static: ngx_http_cache_turbo_commands[] in module.c still
 * references them as function pointers, so they are declared in
 * ngx_http_cache_turbo_internal.h. */

char *
ngx_http_cache_turbo_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                       *p;
    ssize_t                       size;
    ngx_str_t                    *value, name, s;
    ngx_shm_zone_t               *shm_zone;
    ngx_http_cache_turbo_zone_t  *ctx;

    value = cf->args->elts;

    /* arg 1: name=NNN, arg 2: size */
    name.len = 0;
    name.data = NULL;

    p = (u_char *) ngx_strchr(value[1].data, '=');
    if (p && ngx_strncmp(value[1].data, "name=", 5) == 0) {
        name.data = value[1].data + 5;
        name.len = value[1].len - 5;
    } else {
        name = value[1];
    }

    if (name.len == 0) {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                           "invalid cache_turbo_zone name");
    }

    s = value[2];
    size = ngx_parse_size(&s);
    if (size == NGX_ERROR || size < (ssize_t) (8 * ngx_pagesize)) {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                           "invalid cache_turbo_zone size \"%V\"", &s);
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_cache_turbo_zone_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, size,
                                     &ngx_http_cache_turbo_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                           "duplicate cache_turbo_zone \"%V\"", &name);
    }

    shm_zone->init = ngx_http_cache_turbo_shm_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


char *
ngx_http_cache_turbo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t       *value;
    ngx_shm_zone_t  *shm_zone;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        clcf->enable = 0;
        return NGX_CONF_OK;
    }

    /* "cache_turbo <zone>;" enables and binds the zone */
    shm_zone = ngx_shared_memory_add(cf, &value[1], 0,
                                     &ngx_http_cache_turbo_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    clcf->enable = 1;
    clcf->shm_zone = shm_zone;

    /*
     * "cache_turbo <zone> auto;" used to be shorthand for the `generic` preset.
     * Both are GONE — see the cache_turbo_backend comment for why. The directive
     * now takes the zone and nothing else.
     *
     * The command is deliberately still NGX_CONF_TAKE12 rather than TAKE1: that
     * lets us catch the dead token here and name its replacement, instead of
     * letting nginx emit a bare "invalid number of arguments" at someone whose
     * config worked yesterday. It is a hard config error either way — nginx will
     * not start — which is the point. Silently ignoring `auto` would leave a
     * WordPress site with NO preset active and quietly start caching /wp-admin/.
     */
    if (cf->args->nelts == 3) {
        if (ngx_strcmp(value[2].data, "auto") == 0) {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "\"cache_turbo %V auto\" is no longer supported: the `auto` / "
                "`generic` preset union has been removed because it was not a "
                "safe default (it never covered every backend, and `joomla` in "
                "it ships no cookie rule at all). Name the backends you actually "
                "run, e.g. \"cache_turbo %V; cache_turbo_backend wordpress;\"",
                &value[1], &value[1]);
        }

        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "invalid cache_turbo mode \"%V\" (cache_turbo takes a zone name "
            "only; use cache_turbo_backend to enable a CMS preset)",
            &value[2]);
    }

    return NGX_CONF_OK;
}


/*
 * cache_turbo_backend <name>... — compose one or more CMS auto-classify presets.
 * EVERY preset is opt-in: you name the backends you actually run. All backends
 * stack, and spaces and '|' are interchangeable separators:
 *
 *     cache_turbo_backend wordpress woocommerce;
 *     cache_turbo_backend wordpress|woocommerce;
 *     cache_turbo_backend wordpress | woocommerce;
 *
 * `none` is the odd one out: it means "no preset in this location" and overrides
 * a preset inherited from the server block (see BACKEND_NONE in the header). It
 * is exclusive — combining it with a real backend is a config error.
 *
 * Sets bits in clcf->backend_presets consumed by ngx_http_cache_turbo_auto_skip.
 *
 * There is deliberately no `generic` / `auto` union any more. It used to mean
 * wordpress+woocommerce+joomla, and it was never a safe default:
 *
 *   - it never covered every backend (after xenforo/discourse/phpbb/drupal/
 *     mediawiki it named 3 of 9), so `auto` on a Drupal site silently enabled
 *     no Drupal rules at all;
 *   - `woocommerce` inside it leaves /wp-admin/ cacheable unless it is stacked
 *     with `wordpress` — a union whose members you must know how to combine is
 *     not a default;
 *   - `joomla` inside it ships NO cookie rule, so `auto` on a Joomla site LOOKED
 *     like it protected logged-in users and did not.
 *
 * A default that is only correct if you already know which parts of it are wrong
 * is a footgun with a friendly name. Both spellings are now rejected at config
 * parse with a message naming the replacement — a hard error, never a silent
 * no-op, because silently enabling nothing would start caching /wp-admin/ on an
 * existing WordPress config.
 */
/* Backend name -> preset bit. One row per preset; adding a backend is a row here
 * and a row in the registry, nothing else. Order is the order shown in the
 * "unknown backend" diagnostic.
 *
 * `implies` names other preset bits that this backend REQUIRES to be safe — an
 * add-on that layers dynamic surfaces on top of another CMS without repeating
 * that CMS's own login/admin rules. `woocommerce` is the type case: its rows add
 * only cart/checkout/account cookies and URIs and ship NO /wp-admin/ rule and NO
 * wordpress_logged_in_ cookie rule, because it IS WordPress and those belong to
 * the wordpress preset. `cache_turbo_backend woocommerce;` used alone therefore
 * leaves /wp-admin/ cacheable and — on a store whose account page is at a
 * translated slug the woo uris[] cannot know — caches a logged-in customer's
 * account page (no woo cookie on an empty cart, no wordpress preset to catch the
 * login cookie). The implication is resolved to a fixpoint at parse time
 * (ngx_http_cache_turbo_backend), so naming the add-on silently enables the base
 * too; auto_skip then fires the base's rules unchanged. 0 = no implication. */
static const struct {
    const char  *name;
    ngx_uint_t   bit;
    ngx_uint_t   implies;
} ngx_http_cache_turbo_backend_names[] = {
    { "wordpress",   NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS,   0 },
    { "woocommerce", NGX_HTTP_CACHE_TURBO_BACKEND_WOOCOMMERCE,
      NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS },
    { "joomla",      NGX_HTTP_CACHE_TURBO_BACKEND_JOOMLA,      0 },
    { "xenforo",     NGX_HTTP_CACHE_TURBO_BACKEND_XENFORO,     0 },
    { "discourse",   NGX_HTTP_CACHE_TURBO_BACKEND_DISCOURSE,   0 },
    { "phpbb",       NGX_HTTP_CACHE_TURBO_BACKEND_PHPBB,       0 },
    { "drupal",      NGX_HTTP_CACHE_TURBO_BACKEND_DRUPAL,      0 },
    { "mediawiki",   NGX_HTTP_CACHE_TURBO_BACKEND_MEDIAWIKI,   0 },
    { "magento",     NGX_HTTP_CACHE_TURBO_BACKEND_MAGENTO,     0 },
    { "ghost",       NGX_HTTP_CACHE_TURBO_BACKEND_GHOST,       0 },
    { "wagtail",     NGX_HTTP_CACHE_TURBO_BACKEND_WAGTAIL,     0 },
    { "kirby",       NGX_HTTP_CACHE_TURBO_BACKEND_KIRBY,       0 },
    { "shopware6",   NGX_HTTP_CACHE_TURBO_BACKEND_SHOPWARE6,   0 },
    { "typo3",       NGX_HTTP_CACHE_TURBO_BACKEND_TYPO3,       0 },
    { "invision",    NGX_HTTP_CACHE_TURBO_BACKEND_INVISION,    0 },
    { "smf",         NGX_HTTP_CACHE_TURBO_BACKEND_SMF,         0 },
    { "vanilla",     NGX_HTTP_CACHE_TURBO_BACKEND_VANILLA,     0 },
    { "punbb",       NGX_HTTP_CACHE_TURBO_BACKEND_PUNBB,       0 },
    { "phorum",      NGX_HTTP_CACHE_TURBO_BACKEND_PHORUM,      0 },
    { "yabb",        NGX_HTTP_CACHE_TURBO_BACKEND_YABB,        0 },
    { "mybb",        NGX_HTTP_CACHE_TURBO_BACKEND_MYBB,        0 },
    { "vbulletin",   NGX_HTTP_CACHE_TURBO_BACKEND_VBULLETIN,   0 },
    { "textpattern", NGX_HTTP_CACHE_TURBO_BACKEND_TEXTPATTERN, 0 },
    { "bludit",      NGX_HTTP_CACHE_TURBO_BACKEND_BLUDIT,      0 },
    { "spip",        NGX_HTTP_CACHE_TURBO_BACKEND_SPIP,        0 },
    { "bugzilla",    NGX_HTTP_CACHE_TURBO_BACKEND_BUGZILLA,    0 },
    { "mantisbt",    NGX_HTTP_CACHE_TURBO_BACKEND_MANTISBT,    0 },
    { "mantis",      NGX_HTTP_CACHE_TURBO_BACKEND_MANTISBT,    0 },
    { "plone",       NGX_HTTP_CACHE_TURBO_BACKEND_PLONE,       0 },
    { "umbraco",     NGX_HTTP_CACHE_TURBO_BACKEND_UMBRACO,     0 },
    { "dotclear",    NGX_HTTP_CACHE_TURBO_BACKEND_DOTCLEAR,    0 },
    { "wikijs",      NGX_HTTP_CACHE_TURBO_BACKEND_WIKIJS,      0 },
    { "redmine",     NGX_HTTP_CACHE_TURBO_BACKEND_REDMINE,     0 },
    { "flarum",      NGX_HTTP_CACHE_TURBO_BACKEND_FLARUM,      0 },
    { "opencart",    NGX_HTTP_CACHE_TURBO_BACKEND_OPENCART,    0 },
    { "classicpress", NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS,  0 },
    { "backdrop",    NGX_HTTP_CACHE_TURBO_BACKEND_DRUPAL,      0 },
    { "none",        NGX_HTTP_CACHE_TURBO_BACKEND_NONE,        0 },
    { NULL,          0,                                        0 }
};


/* Expand every implied backend bit into `mask` to a fixpoint. An add-on preset
 * (woocommerce -> wordpress) is unsafe without its base, so naming it must
 * enable the base too. The loop repeats until a pass adds nothing, so a chain
 * (a -> b -> c) resolves fully however the table is ordered; the table is small
 * and implications are shallow, so the cost is negligible. Returns the expanded
 * mask. */
static ngx_uint_t
ngx_http_cache_turbo_expand_implies(ngx_uint_t mask)
{
    ngx_uint_t  i, added;

    do {
        added = 0;

        for (i = 0; ngx_http_cache_turbo_backend_names[i].name; i++) {
            if ((mask & ngx_http_cache_turbo_backend_names[i].bit)
                && ngx_http_cache_turbo_backend_names[i].implies)
            {
                ngx_uint_t  imp = ngx_http_cache_turbo_backend_names[i].implies;

                if ((mask & imp) != imp) {
                    mask |= imp;
                    added = 1;
                }
            }
        }
    } while (added);

    return mask;
}


/* Resolve one backend name (already split off a token) to its bit. Returns 0 for
 * an unknown name — 0 is not a valid bit, so the caller uses it as "not found".
 * `len` is explicit because names arrive as slices of a `a|b|c` token and are
 * NOT NUL-terminated at the boundary. */
static ngx_uint_t
ngx_http_cache_turbo_backend_bit(u_char *name, size_t len)
{
    ngx_uint_t  i;
    size_t      nlen;

    for (i = 0; ngx_http_cache_turbo_backend_names[i].name; i++) {
        nlen = ngx_strlen(ngx_http_cache_turbo_backend_names[i].name);

        if (nlen == len
            && ngx_strncmp(name, ngx_http_cache_turbo_backend_names[i].name,
                           len) == 0)
        {
            return ngx_http_cache_turbo_backend_names[i].bit;
        }
    }

    return 0;
}


char *
ngx_http_cache_turbo_backend(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;
    ngx_str_t                        *value;
    ngx_uint_t                        i, bit, mask;
    u_char                           *p, *end, *tok;
    ngx_str_t                         bad;

    value = cf->args->elts;
    mask = 0;

    /*
     * Backends stack, and both separators mean the same thing:
     *
     *     cache_turbo_backend wordpress woocommerce;      (spaces)
     *     cache_turbo_backend wordpress|woocommerce;      (pipe)
     *     cache_turbo_backend wordpress | woocommerce;    (both)
     *
     * nginx's config lexer splits on whitespace, so `a|b` reaches us as ONE
     * token containing a '|', while `a | b` reaches us as THREE tokens (the
     * middle one a bare "|"). Hence two levels: walk the argv tokens, and split
     * each one on '|'. A bare "|" token contributes no names and is skipped.
     * Empty slices (`a||b`, a trailing `a|`) are rejected rather than ignored —
     * they are a typo, and silently accepting them hides it.
     */
    for (i = 1; i < cf->args->nelts; i++) {
        p = value[i].data;
        end = p + value[i].len;

        /* a bare "|" used as a standalone separator token */
        if (value[i].len == 1 && *p == '|') {
            continue;
        }

        while (p < end) {
            tok = p;
            while (p < end && *p != '|') {
                p++;
            }

            if (p == tok) {          /* empty slice: "||", leading/trailing "|" */
                return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                    "empty backend name in cache_turbo_backend \"%V\" "
                    "(stray '|')", &value[i]);
            }

            bit = ngx_http_cache_turbo_backend_bit(tok, (size_t) (p - tok));

            if (bit == 0) {
                bad.data = tok;
                bad.len  = (size_t) (p - tok);

                /* The two removed spellings get their own diagnostic — a bare
                 * "unknown backend" would leave an operator whose config worked
                 * yesterday with no idea what to do. This is a HARD error, not a
                 * silent no-op: accepting the name and enabling nothing would
                 * leave an existing WordPress config with no preset active and
                 * quietly start caching /wp-admin/, which is the exact failure
                 * the removal exists to prevent. Refusing to start makes the
                 * operator look. */
                if ((bad.len == sizeof("generic") - 1
                     && ngx_strncmp(bad.data, "generic", bad.len) == 0)
                    || (bad.len == sizeof("auto") - 1
                        && ngx_strncmp(bad.data, "auto", bad.len) == 0))
                {
                    return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                        "cache_turbo_backend \"%V\" has been removed: it was a "
                        "union of wordpress+woocommerce+joomla, which was never "
                        "a safe default — it did not cover every backend, "
                        "`woocommerce` in it left /wp-admin/ cacheable unless "
                        "stacked with `wordpress`, and `joomla` in it ships no "
                        "cookie rule at all. Name the backends you actually run, "
                        "e.g. \"cache_turbo_backend wordpress|woocommerce;\"",
                        &bad);
                }

                return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                    "unknown cache_turbo_backend \"%V\" (want wordpress, "
                    "woocommerce, joomla, xenforo, discourse, phpbb, drupal, "
                    "mediawiki, magento, ghost, wagtail, kirby, shopware6, "
                    "typo3, invision, smf, vanilla, punbb, phorum, yabb, mybb, "
                    "vbulletin, textpattern, bludit, spip, bugzilla, mantisbt, "
                    "mantis, plone, umbraco, dotclear, wikijs, redmine, "
                    "flarum, opencart, "
                    "classicpress, backdrop, or none — "
                    "separated by spaces or '|')", &bad);
            }

            mask |= bit;

            if (p < end) {
                p++;                 /* step over the '|' */

                /* A '|' promises another name. If it was the last character of
                 * the token ("wordpress|"), there is none — and the outer
                 * `while (p < end)` would simply exit, silently accepting the
                 * typo. Catch it here; the empty-slice check above only fires
                 * for a leading or doubled pipe. */
                if (p == end) {
                    return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                        "empty backend name in cache_turbo_backend \"%V\" "
                        "(trailing '|')", &value[i]);
                }
            }
        }
    }

    /* Every argument was a bare '|' separator, so no backend was actually named
     * ("cache_turbo_backend |;"). Leaving the mask at 0 would mean "unset", which
     * the loc-conf merge reads as "inherit the parent's" — a directive that looks
     * like it says something and silently does nothing. NGX_CONF_1MORE already
     * guarantees at least one argument; this catches the degenerate one. */
    if (mask == 0) {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_backend names no backend (want wordpress, woocommerce, "
            "joomla, xenforo, discourse, phpbb, drupal, mediawiki, magento, "
            "ghost, wagtail, kirby, shopware6, typo3, invision, smf, vanilla, "
            "punbb, phorum, yabb, mybb, vbulletin, textpattern, bludit, spip, "
            "bugzilla, mantisbt, mantis, plone, umbraco, dotclear, wikijs, "
            "redmine, flarum, opencart, "
            "classicpress, backdrop, or none)");
    }

    /* Resolve add-on implications (woocommerce -> wordpress) to a fixpoint.
     * Silent by design — an add-on that needed its base spelled out would be the
     * same footgun cache_turbo_backend "auto" was removed for. "none" carries no
     * implication (implies == 0 in the name table), so folding it through here is
     * a no-op and safe to do before the exclusivity check below. */
    mask = ngx_http_cache_turbo_expand_implies(mask);

    /* Fold in any earlier cache_turbo_backend in the SAME context before the
     * "none" exclusivity check. backend_presets accumulates per context (0 =
     * unset), so this makes the check see the combined value rather than only this
     * one invocation's args — otherwise `cache_turbo_backend none;` and
     * `cache_turbo_backend wordpress;` on two lines each pass alone and silently
     * leave NONE|WORDPRESS set. */
    mask |= clcf->backend_presets;

    /* "none" is exclusive: `none|wordpress` is a contradiction, not a merge, and
     * silently letting one win would be the quiet surprise this directive exists
     * to avoid. Checked on the combined mask so it catches the mix however it was
     * spelled (spaces, pipes, or across several directives). */
    if ((mask & NGX_HTTP_CACHE_TURBO_BACKEND_NONE)
        && NGX_HTTP_CACHE_TURBO_HAS_BACKEND(mask))
    {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_backend \"none\" cannot be combined with other backends "
            "— it means \"no preset in this location\" (and overrides one "
            "inherited from the server block). Use it alone.");
    }

    clcf->backend_presets = mask;

    return NGX_CONF_OK;
}


/* "cache_turbo_cache_control respect|honor|ignore;" — how the response
 * Cache-Control is treated. Sets the tri-state cc_mode; honor_cc/ignore_cc are
 * derived from it at merge (see merge_loc_conf). Replaces the former
 * cache_turbo_honor_cache_control / cache_turbo_ignore_cache_control flags. */
char *
ngx_http_cache_turbo_cache_control(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;
    ngx_str_t                        *value = cf->args->elts;

    if (clcf->cc_mode != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "respect") == 0) {
        clcf->cc_mode = NGX_HTTP_CACHE_TURBO_CC_RESPECT;
    } else if (ngx_strcmp(value[1].data, "honor") == 0) {
        clcf->cc_mode = NGX_HTTP_CACHE_TURBO_CC_HONOR;
    } else if (ngx_strcmp(value[1].data, "ignore") == 0) {
        clcf->cc_mode = NGX_HTTP_CACHE_TURBO_CC_IGNORE;
    } else {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "invalid cache_turbo_cache_control \"%V\" "
            "(want respect|honor|ignore)", &value[1]);
    }

    return NGX_CONF_OK;
}


char *
ngx_http_cache_turbo_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    clcf->key = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (clcf->key == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = clcf->key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * "cache_turbo_valid [code ...] time;"
 *   - bare `cache_turbo_valid 30s;`  => the default/200 fresh TTL (valid_raw),
 *     which also drives the stale window + autotune (back-compatible).
 *   - `cache_turbo_valid 301 302 1h;` / `cache_turbo_valid 404 1m;` => per-status
 *     fresh TTLs, so redirects and negative responses get cached too.
 * Last arg is always the time; any leading args are HTTP status codes.
 */
char *
ngx_http_cache_turbo_valid_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t                     *value;
    time_t                         valid;
    ngx_uint_t                     i;
    ngx_int_t                      code;
    ngx_http_cache_turbo_valid_t  *v;

    value = cf->args->elts;

    valid = ngx_parse_time(&value[cf->args->nelts - 1], 1);   /* seconds */
    if (valid == (time_t) NGX_ERROR) {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                           "cache_turbo_valid: bad time \"%V\"",
                           &value[cf->args->nelts - 1]);
    }

    /* "0" means "cache forever" (the documented contract). Resolve it to a long
     * finite TTL so the object stays FRESH (not instantly-stale) and L2 works —
     * a literal 0 fresh TTL produced an L2 blob with stale_ttl 0, which every L2
     * hit re-read as already-expired. Covers both the bare default TTL and any
     * per-status `cache_turbo_valid <code> 0` rule (same parsed `valid`). */
    if (valid == 0) {
        valid = NGX_HTTP_CACHE_TURBO_FOREVER_TTL;
    }

    if (cf->args->nelts == 2) {
        clcf->valid_raw = valid;           /* default / 200 TTL */
        return NGX_CONF_OK;
    }

    if (clcf->valid_status == NULL) {
        clcf->valid_status = ngx_array_create(cf->pool, 4,
                                 sizeof(ngx_http_cache_turbo_valid_t));
        if (clcf->valid_status == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts - 1; i++) {
        code = ngx_atoi(value[i].data, value[i].len);
        if (code < 100 || code > 599) {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_valid: bad status code \"%V\"", &value[i]);
        }
        /* Reject statuses that must not stand alone as a cached representation
         * (COR-12): 1xx informational are not final responses; 206 has no Range
         * in the key (a stored partial would be replayed for another range); 304
         * is a conditional answer that must never be served to an unconditional
         * request. The body filter also refuses 206 at store time, but rejecting
         * here turns a meaningless config into a clear error. */
        if (code < 200 || code == NGX_HTTP_PARTIAL_CONTENT
            || code == NGX_HTTP_NOT_MODIFIED)
        {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_valid: status %V cannot be cached standalone "
                "(1xx/206/304 refused)", &value[i]);
        }
        /* COR-9: status_ttl() returns the FIRST matching rule, so a second rule
         * for the same code is dead. Warn rather than silently ignore it. */
        {
            ngx_http_cache_turbo_valid_t  *ev = clcf->valid_status->elts;
            ngx_uint_t                     j;

            for (j = 0; j < clcf->valid_status->nelts; j++) {
                if (ev[j].status == (ngx_uint_t) code) {
                    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                        "cache_turbo_valid: duplicate rule for status %V "
                        "ignored (the first rule for a code wins)", &value[i]);
                    break;
                }
            }
        }

        v = ngx_array_push(clcf->valid_status);
        if (v == NULL) {
            return NGX_CONF_ERROR;
        }
        v->status = (ngx_uint_t) code;
        v->valid = valid;
    }

    return NGX_CONF_OK;
}


/* "cache_turbo_tag <expr>;" sets the tag-list expression. On store the result
 * is split on whitespace/commas and each tag set gets the object's L2 key. */
char *
ngx_http_cache_turbo_tag(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    clcf->tag = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (clcf->tag == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = clcf->tag;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * cache_turbo_require_header <name>: the explicit upstream store opt-in.
 * A plain header NAME, not a complex value -- the module reads the RESPONSE
 * header of that name, and a $variable here would be evaluated against the
 * request, quietly gating on the wrong thing.
 */
char *
ngx_http_cache_turbo_require_header(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t  *value = cf->args->elts;
    ngx_uint_t  i;

    if (clcf->require_header.len) {
        return "is duplicate";
    }

    if (value[1].len == 0) {
        return "requires a header name";
    }

    /* A header name is a token (RFC 9110 5.6.2). Reject anything else at config
     * time rather than compare a name that can never match at runtime -- a
     * store gate that silently never passes reads as "the cache is broken",
     * and one that silently never fires would be worse. */
    for (i = 0; i < value[1].len; i++) {
        u_char  c = value[1].data[i];

        if (c <= 0x20 || c >= 0x7f || c == ':' || c == ',' || c == ';'
            || c == '(' || c == ')' || c == '<' || c == '>' || c == '@'
            || c == '\\' || c == '"' || c == '/' || c == '[' || c == ']'
            || c == '?' || c == '=' || c == '{' || c == '}')
        {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                               "invalid header name \"%V\" in "
                               "\"cache_turbo_require_header\"", &value[1]);
        }
    }

    clcf->require_header = value[1];

    return NGX_CONF_OK;
}


/*
 * The store gate itself. Unset (len == 0) => 1, so every existing config keeps
 * the module's normal "cacheable unless vetoed" behaviour untouched.
 *
 * Set => the named response header must be present AND affirmative. Scans the
 * whole headers_out list rather than stopping at the first match: an upstream
 * that emits the header twice ("yes" and "no") is ambiguous, and the only safe
 * reading of an ambiguous store signal is "do not store" -- so ANY
 * non-affirmative occurrence vetoes, whatever order they arrive in.
 */
ngx_int_t
ngx_http_cache_turbo_require_hdr_ok(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
    ngx_uint_t        i, found = 0;

    if (clcf->require_header.len == 0) {
        return 1;
    }

    part = &r->headers_out.headers.part;
    h = part->elts;

    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (h[i].hash == 0 || h[i].key.len != clcf->require_header.len) {
            continue;
        }
        if (ngx_strncasecmp(h[i].key.data, clcf->require_header.data,
                            clcf->require_header.len) != 0)
        {
            continue;
        }

        /* Affirmative values only, matched whole: "yes" / "1" / "on". A prefix
         * compare would read "note" as "no"-negative and, worse, "yes-but-not-
         * really" as affirmative. */
        if (!((h[i].value.len == 3
               && ngx_strncasecmp(h[i].value.data, (u_char *) "yes", 3) == 0)
              || (h[i].value.len == 2
                  && ngx_strncasecmp(h[i].value.data, (u_char *) "on", 2) == 0)
              || (h[i].value.len == 1 && h[i].value.data[0] == '1')))
        {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "cache_turbo: \"%V\" not cached: %V is not "
                           "affirmative", &r->uri, &clcf->require_header);
            return 0;
        }

        found = 1;
    }

    if (!found) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: \"%V\" not cached: no %V header",
                       &r->uri, &clcf->require_header);
    }

    return found ? 1 : 0;
}


/* cache_turbo_stale_mult N (H5). Range-checked rather than a bare
 * ngx_conf_set_num_slot: ngx_http_cache_turbo_stale_ttl() coerces <= 0 back to
 * the BALANCED default, so an explicit `0` would silently behave as `4` instead
 * of the "no stale window" the operator wrote. Reject it at parse instead. */
char *
ngx_http_cache_turbo_stale_mult(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t  *value = cf->args->elts;
    ngx_int_t   n;

    if (clcf->stale_mult_raw != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    n = ngx_atoi(value[1].data, value[1].len);
    if (n == NGX_ERROR) {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_stale_mult: bad value \"%V\"", &value[1]);
    }

    if (n < NGX_HTTP_CACHE_TURBO_STALE_MULT_MIN
        || n > NGX_HTTP_CACHE_TURBO_STALE_MULT_MAX)
    {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_stale_mult \"%V\" is out of range: expected %d..%d",
            &value[1], NGX_HTTP_CACHE_TURBO_STALE_MULT_MIN,
            NGX_HTTP_CACHE_TURBO_STALE_MULT_MAX);
    }

    clcf->stale_mult_raw = n;

    return NGX_CONF_OK;
}


/* cache_turbo_min_uses N (H3c). Range-checked rather than a bare
 * ngx_conf_set_num_slot for the same reason as stale_mult above: merge_loc_conf
 * coerces a value < 1 up to 1, so an explicit `0` or a negative would silently
 * behave as `1` ("store on the first miss") instead of whatever the operator
 * meant by it. Reject at parse so the config cannot lie. */
char *
ngx_http_cache_turbo_min_uses(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t  *value = cf->args->elts;
    ngx_int_t   n;

    if (clcf->min_uses_raw != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    /* ngx_atoi has no sign handling, so a negative fails here as NGX_ERROR and
     * surfaces as "bad value" rather than reaching the range check below. The
     * two diagnostics are deliberately distinct — see the H5 lesson. */
    n = ngx_atoi(value[1].data, value[1].len);
    if (n == NGX_ERROR) {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_min_uses: bad value \"%V\"", &value[1]);
    }

    if (n < NGX_HTTP_CACHE_TURBO_MIN_USES_MIN
        || n > NGX_HTTP_CACHE_TURBO_MIN_USES_MAX)
    {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_min_uses \"%V\" is out of range: expected %d..%d",
            &value[1], NGX_HTTP_CACHE_TURBO_MIN_USES_MIN,
            NGX_HTTP_CACHE_TURBO_MIN_USES_MAX);
    }

    clcf->min_uses_raw = n;

    return NGX_CONF_OK;
}


/* cache_turbo_breaker_open T (O4.4). Hand-rolled rather than
 * ngx_conf_set_sec_slot for the same class of reason as min_uses/stale_mult
 * above, but inverted: those reject 0 because merge_loc_conf would silently
 * COERCE it to a non-zero default, masking the operator's intent. This one
 * rejects 0 because a literal 0 would NOT be inert here the way it is for
 * every sibling breaker field -- _breaker_state()'s timed reopen is guarded
 * on `open_for > 0` (see the field comment in the .h and O4.3-a in memory
 * issues.md), so `cache_turbo_breaker_open 0` would WEDGE an OPEN breaker
 * permanently: it would never promote a probe, and with nobody talking to
 * the origin while OPEN, no success could ever be recorded to close it
 * either. That is materially worse than the "off" the operator likely
 * intended, so it is refused outright -- "off" for the breaker is expressed
 * via cache_turbo_breaker, cache_turbo_breaker_threshold 0, or
 * cache_turbo_breaker_window 0 instead. */
char *
ngx_http_cache_turbo_breaker_open_conf(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t   *value = cf->args->elts;
    ngx_int_t    n;

    if (clcf->breaker_open != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    n = ngx_parse_time(&value[1], 1);
    if (n == NGX_ERROR) {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_breaker_open: invalid value \"%V\"", &value[1]);
    }

    if (n == 0) {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_breaker_open \"%V\" must be greater than 0 "
            "(0 wedges the breaker OPEN forever: it never reopens and, with "
            "no origin contact while OPEN, never closes either -- use "
            "cache_turbo_breaker off, cache_turbo_breaker_threshold 0, or "
            "cache_turbo_breaker_window 0 to disable the breaker instead)",
            &value[1]);
    }

    clcf->breaker_open = (time_t) n;

    return NGX_CONF_OK;
}


/* cache_turbo_scan_resistant on|off [protected_pct=N]   (S8, default flipped P3-1)
 *
 * Segmented (probation/protected) LRU. ON BY DEFAULT since P3-1 (protected_pct
 * 80, the same PROTECTED_PCT_DEFAULT the bare `on` directive has always used):
 * when absent, or set to `on`, a key needs a second hit to promote out of
 * probation, so a one-hit crawler/sitemap/scanner walk cannot evict it.
 * Explicit `off` sets scan_resistant_pct to 0 and every LRU path behaves
 * exactly as the flat single-queue LRU did before S8 -- no node is ever
 * promoted, the protected queue stays empty, and eviction always finds its
 * victim on probation. Use `off` to restore that pre-P3-1 behaviour on
 * upgrade; see README's Upgrading section.
 *
 * `on` stores the protected-segment cap (1..99, default 80) in the same field,
 * so "on" and the tuning cannot disagree and there is no representable
 * "on with pct 0" state.
 *
 * Range-checked by hand rather than via ngx_conf_set_num_slot for the reason
 * H5/stale_mult and H3c/min_uses both re-learned the hard way: a bare num_slot
 * would accept `protected_pct=0` and let it be silently coerced to the default,
 * so the config would quietly mean something other than what it says. A value
 * outside the band is a config ERROR here.
 */
char *
ngx_http_cache_turbo_scan_resistant(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t  *value = cf->args->elts;
    ngx_int_t   pct;
    ngx_uint_t  i;
    ngx_uint_t  on;

    if (clcf->scan_resistant_pct != (ngx_uint_t) NGX_CONF_UNSET) {
        return "is duplicate";
    }

    if (value[1].len == 2 && ngx_strncmp(value[1].data, "on", 2) == 0) {
        on = 1;

    } else if (value[1].len == 3
               && ngx_strncmp(value[1].data, "off", 3) == 0)
    {
        on = 0;

    } else {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_scan_resistant: bad value \"%V\": expected "
            "\"on\" or \"off\"", &value[1]);
    }

    pct = NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_DEFAULT;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "protected_pct=", 14) == 0) {

            /* ngx_atoi has no sign handling, so a negative fails as NGX_ERROR
             * and surfaces as "bad protected_pct" rather than reaching the
             * range check. The two diagnostics are deliberately distinct --
             * same split as cache_turbo_stale_mult (the H5 lesson). */
            pct = ngx_atoi(value[i].data + 14, value[i].len - 14);
            if (pct == NGX_ERROR) {
                return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_scan_resistant: bad protected_pct \"%V\"",
                    &value[i]);
            }

            if (pct < NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_MIN
                || pct > NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_MAX)
            {
                return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                    "cache_turbo_scan_resistant: protected_pct \"%V\" is out "
                    "of range: expected %d..%d", &value[i],
                    NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_MIN,
                    NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_MAX);
            }

            continue;
        }

        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_scan_resistant: unknown parameter \"%V\"", &value[i]);
    }

    /* protected_pct on an `off` directive is accepted-but-inert config: reject
     * it rather than store a value that will never be read. */
    if (!on && cf->args->nelts > 2) {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_scan_resistant: protected_pct is meaningless with "
            "\"off\"");
    }

    clcf->scan_resistant_pct = on ? (ngx_uint_t) pct : 0;

    return NGX_CONF_OK;
}


/* cache_turbo_l2_negative_ttl N (L13). Seconds to remember an L2 miss so the
 * next cold request for the same key skips the L2 round-trip.
 *
 * Range-checked like stale_mult/min_uses above, but with one deliberate
 * difference: 0 is ACCEPTED here and means OFF (the default). For those two
 * directives a literal 0 was a config lie -- merge coerced it back up to 1 --
 * so it had to be rejected. Here 0 is the honest, and default, way to say "no
 * memo", and merge_loc_conf leaves it at 0. A NEGATIVE still fails as
 * NGX_ERROR out of ngx_atoi (no sign handling) and surfaces as "bad value". */
char *
ngx_http_cache_turbo_l2_negative_ttl(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t  *value = cf->args->elts;
    ngx_int_t   n;

    if (clcf->l2_negative_ttl != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    n = ngx_atoi(value[1].data, value[1].len);
    if (n == NGX_ERROR) {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_l2_negative_ttl: bad value \"%V\"", &value[1]);
    }

    if (n != 0
        && (n < NGX_HTTP_CACHE_TURBO_L2_NEG_TTL_MIN
            || n > NGX_HTTP_CACHE_TURBO_L2_NEG_TTL_MAX))
    {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_l2_negative_ttl \"%V\" is out of range: expected 0 "
            "(off) or %d..%d",
            &value[1], NGX_HTTP_CACHE_TURBO_L2_NEG_TTL_MIN,
            NGX_HTTP_CACHE_TURBO_L2_NEG_TTL_MAX);
    }

    clcf->l2_negative_ttl = (time_t) n;

    return NGX_CONF_OK;
}


/* cache_turbo_keep_stale <off|time|forever> (S2.1). Origin-independent
 * last-resort retention: when a response carries no `stale-if-error` window of
 * its own, this value becomes the effective stale-if-error window instead of
 * leaving the object with no fallback. The store path reads clcf->keep_stale
 * into sie_window in the two branches at the `ttl > 0 && clcf->keep_stale > 0`
 * and `ttl > 0 && clcf->ignore_cc && clcf->keep_stale > 0` gates (S2.2).
 *
 * cache_turbo_cache_control ignore does NOT suppress this directive (decision
 * D-1; clcf->ignore_cc is the internal flag it sets). Every
 * !clcf->ignore_cc gate in the store path guards a RESPONSE-derived value --
 * upstream max-age, stale-while-revalidate, must-revalidate, stale-if-error --
 * because ignore_cc means "the upstream Cache-Control header is inert", not
 * "operator retention config is inert". stale_window is likewise built from
 * cache_turbo_valid + cache_turbo_stale_mult regardless of ignore_cc; keep_stale
 * is the sie_window analogue of stale_mult. Under ignore_cc the response
 * stale-if-error branch never runs, so keep_stale simply applies unconditionally.
 * Precedence when both are available: a HONORED response stale-if-error WINS over
 * keep_stale (same shape as response swr beating stale_mult) -- deliberately not
 * max(), which would make keep_stale a silent floor overriding an origin that
 * explicitly stated its own error window.
 *
 * Argument forms:
 *   off      -> 0 (the default; today's behaviour, unchanged)
 *   forever  -> NGX_HTTP_CACHE_TURBO_FOREVER_TTL
 *   <time>   -> ngx_parse_time(..., 1), clamped to NGX_HTTP_CACHE_TURBO_TTL_MAX
 *
 * A bare "0" is accepted as a synonym for `off`, NOT for "forever" --
 * ngx_parse_time("0", 1) already returns 0 with no error, so this falls out
 * naturally rather than needing a special case. This is a DELIBERATE
 * departure from cache_turbo_valid's contract, where `cache_turbo_valid 0`
 * means "cache forever" (see the FOREVER_TTL resolution above
 * ngx_http_cache_turbo_valid_conf). The two directives read the same digit
 * with opposite meaning: cache_turbo_valid's forever-TTL and this directive's
 * off both had to spell as "reset the field to a value that switches the
 * feature off"; but cache_turbo_valid's field can never mean "no TTL" (a
 * cached object always has SOME fresh window), so 0 there was repurposed as
 * an alias for forever. keep_stale, by contrast, has an honest OFF state (no
 * last-resort retention at all), and OFF is what an operator who writes a
 * bare 0 -- or omits the directive -- means. Do not "fix" this to match
 * cache_turbo_valid; a future reader who reconciles the two will silently
 * turn every un-configured location into permanent stale retention. */
char *
ngx_http_cache_turbo_keep_stale(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t  *value = cf->args->elts;
    time_t      t;

    if (clcf->keep_stale != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    if (value[1].len == 3 && ngx_strncmp(value[1].data, "off", 3) == 0) {
        clcf->keep_stale = 0;
        return NGX_CONF_OK;
    }

    if (value[1].len == 7 && ngx_strncmp(value[1].data, "forever", 7) == 0) {
        clcf->keep_stale = NGX_HTTP_CACHE_TURBO_FOREVER_TTL;
        return NGX_CONF_OK;
    }

    t = ngx_parse_time(&value[1], 1);   /* seconds, matches cache_turbo_valid */
    if (t == (time_t) NGX_ERROR) {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_keep_stale: bad value \"%V\"", &value[1]);
    }

    /* Clamp rather than reject (matches the store path's own TTL_MAX clamp,
     * see the header comment on NGX_HTTP_CACHE_TURBO_TTL_MAX): an operator
     * writing an oversized-but-well-formed time is asking for "as long as
     * possible", not making a typo the way an out-of-range l2_negative_ttl
     * is -- there is no bounded-blindness cost here to make a large value a
     * footgun, only a wire-format ceiling. */
    if (t > NGX_HTTP_CACHE_TURBO_TTL_MAX) {
        t = NGX_HTTP_CACHE_TURBO_TTL_MAX;
    }

    clcf->keep_stale = t;

    return NGX_CONF_OK;
}


/* cache_turbo_use_stale <off | error | timeout | http_403 | http_404 |
 *                         http_429 | http_500 | http_502 | http_503 |
 *                         http_504> ... (S4.1). Read on the request path by
 * the stale-if-error gate in ngx_http_cache_turbo_header_filter (S4.2). See the
 * NGX_HTTP_CACHE_TURBO_USE_STALE_* block in the header for the full mask
 * contract, the error/timeout aliasing rationale, and why the merge default
 * includes the ANY_5XX bit.
 *
 * `off` must appear alone: mixing it with any other token is rejected, same
 * shape as nginx's own proxy_cache_use_stale (`off` there is likewise not
 * combinable). Any unrecognised token is rejected by name. Hand-written
 * NGX_CONF_1MORE parser -- this module has zero uses of
 * ngx_conf_set_bitmask_slot anywhere, by established convention (see
 * cache_turbo_scan_resistant, cache_turbo_normalize_strip, and the directive
 * this one is modelled on, cache_turbo_keep_stale, immediately above). */
/* MAINT-SEAM: the token vocabulary as data. The chain of length+strncmp arms
 * this replaces carried one branch pair per token, which is what put this
 * function at the top of the complexity list; adding a token now means adding
 * a row, not another arm. `off` stays a special case above the table -- it
 * sets no bit and is the only token that cannot be combined. Terminated by a
 * zero-length name. */
typedef struct {
    ngx_str_t   name;
    ngx_uint_t  bit;
} ngx_http_cache_turbo_use_stale_token_t;

static const ngx_http_cache_turbo_use_stale_token_t
    ngx_http_cache_turbo_use_stale_tokens[] = {
    { ngx_string("error"),    NGX_HTTP_CACHE_TURBO_USE_STALE_ERROR    },
    { ngx_string("timeout"),  NGX_HTTP_CACHE_TURBO_USE_STALE_TIMEOUT  },
    { ngx_string("http_403"), NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_403 },
    { ngx_string("http_404"), NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_404 },
    { ngx_string("http_429"), NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_429 },
    { ngx_string("http_500"), NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_500 },
    { ngx_string("http_502"), NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_502 },
    { ngx_string("http_503"), NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_503 },
    { ngx_string("http_504"), NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_504 },
    { ngx_null_string, 0 }
};


char *
ngx_http_cache_turbo_use_stale(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t   *value;
    ngx_uint_t   i, mask, saw_off;

    const ngx_http_cache_turbo_use_stale_token_t  *t;

    if (clcf->use_stale != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;
    mask = 0;
    saw_off = 0;

    for (i = 1; i < cf->args->nelts; i++) {

        if (value[i].len == 3
            && ngx_strncmp(value[i].data, "off", 3) == 0)
        {
            saw_off = 1;
            continue;
        }

        for (t = ngx_http_cache_turbo_use_stale_tokens; t->name.len; t++) {
            if (value[i].len == t->name.len
                && ngx_strncmp(value[i].data, t->name.data, t->name.len) == 0)
            {
                mask |= t->bit;
                break;
            }
        }

        if (t->name.len == 0) {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "invalid value \"%V\" in \"%V\" directive",
                &value[i], &cmd->name);
        }
    }

    if (saw_off && mask != 0) {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "invalid value \"off\" in \"%V\" directive: "
            "\"off\" cannot be combined with other tokens", &cmd->name);
    }

    /* saw_off with mask == 0 -> empty mask (off). Any other combination of
     * real tokens -> their OR. Note this never sets ANY_5XX: that bit is a
     * merge-default-only construct (see header comment), not reachable from
     * the config vocabulary. */
    clcf->use_stale = mask;

    return NGX_CONF_OK;
}


/* "cache_turbo_preset micro|conservative|balanced|aggressive;" stores the enum
 * (and validates the name here, at config time). The enum only selects the band
 * of default knob values used in merge_loc_conf; an explicit knob directive
 * (cache_turbo_valid/_beta/_lock_ttl) still wins because those write the *_raw
 * fields, which take precedence over the band in the merge. */
char *
ngx_http_cache_turbo_preset(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t  *value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "conservative") == 0) {
        clcf->preset = NGX_HTTP_CACHE_TURBO_PRESET_CONSERVATIVE;

    } else if (ngx_strcmp(value[1].data, "balanced") == 0) {
        clcf->preset = NGX_HTTP_CACHE_TURBO_PRESET_BALANCED;

    } else if (ngx_strcmp(value[1].data, "aggressive") == 0) {
        clcf->preset = NGX_HTTP_CACHE_TURBO_PRESET_AGGRESSIVE;

    } else if (ngx_strcmp(value[1].data, "micro") == 0) {
        clcf->preset = NGX_HTTP_CACHE_TURBO_PRESET_MICRO;

    } else {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "invalid cache_turbo_preset \"%V\": "
            "expected micro, conservative, balanced, or aggressive",
            &value[1]);
    }

    return NGX_CONF_OK;
}


/* "cache_turbo_admin <zone>;" turns this location into a control endpoint for
 * the named zone. Gate it with the usual allow/deny. */
char *
ngx_http_cache_turbo_admin(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;

    ngx_str_t                 *value;
    ngx_http_core_loc_conf_t  *core;

    value = cf->args->elts;

    clcf->admin_zone = ngx_shared_memory_add(cf, &value[1], 0,
                                             &ngx_http_cache_turbo_module);
    if (clcf->admin_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    clcf->admin = 1;

    core = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    core->handler = ngx_http_cache_turbo_admin_handler;

    return NGX_CONF_OK;
}


#if (NGX_SSL)
/* Build the per-location client SSL context for a rediss:// (TLS) backend.
 * Verification is on unless tls_verify=off: trust the system CA store, or the
 * file named by tls_ca=. The cert+hostname are checked post-handshake in the
 * driver (ngx_ssl_check_host + SSL_get_verify_result). */
static char *
ngx_http_cache_turbo_redis_build_ssl(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
    ngx_ssl_t           *ssl;
    ngx_pool_cleanup_t  *cln;

    ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (ssl == NULL) {
        return NGX_CONF_ERROR;
    }
    ssl->log = cf->log;

    if (ngx_ssl_create(ssl, NGX_SSL_TLSv1_2|NGX_SSL_TLSv1_3, NULL) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        ngx_ssl_cleanup_ctx(ssl);
        return NGX_CONF_ERROR;
    }
    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = ssl;

    /* Called post-merge (COR-6): redis_tls_verify is resolved to 0 or 1 here.
     * 0 = verify off (tls_verify=off); 1 = verify on (the default). */
    if (clcf->redis_tls_verify != 0) {
        if (clcf->redis_tls_ca.len) {
            if (ngx_ssl_trusted_certificate(cf, ssl, &clcf->redis_tls_ca, 2)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        } else if (SSL_CTX_set_default_verify_paths(ssl->ctx) != 1) {
            ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                          "cache_turbo_redis: "
                          "SSL_CTX_set_default_verify_paths() failed");
            return NGX_CONF_ERROR;
        }
    }

    clcf->redis_ssl = ssl;
    return NGX_CONF_OK;
}
#endif


/* cache_turbo_normalize_strip name...  — append extra denylist patterns. */
char *
ngx_http_cache_turbo_normalize_strip(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;
    ngx_str_t                        *value, *s;
    ngx_uint_t                        i;

    if (clcf->normalize_strip == NGX_CONF_UNSET_PTR) {
        clcf->normalize_strip = ngx_array_create(cf->pool, 8,
                                                 sizeof(ngx_str_t));
        if (clcf->normalize_strip == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        s = ngx_array_push(clcf->normalize_strip);
        if (s == NULL) {
            return NGX_CONF_ERROR;
        }
        *s = value[i];
    }

    return NGX_CONF_OK;
}


/* "cache_turbo_normalize_vary encoding device;" — select which Vary buckets are
 * appended to $cache_turbo_normalized_args (v3-4). Tokens validated at config
 * time; an unknown token is rejected (like cache_turbo_preset). Default off. */
char *
ngx_http_cache_turbo_normalize_vary(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;
    ngx_str_t                        *value;
    ngx_uint_t                        i;
    ngx_int_t                         vary = 0;

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strcmp(value[i].data, "encoding") == 0) {
            vary |= NGX_HTTP_CACHE_TURBO_VARY_ENCODING;

        } else if (ngx_strcmp(value[i].data, "device") == 0) {
            vary |= NGX_HTTP_CACHE_TURBO_VARY_DEVICE;

        } else {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "invalid cache_turbo_normalize_vary token \"%V\": "
                "expected encoding and/or device", &value[i]);
        }
    }

    clcf->normalize_vary = vary;

    return NGX_CONF_OK;
}


/* "cache_turbo_vary_ignore Accept X-Requested-With ...;" (P3-3) — append
 * header names that classify_vary() drops from a response's Vary header
 * BEFORE the whitelist/unknown-axis check, i.e. treated as absent rather than
 * safe: an ignored token contributes nothing to the variant key and does NOT
 * get folded into the built-in safe-axis whitelist (Accept-Encoding/
 * User-Agent/Accept-Language/Origin), which stays fixed. Off by default
 * (nothing ignored) -- only takes effect once cache_turbo_auto_vary is also
 * on, since that is the only caller of classify_vary().
 *
 * ⚠ Correctness override, not a free win: naming a header here is the
 * operator asserting that clients differing only on that axis may share one
 * cached body even though the origin's Vary line said otherwise. Cookie,
 * Authorization and "*" are REJECTED at config time (see the loop below) --
 * classify_vary() drops an ignored token before classify_token() ever runs,
 * which is exactly where those three tokens' dedicated veto lives; silently
 * accepting them here would let one directive line disable a
 * security-relevant refusal (RFC 9110 12.5.5) rather than a keying
 * optimisation, so they are refused outright instead of silently ignored. */
char *
ngx_http_cache_turbo_vary_ignore(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;
    ngx_str_t                        *value, *s;
    ngx_uint_t                        i;

    if (clcf->vary_ignore == NULL || clcf->vary_ignore == NGX_CONF_UNSET_PTR) {
        clcf->vary_ignore = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (clcf->vary_ignore == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        if ((value[i].len == 1 && value[i].data[0] == '*')
            || (value[i].len == sizeof("Cookie") - 1
                && ngx_strncasecmp(value[i].data, (u_char *) "Cookie",
                                    value[i].len) == 0)
            || (value[i].len == sizeof("Authorization") - 1
                && ngx_strncasecmp(value[i].data, (u_char *) "Authorization",
                                    value[i].len) == 0))
        {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_vary_ignore \"%V\": refusing to ignore a "
                "security-relevant Vary axis (\"*\", Cookie, Authorization "
                "always veto caching)", &value[i]);
        }

        s = ngx_array_push(clcf->vary_ignore);
        if (s == NULL) {
            return NGX_CONF_ERROR;
        }
        *s = value[i];
    }

    return NGX_CONF_OK;
}


/*
 * "cache_turbo_backend_prefix /shop/;"
 *
 * Mount point of a subdirectory install. Rebases r->uri before the preset
 * uris[] tier runs, so "/shop/wp-admin/" matches the "/wp-admin/" needle.
 * See the backend_prefix field comment for why the scope stops there.
 *
 * Both slashes are REQUIRED rather than silently added. A value that does not
 * match the deployed mount produces zero URI-rule coverage — the exact silent
 * failure this directive exists to end — so a malformed one is rejected loudly
 * at config time instead of being coerced into something that merely looks
 * like it works.
 */
char *
ngx_http_cache_turbo_backend_prefix(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;
    ngx_str_t                        *value;

    if (clcf->backend_prefix != NGX_CONF_UNSET_PTR
        && clcf->backend_prefix != NULL)
    {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].len < 2 || value[1].data[0] != '/'
        || value[1].data[value[1].len - 1] != '/')
    {
        return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
            "cache_turbo_backend_prefix \"%V\" must begin and end with \"/\" "
            "(e.g. \"/shop/\"); \"/\" alone is the root mount and is the "
            "default behaviour, so it is not a valid value", &value[1]);
    }

    clcf->backend_prefix = ngx_palloc(cf->pool, sizeof(ngx_str_t));
    if (clcf->backend_prefix == NULL) {
        return NGX_CONF_ERROR;
    }

    *clcf->backend_prefix = value[1];

    return NGX_CONF_OK;
}


/* cache_turbo_bypass_uri prefix...  — DIY equivalent of a preset URI rule. Each
 * prefix is stored verbatim; the request path matches it with the same
 * segment-boundary matcher the presets use. Appends across levels (a location
 * adds to the server-level set) rather than replacing. */
char *
ngx_http_cache_turbo_bypass_uri(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;
    ngx_str_t                        *value, *s;
    ngx_uint_t                        i;

    if (clcf->bypass_uri == NGX_CONF_UNSET_PTR) {
        clcf->bypass_uri = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (clcf->bypass_uri == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 0 || value[i].data[0] != '/') {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_bypass_uri prefix \"%V\" must begin with \"/\"",
                &value[i]);
        }
        s = ngx_array_push(clcf->bypass_uri);
        if (s == NULL) {
            return NGX_CONF_ERROR;
        }
        *s = value[i];
    }

    return NGX_CONF_OK;
}


/* S232-BYPASS-STALE: cache_turbo_bypass_stale_uri <prefix>... -- same parsing
 * and same segment-boundary matcher as cache_turbo_bypass_uri above, but the
 * effect is the opposite: these prefixes are STORED (as breaker-only fallback)
 * rather than skipped. See the bypass_stale_uri field comment in module.h for
 * why this is a separate directive instead of a flag on the bypass rules. */
char *
ngx_http_cache_turbo_bypass_stale_uri(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;
    ngx_str_t                        *value, *s;
    ngx_uint_t                        i;

    if (clcf->bypass_stale_uri == NGX_CONF_UNSET_PTR) {
        clcf->bypass_stale_uri = ngx_array_create(cf->pool, 4,
                                                  sizeof(ngx_str_t));
        if (clcf->bypass_stale_uri == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 0 || value[i].data[0] != '/') {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_bypass_stale_uri prefix \"%V\" must begin "
                "with \"/\"", &value[i]);
        }
        s = ngx_array_push(clcf->bypass_stale_uri);
        if (s == NULL) {
            return NGX_CONF_ERROR;
        }
        *s = value[i];
    }

    return NGX_CONF_OK;
}


/* cache_turbo_key_cookie name...  — DIY equivalent of a preset key cookie. The
 * VALUE of each named cookie is folded into the cache key (tier-3 value-keying)
 * so segment variants get their own entries instead of bypassing. EXACT name
 * match. See ngx_http_cache_turbo_build_key for the fold and its security
 * rationale (unforgeable length-prefixed framing, all Cookie headers scanned).
 * Appends across levels. */
char *
ngx_http_cache_turbo_key_cookie_conf(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_cache_turbo_loc_conf_t  *clcf = conf;
    ngx_str_t                        *value, *s;
    ngx_uint_t                        i;

    if (clcf->key_cookies == NGX_CONF_UNSET_PTR) {
        clcf->key_cookies = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (clcf->key_cookies == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 0) {
            return NGX_HTTP_CACHE_TURBO_CONF_ERROR(NGX_LOG_EMERG, cf, 0,
                "cache_turbo_key_cookie name must not be empty");
        }
        s = ngx_array_push(clcf->key_cookies);
        if (s == NULL) {
            return NGX_CONF_ERROR;
        }
        *s = value[i];
    }

    return NGX_CONF_OK;
}
