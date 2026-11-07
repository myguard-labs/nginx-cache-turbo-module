/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_http_cache_turbo_testalloc.h -- TEST_FAULTS-only allocation funnel.
 *
 * WHAT THIS IS FOR
 *   Every pool allocation the module makes goes through one gate in a test
 *   build. The gate traps an allocation on a dead (NULL) pool at the call
 *   site that made it: it logs
 *
 *       [alert] cache_turbo: alloc on dead pool at <file>:<line>
 *
 *   then calls ngx_debug_point() and aborts. Without the gate the same call
 *   faults inside nginx core (pool->d.last) with no module frame in the
 *   message, and the runtime harness fails every test on any [alert], so a
 *   trap that fires anywhere in the suite names its site.
 *
 * WHY IT IS NOT IN THE SHIPPING MODULE
 *   ngx_http_cache_turbo_module.h includes this file only when
 *   NGX_HTTP_CACHE_TURBO_TEST_FAULTS is non-zero, at its very end, so a
 *   release translation unit sees neither the macros nor a line shift. The
 *   gate and the trap directive are defined at the end of module.c under the
 *   same guard, after every other definition, for the same reason. A release
 *   .so therefore has no funnel symbol and its objects are byte-identical to
 *   a build without this header.
 *
 * HOW THE MACROS WORK
 *   nginx's own headers are already included when this file is read, so the
 *   real ngx_palloc() and friends are declared. Each wrapper below is defined
 *   BEFORE its macro and so calls the real function; every use in module
 *   source AFTER this point, including nginx macros that expand to one of
 *   these names at the use site (ngx_calloc_buf, ngx_alloc_buf), expands to
 *   the wrapper with the caller's __FILE__/__LINE__. Each argument is
 *   evaluated exactly once. nginx's own static inline helpers that allocate
 *   (ngx_array_init, ngx_list_init) were compiled before the macros exist and
 *   stay outside the funnel.
 *
 * INJECTED FAILURES (BP-C1)
 *   ngx_http_cache_turbo_test_alloc_gate() is the single decision point.
 *   NGX_OK lets the allocation proceed; any other value makes the wrapper
 *   return NULL without allocating. The fault_alloc=N countdown plugs in
 *   there without touching a macro: a location with
 *   `cache_turbo_test_fault_alloc;` arms it from a request (?n=N), and the
 *   gate then fails exactly the Nth funnel call after that request finishes,
 *   once, and disarms. See the countdown comment at the end of module.c.
 */

#ifndef NGX_HTTP_CACHE_TURBO_TESTALLOC_H_INCLUDED_
#define NGX_HTTP_CACHE_TURBO_TESTALLOC_H_INCLUDED_

/* Empty outside TEST_FAULTS: a stray include from a release TU (or a lint
 * that parses this header on its own) sees nothing. */
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS

#include <ngx_config.h>
#include <ngx_core.h>


/* The gate, defined at the end of module.c. Traps a NULL pool (does not
 * return); otherwise NGX_OK to allocate, NGX_DECLINED to fail the call (the
 * armed fault_alloc countdown reaching its Nth call). */
ngx_int_t ngx_http_cache_turbo_test_alloc_gate(ngx_pool_t *pool,
    const char *file, ngx_uint_t line);

/* `cache_turbo_test_dead_pool_alloc;` (http{} level, no arguments): the
 * deliberate dead-pool allocation the runtime suite uses to prove the trap
 * fires. Its handler calls ngx_palloc() on a NULL pool at parse time. */
char *ngx_http_cache_turbo_test_dead_pool_alloc(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

/* `cache_turbo_test_fault_alloc;` (location level, no arguments): installs
 * the content handler that reports and arms the fault_alloc=N countdown. */
char *ngx_http_cache_turbo_test_fault_alloc(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

/* Spliced into ngx_http_cache_turbo_commands[] (module.c) in place of a
 * blank line, so module.c gains no line in any build. */
#define NGX_HTTP_CACHE_TURBO_TEST_ALLOC_COMMANDS                              \
    { ngx_string("cache_turbo_test_dead_pool_alloc"),                         \
      NGX_HTTP_MAIN_CONF|NGX_CONF_NOARGS,                                     \
      ngx_http_cache_turbo_test_dead_pool_alloc,                              \
      0,                                                                      \
      0,                                                                      \
      NULL },                                                                 \
    { ngx_string("cache_turbo_test_fault_alloc"),                             \
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,                                      \
      ngx_http_cache_turbo_test_fault_alloc,                                  \
      NGX_HTTP_LOC_CONF_OFFSET,                                               \
      0,                                                                      \
      NULL },


static ngx_inline void *
ngx_http_cache_turbo_ta_palloc(ngx_pool_t *pool, size_t size,
    const char *file, ngx_uint_t line)
{
    if (ngx_http_cache_turbo_test_alloc_gate(pool, file, line) != NGX_OK) {
        return NULL;
    }

    return ngx_palloc(pool, size);
}


static ngx_inline void *
ngx_http_cache_turbo_ta_pnalloc(ngx_pool_t *pool, size_t size,
    const char *file, ngx_uint_t line)
{
    if (ngx_http_cache_turbo_test_alloc_gate(pool, file, line) != NGX_OK) {
        return NULL;
    }

    return ngx_pnalloc(pool, size);
}


static ngx_inline void *
ngx_http_cache_turbo_ta_pcalloc(ngx_pool_t *pool, size_t size,
    const char *file, ngx_uint_t line)
{
    if (ngx_http_cache_turbo_test_alloc_gate(pool, file, line) != NGX_OK) {
        return NULL;
    }

    return ngx_pcalloc(pool, size);
}


static ngx_inline void *
ngx_http_cache_turbo_ta_array_push(ngx_array_t *a, const char *file,
    ngx_uint_t line)
{
    if (ngx_http_cache_turbo_test_alloc_gate(a->pool, file, line) != NGX_OK) {
        return NULL;
    }

    return ngx_array_push(a);
}


static ngx_inline void *
ngx_http_cache_turbo_ta_array_push_n(ngx_array_t *a, ngx_uint_t n,
    const char *file, ngx_uint_t line)
{
    if (ngx_http_cache_turbo_test_alloc_gate(a->pool, file, line) != NGX_OK) {
        return NULL;
    }

    return ngx_array_push_n(a, n);
}


static ngx_inline void *
ngx_http_cache_turbo_ta_list_push(ngx_list_t *l, const char *file,
    ngx_uint_t line)
{
    if (ngx_http_cache_turbo_test_alloc_gate(l->pool, file, line) != NGX_OK) {
        return NULL;
    }

    return ngx_list_push(l);
}


static ngx_inline ngx_buf_t *
ngx_http_cache_turbo_ta_create_temp_buf(ngx_pool_t *pool, size_t size,
    const char *file, ngx_uint_t line)
{
    if (ngx_http_cache_turbo_test_alloc_gate(pool, file, line) != NGX_OK) {
        return NULL;
    }

    return ngx_create_temp_buf(pool, size);
}


static ngx_inline ngx_chain_t *
ngx_http_cache_turbo_ta_alloc_chain_link(ngx_pool_t *pool, const char *file,
    ngx_uint_t line)
{
    if (ngx_http_cache_turbo_test_alloc_gate(pool, file, line) != NGX_OK) {
        return NULL;
    }

    return ngx_alloc_chain_link(pool);
}


static ngx_inline ngx_pool_cleanup_t *
ngx_http_cache_turbo_ta_pool_cleanup_add(ngx_pool_t *p, size_t size,
    const char *file, ngx_uint_t line)
{
    if (ngx_http_cache_turbo_test_alloc_gate(p, file, line) != NGX_OK) {
        return NULL;
    }

    return ngx_pool_cleanup_add(p, size);
}


#define ngx_palloc(pool, size)                                                \
    ngx_http_cache_turbo_ta_palloc(pool, size, __FILE__, __LINE__)
#define ngx_pnalloc(pool, size)                                               \
    ngx_http_cache_turbo_ta_pnalloc(pool, size, __FILE__, __LINE__)
#define ngx_pcalloc(pool, size)                                               \
    ngx_http_cache_turbo_ta_pcalloc(pool, size, __FILE__, __LINE__)
#define ngx_array_push(a)                                                     \
    ngx_http_cache_turbo_ta_array_push(a, __FILE__, __LINE__)
#define ngx_array_push_n(a, n)                                                \
    ngx_http_cache_turbo_ta_array_push_n(a, n, __FILE__, __LINE__)
#define ngx_list_push(l)                                                      \
    ngx_http_cache_turbo_ta_list_push(l, __FILE__, __LINE__)
#define ngx_create_temp_buf(pool, size)                                       \
    ngx_http_cache_turbo_ta_create_temp_buf(pool, size, __FILE__, __LINE__)
#define ngx_alloc_chain_link(pool)                                            \
    ngx_http_cache_turbo_ta_alloc_chain_link(pool, __FILE__, __LINE__)
#define ngx_pool_cleanup_add(p, size)                                         \
    ngx_http_cache_turbo_ta_pool_cleanup_add(p, size, __FILE__, __LINE__)


#endif /* NGX_HTTP_CACHE_TURBO_TEST_FAULTS */

#endif /* NGX_HTTP_CACHE_TURBO_TESTALLOC_H_INCLUDED_ */
