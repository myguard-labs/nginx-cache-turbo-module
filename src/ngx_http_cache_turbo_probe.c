/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_http_cache_turbo_probe.c -- nginx-module-testkit probe integration.
 *
 * WHAT THIS IS FOR
 *   testkit's prober grew a cross-process shared-memory invariant lens
 *   (`fanout` / `quiesce` / `zone_invariant`, testkit PR #220). That lens is
 *   the only oracle in this project's toolbox that can see the module's real
 *   race class: nginx workers are fork()ed processes sharing an mmap guarded
 *   by ngx_shmtx, which helgrind and TSan both structurally cannot model --
 *   they reason about pthread primitives inside ONE address space.
 *
 *   The lens needs one thing from a consumer: a shared counter it can read
 *   from several workers at once. testkit's own reference module has none, so
 *   all three `zone_invariant` forms are TAUTOLOGICALLY green there and its
 *   shm-coherence scenario deliberately asserts none of them. This file is the
 *   real home of that coverage: it renders this module's own zone counters
 *   into the probe document so ci/prober-scenarios/shm-coherence-varidx/ can
 *   assert on them and, when the counters are wrong, go red.
 *
 * WHY IT IS NOT A COMPILE-TIME DEPENDENCY OF THE SHIPPING MODULE
 *   The whole file is inside `#ifdef NGX_TEST_HARNESS`, and the #include of
 *   testkit's header is inside that guard too. In every build this repo ships
 *   -- packages, ci-build.sh, the runtime suite -- NGX_TEST_HARNESS is
 *   undefined, this translation unit compiles to nothing, and testkit's
 *   headers are never opened. The .so is byte-identical to one built without
 *   the file in the source list.
 *
 *   The macro is defined ONLY by testkit's t/module/config, which appends
 *   -DNGX_TEST_HARNESS to the global CFLAGS of the tree it is configured into.
 *   ci/tools/testkit-stage.sh is the sole caller that configures both modules
 *   into one tree, so "harness build" and "staged by testkit-stage.sh" are the
 *   same set of builds. No --with-cc-opt of our own is needed or wanted: a
 *   second way to turn the probe on is a second way to turn it on by accident.
 *
 *   The include path likewise costs nothing normally. `config` adds testkit's
 *   src/ to ngx_module_incs only when $TESTKIT_ROOT names a real checkout, so
 *   an ordinary build has no such -I and no such dependency.
 *
 * WHY THE DIRECTIVE IS OURS AND NOT test_ref_probe
 *   testkit's ref module points ngx_test_probe_json() at ITS OWN zone (NULL in
 *   every scenario but one). A probe aimed at a zone this module did not
 *   create renders "zone":{"present":false} and never reaches the zone_render
 *   dispatch at all -- the hook would be registered, linked, and never called
 *   once. So the probe location has to be served by a handler that passes OUR
 *   ngx_shm_zone_t, which means our own directive.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifdef NGX_TEST_HARNESS

#include "ngx_test_probe.h"

#include "ngx_http_cache_turbo_module.h"


static u_char *ngx_http_cache_turbo_probe_zone_render(u_char *buf,
    u_char *last, ngx_shm_zone_t *zone);
static ngx_int_t ngx_http_cache_turbo_probe_handler(ngx_http_request_t *r);


/*
 * The zone the probe location was pointed at.
 *
 * A single file-scope pointer rather than a loc_conf member: the handler needs
 * it, the directive is the only writer, and it is set in the master before any
 * worker forks -- so every worker inherits the same value and nothing here
 * races. A loc_conf member would be the tidier shape in a shipping directive,
 * but this whole file exists only under NGX_TEST_HARNESS and adding a member
 * to ngx_http_cache_turbo_loc_conf_t would change that struct's layout between
 * a harness build and a shipping build. That is exactly the kind of
 * conditional ABI divergence that makes a harness build stop being a faithful
 * proxy for the real one.
 */
static ngx_shm_zone_t  *ngx_http_cache_turbo_probe_zone;


/*
 * FROZEN STRUCT, POSITIONAL INITIALISATION.
 *
 * ngx_test_probe_hooks_t is documented as frozen and its consumers initialise
 * it positionally; testkit's header states that appending a member there would
 * be a build failure in every downstream repo under -Wextra -Werror, which is
 * why the zone-independent hooks live in a SECOND struct instead. Following
 * the documented convention rather than designated initialisers keeps this
 * file in the same shape as the other consumers, so a future member addition
 * breaks here the same way it breaks there -- loudly, at compile time.
 *
 * fault_set is NULL: this module has no probe-armed fault sites. The probe
 * treats that exactly as "no such site" and refuses a fault_* query rather
 * than reporting one applied.
 */
static const ngx_test_probe_hooks_t  ngx_http_cache_turbo_probe_hooks = {
    ngx_http_cache_turbo_probe_zone_render,
    NULL
};


void
ngx_http_cache_turbo_probe_hooks_register(void)
{
    ngx_test_probe_register(&ngx_http_cache_turbo_probe_hooks);
}


/*
 * Append this module's shared counters to the probe's "zone" object.
 *
 * CONTRACT (ngx_test_probe_hooks_t): the generic members are already rendered
 * and the object is still open, so this leads with a comma, does NOT close the
 * brace, renders only through ngx_slprintf against `last`, and returns the new
 * `last`. Called WITHOUT the slab mutex held -- the hook owns its own locking.
 *
 * WHY NO LOCK IS TAKEN HERE
 *   Every field read below is an ngx_atomic_t read through
 *   ngx_atomic_fetch_add(&f, 0), which is the module's own established
 *   spelling for "atomic load" (purge.c:169, module.c:1973, admin.c:332). Not
 *   one of them is part of a multi-word invariant that a reader must see
 *   atomically as a group, so there is nothing for the zone mutex to protect
 *   that the atomics do not already. Taking it would be worse than useless: it
 *   would serialise the probe against the very request traffic the fanout is
 *   trying to observe, and the counters would then be sampled at moments the
 *   lens itself created.
 *
 * WHICH FIELDS, AND WHICH INVARIANT FORM EACH ONE FEEDS
 *
 *   varidx_inflight -- the `at_rest` oracle, and the reason this file exists.
 *     Incremented in redis_tag_add_many() immediately before a varidx op is
 *     launched (redis.c:1706) and decremented in redis_op_done(), which every
 *     completion and every failure path funnels through (redis.c:1715, :3515).
 *     Its resting value is therefore 0, and a strand -- a launch whose
 *     completion never decremented -- leaves it above 0 forever. That is
 *     COR-5's defect class (PR #443), which until now had no automated guard
 *     at all. Paired with a `quiesce` in the rule so the reading is taken
 *     after the counter stopped moving rather than at an arbitrary instant.
 *
 *   hits / misses / lookups -- the `monotonic` oracle.
 *     varidx_inflight is deliberately NOT the monotonic field: it goes both up
 *     and down by design, so asserting it never decreases would be asserting a
 *     falsehood and the form would fire on correct behaviour. A monotonic
 *     oracle needs a field that is genuinely non-decreasing, and `lookups` is
 *     one by construction: hits and misses are lifetime tallies, only ever
 *     ngx_atomic_fetch_add(+1) (access.c:301,320,380,403,461,928,2443,2855,
 *     2908,2953,3054,3088,3107,3143), zeroed exactly once when a fresh zone is
 *     carved (shm.c:172-173) and never reset thereafter -- a reload inherits
 *     the live shm rather than re-initialising it. The sum is rendered as its
 *     own field rather than left for the rule to add, because `zone_invariant`
 *     takes ONE field path and cannot compute over two.
 *
 *   ct_digest -- the `coherent` oracle.
 *     The generic zone.digest already exists, but it is derived from SLAB
 *     bookkeeping and so proves coherence of nginx's allocator, not of this
 *     module's own counters. A worker whose view of the module's shared
 *     struct had diverged -- a per-worker copy that drifted, a write that
 *     never reached the shared page -- would still agree with its siblings on
 *     zone.digest while disagreeing about every field above. Folding the
 *     module fields into one value makes that disagreement one rule line wide,
 *     which is the same argument testkit's header makes for zone.digest
 *     itself.
 *
 *     Mixed with small odd multipliers so that a compensating pair of errors
 *     (one counter high by k, another low by k) still moves the digest.
 *     Truncated to 31 bits so it renders as a non-negative %i and stays clear
 *     of the probe's own negative-reading refusal, which treats a negative
 *     value as an unavailable sentinel rather than a datum.
 */
static u_char *
ngx_http_cache_turbo_probe_zone_render(u_char *buf, u_char *last,
    ngx_shm_zone_t *zone)
{
    ngx_uint_t                     inflight, hits, misses, lookups, digest;
    ngx_http_cache_turbo_zone_t   *z;

    /*
     * The probe reaches present:true off shm.addr alone, so it can call this
     * for a zone whose init() has not run -- and after a failed init, z->sh is
     * NULL while shm.addr is not. Rendering nothing is the honest answer: the
     * rule's fields are then absent from the document and the prober reports
     * an unavailable reading, which is a FAILURE in every form. Substituting
     * zeros here would satisfy `at_rest == 0` on a zone that never
     * initialised.
     */
    if (zone == NULL || zone->data == NULL) {
        return buf;
    }

    z = zone->data;

    if (z->nstripes == 0 || ngx_http_cache_turbo_zone_sh(z) == NULL) {
        return buf;
    }

    inflight = (ngx_uint_t) ngx_atomic_fetch_add(
                   &ngx_http_cache_turbo_zone_sh(z)->varidx_inflight, 0);
    hits     = (ngx_uint_t) ngx_atomic_fetch_add(
                   &ngx_http_cache_turbo_zone_sh(z)->hits, 0);
    misses   = (ngx_uint_t) ngx_atomic_fetch_add(
                   &ngx_http_cache_turbo_zone_sh(z)->misses, 0);

    lookups = hits + misses;

    digest = (inflight * 31 + hits * 131 + misses * 8191 + lookups * 65521)
             & 0x7fffffff;

    return ngx_slprintf(buf, last,
                        ",\"varidx_inflight\":%ui"
                        ",\"hits\":%ui"
                        ",\"misses\":%ui"
                        ",\"lookups\":%ui"
                        ",\"ct_digest\":%ui",
                        inflight, hits, misses, lookups, digest);
}


/*
 * `cache_turbo_probe <zone>;` -- location level, harness builds only.
 *
 * Binds the probe location to a cache_turbo zone and installs the handler.
 * The zone is looked up with ngx_shared_memory_add() exactly as
 * `cache_turbo <zone>;` does, so naming a zone no cache_turbo_zone declared is
 * caught by nginx's own "zone was not defined" at the end of configuration
 * rather than by a NULL deref here.
 */
char *
ngx_http_cache_turbo_probe(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                 *value;
    ngx_shm_zone_t            *shm_zone;
    ngx_http_core_loc_conf_t  *core_lcf;

    value = cf->args->elts;

    if (ngx_http_cache_turbo_probe_zone != NULL) {
        return "is duplicate";
    }

    shm_zone = ngx_shared_memory_add(cf, &value[1], 0,
                                     &ngx_http_cache_turbo_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_http_cache_turbo_probe_zone = shm_zone;

    core_lcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    core_lcf->handler = ngx_http_cache_turbo_probe_handler;

    return NGX_CONF_OK;
}


/*
 * The directive handler, reached from the ONE entry appended to
 * ngx_http_cache_turbo_commands[] in module.c under the same NGX_TEST_HARNESS
 * guard. It is a member of the module's own command array rather than a
 * second array of its own because nginx binds exactly one ngx_command_t[] per
 * ngx_module_t; a separate array here would compile, link, and never be read.
 */
/*
 * Content handler: render the probe snapshot as JSON.
 *
 * Buffer sizing: NGX_TEST_PROBE_JSON_MAX covers the generic document; the zone
 * name is rendered escaped (up to 6x raw, \u00XX being the longest expansion)
 * and this hook appends five decimal integers. 256 bytes for the hook is far
 * past five ngx_uint_t at their widest. Undersizing truncates the JSON --
 * ngx_slprintf stops at `last` -- which surfaces as a parse error on EVERY
 * case rather than a wrong assertion on one, so it is deliberately oversized.
 */
static ngx_int_t
ngx_http_cache_turbo_probe_handler(ngx_http_request_t *r)
{
    u_char       *buf, *last;
    size_t        len, size;
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t   out;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    /*
     * Discard the body before answering. An unread body stays in the
     * connection buffer and the next request on a keepalive connection parses
     * it as its request line.
     */
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    size = NGX_TEST_PROBE_JSON_MAX + 256;
    if (ngx_http_cache_turbo_probe_zone != NULL) {
        size += ngx_http_cache_turbo_probe_zone->shm.name.len * 6 + 64;
    }

    buf = ngx_pnalloc(r->pool, size);
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    last = ngx_test_probe_json(buf, buf + size,
                               ngx_http_cache_turbo_probe_zone);
    len = (size_t) (last - buf);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = (off_t) len;

    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_lowcase = NULL;

    if (r->method == NGX_HTTP_HEAD) {
        return ngx_http_send_header(r);
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last = ngx_cpymem(b->pos, buf, len);
    b->memory = 1;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

#endif /* NGX_TEST_HARNESS */
