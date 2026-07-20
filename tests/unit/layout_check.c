/*
 * Layout guard, REAL-HEADER side.
 *
 * The test binary mirrors ngx_rbtree_node_t / ngx_rbtree_t / ngx_queue_t
 * instead of including the real headers (which drag in the whole nginx type
 * universe -- see the comment in ngx_shim_shm.h). The real ngx_rbtree.c is
 * then linked in as a separate translation unit compiled against the GENUINE
 * headers.
 *
 * That means two TUs must agree on layout by hand. If they ever drift, the
 * failure mode is silent memory corruption at run time, NOT a compile error --
 * the linker happily pairs a call with a differently-shaped struct.
 *
 * The two views CANNOT be compared inside one TU: they declare the same type
 * names, so including both collides (hence INCS_TEST vs INCS_NGX in the
 * Makefile). Each side therefore asserts against the shared literals in
 * layout_expect.h:
 *
 *   THIS FILE          real nginx headers  -> real   == layout_expect.h
 *   test_shm_state.c   mirrored decls      -> mirror == layout_expect.h
 *
 * Transitively, real == mirror. Drift on either side fails the build at the
 * exact field. Asserting the real headers alone -- as an earlier revision of
 * this file did -- proves nothing about the mirror: a hand edit to
 * ngx_shim_shm.h would sail straight through.
 *
 * Compiled by `make layout-check`, which `make check` depends on.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <stddef.h>

#include "layout_expect.h"

NGX_CT_ASSERT_LAYOUTS("real nginx header:");

/* Not linked into the test binary; compiling this TU is the whole point. */
int ngx_cache_turbo_layout_check_ok(void);

int
ngx_cache_turbo_layout_check_ok(void)
{
    return 1;
}
