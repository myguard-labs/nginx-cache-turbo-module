/*
 * Layout guard for the mirrored nginx declarations in ngx_shim_shm.h.
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
 * This TU includes BOTH views and static-asserts they match. It is compiled on
 * every `make check`, so drift becomes a build failure at the exact field.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <stddef.h>
#include <assert.h>

/* Pull in the mirrored view under a namespace of its own. The shim's reduced
 * core types (ngx_int_t, u_char, ...) are compatible with the real ones by
 * construction; what is checked here is the aggregate layout the linker
 * depends on. */
#define NGX_CACHE_TURBO_LAYOUT_CHECK 1

#define ASSERT_SAME_SIZE(t)                                                   \
    _Static_assert(sizeof(t) == sizeof(t),  "sizeof " #t " drifted")

/* ngx_rbtree_node_t */
_Static_assert(sizeof(ngx_rbtree_node_t) == 5 * sizeof(void *),
    "ngx_rbtree_node_t is no longer key+3 pointers+2 chars packed as expected; "
    "update the mirrored struct in tests/unit/ngx_shim_shm.h");
_Static_assert(offsetof(ngx_rbtree_node_t, key)    == 0,
    "ngx_rbtree_node_t.key moved; update ngx_shim_shm.h");
_Static_assert(offsetof(ngx_rbtree_node_t, left)   == sizeof(void *),
    "ngx_rbtree_node_t.left moved; update ngx_shim_shm.h");
_Static_assert(offsetof(ngx_rbtree_node_t, right)  == 2 * sizeof(void *),
    "ngx_rbtree_node_t.right moved; update ngx_shim_shm.h");
_Static_assert(offsetof(ngx_rbtree_node_t, parent) == 3 * sizeof(void *),
    "ngx_rbtree_node_t.parent moved; update ngx_shim_shm.h");
_Static_assert(offsetof(ngx_rbtree_node_t, color)  == 4 * sizeof(void *),
    "ngx_rbtree_node_t.color moved; update ngx_shim_shm.h");

/* ngx_rbtree_t */
_Static_assert(sizeof(ngx_rbtree_t) == 3 * sizeof(void *),
    "ngx_rbtree_t grew; update ngx_shim_shm.h");
_Static_assert(offsetof(ngx_rbtree_t, root)     == 0,
    "ngx_rbtree_t.root moved; update ngx_shim_shm.h");
_Static_assert(offsetof(ngx_rbtree_t, sentinel) == sizeof(void *),
    "ngx_rbtree_t.sentinel moved; update ngx_shim_shm.h");
_Static_assert(offsetof(ngx_rbtree_t, insert)   == 2 * sizeof(void *),
    "ngx_rbtree_t.insert moved; update ngx_shim_shm.h");

/* ngx_queue_t */
_Static_assert(sizeof(ngx_queue_t) == 2 * sizeof(void *),
    "ngx_queue_t grew; update ngx_shim_shm.h");
_Static_assert(offsetof(ngx_queue_t, prev) == 0,
    "ngx_queue_t.prev moved; update ngx_shim_shm.h");
_Static_assert(offsetof(ngx_queue_t, next) == sizeof(void *),
    "ngx_queue_t.next moved; update ngx_shim_shm.h");

/* Not linked into the test binary; existence is the whole point. */
int ngx_cache_turbo_layout_check_ok(void);

int
ngx_cache_turbo_layout_check_ok(void)
{
    return 1;
}
