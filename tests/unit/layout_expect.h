/*
 * The ONE definition of the nginx aggregate layouts this harness depends on.
 *
 * The mirrored declarations in ngx_shim_shm.h and the genuine nginx headers can
 * never meet in a single translation unit -- they declare the same type names,
 * so including both collides (see INCS_TEST vs INCS_NGX in the Makefile). That
 * is why layout_check.c alone could not compare them: it sees only the real
 * headers, so pinning them to literals written in that same file proves nothing
 * about the mirror.
 *
 * Instead both sides assert against the literals HERE:
 *
 *   layout_check.c   (real headers)  -- includes this, asserts real == expected
 *   test_shm_state.c (mirrored decls) -- includes this, asserts mirror == expected
 *
 * Drift on EITHER side is then a build failure at the exact field:
 *   - upstream nginx changes a struct  -> layout_check.c fails
 *   - someone edits the mirror by hand -> test_shm_state.c fails
 *
 * The failure mode this guards is not a compile error by default: the linker
 * happily pairs a call in the test TU with a differently-shaped struct in the
 * real ngx_rbtree.c, and the result is silent memory corruption at run time.
 *
 * Sizes are expressed in pointer units because every field in these three
 * structs is pointer-sized or packs into the tail padding of one, on every ABI
 * this harness builds on (LP64 and ILP32 alike).
 */

#ifndef NGX_CACHE_TURBO_UNIT_LAYOUT_EXPECT_H
#define NGX_CACHE_TURBO_UNIT_LAYOUT_EXPECT_H

#include <stddef.h>

#define NGX_CT_PTR  (sizeof(void *))

/* ngx_rbtree_node_t: key + left + right + parent + (color,data) packed into a
 * final pointer-sized slot. */
#define NGX_CT_RBTREE_NODE_SIZE     (5 * NGX_CT_PTR)
#define NGX_CT_RBTREE_NODE_KEY      (0 * NGX_CT_PTR)
#define NGX_CT_RBTREE_NODE_LEFT     (1 * NGX_CT_PTR)
#define NGX_CT_RBTREE_NODE_RIGHT    (2 * NGX_CT_PTR)
#define NGX_CT_RBTREE_NODE_PARENT   (3 * NGX_CT_PTR)
#define NGX_CT_RBTREE_NODE_COLOR    (4 * NGX_CT_PTR)

/* ngx_rbtree_t: root + sentinel + insert callback. */
#define NGX_CT_RBTREE_SIZE          (3 * NGX_CT_PTR)
#define NGX_CT_RBTREE_ROOT          (0 * NGX_CT_PTR)
#define NGX_CT_RBTREE_SENTINEL      (1 * NGX_CT_PTR)
#define NGX_CT_RBTREE_INSERT        (2 * NGX_CT_PTR)

/* ngx_queue_t: prev + next. */
#define NGX_CT_QUEUE_SIZE           (2 * NGX_CT_PTR)
#define NGX_CT_QUEUE_PREV           (0 * NGX_CT_PTR)
#define NGX_CT_QUEUE_NEXT           (1 * NGX_CT_PTR)

/*
 * Assert one view (real or mirrored) against the expectations above. Both
 * includers expand this with the same type names -- which resolve to the real
 * structs in layout_check.c and to the mirrored ones in test_shm_state.c.
 *
 * `which` only distinguishes the two sides in the diagnostic text.
 */
#define NGX_CT_ASSERT_LAYOUTS(which)                                          \
                                                                              \
    _Static_assert(sizeof(ngx_rbtree_node_t) == NGX_CT_RBTREE_NODE_SIZE,      \
        which " ngx_rbtree_node_t size drifted from layout_expect.h");        \
    _Static_assert(offsetof(ngx_rbtree_node_t, key) == NGX_CT_RBTREE_NODE_KEY,\
        which " ngx_rbtree_node_t.key drifted from layout_expect.h");         \
    _Static_assert(offsetof(ngx_rbtree_node_t, left)                          \
        == NGX_CT_RBTREE_NODE_LEFT,                                           \
        which " ngx_rbtree_node_t.left drifted from layout_expect.h");        \
    _Static_assert(offsetof(ngx_rbtree_node_t, right)                         \
        == NGX_CT_RBTREE_NODE_RIGHT,                                          \
        which " ngx_rbtree_node_t.right drifted from layout_expect.h");       \
    _Static_assert(offsetof(ngx_rbtree_node_t, parent)                        \
        == NGX_CT_RBTREE_NODE_PARENT,                                         \
        which " ngx_rbtree_node_t.parent drifted from layout_expect.h");      \
    _Static_assert(offsetof(ngx_rbtree_node_t, color)                         \
        == NGX_CT_RBTREE_NODE_COLOR,                                          \
        which " ngx_rbtree_node_t.color drifted from layout_expect.h");       \
                                                                              \
    _Static_assert(sizeof(ngx_rbtree_t) == NGX_CT_RBTREE_SIZE,                \
        which " ngx_rbtree_t size drifted from layout_expect.h");             \
    _Static_assert(offsetof(ngx_rbtree_t, root) == NGX_CT_RBTREE_ROOT,        \
        which " ngx_rbtree_t.root drifted from layout_expect.h");             \
    _Static_assert(offsetof(ngx_rbtree_t, sentinel)                           \
        == NGX_CT_RBTREE_SENTINEL,                                            \
        which " ngx_rbtree_t.sentinel drifted from layout_expect.h");         \
    _Static_assert(offsetof(ngx_rbtree_t, insert) == NGX_CT_RBTREE_INSERT,    \
        which " ngx_rbtree_t.insert drifted from layout_expect.h");           \
                                                                              \
    _Static_assert(sizeof(ngx_queue_t) == NGX_CT_QUEUE_SIZE,                  \
        which " ngx_queue_t size drifted from layout_expect.h");              \
    _Static_assert(offsetof(ngx_queue_t, prev) == NGX_CT_QUEUE_PREV,          \
        which " ngx_queue_t.prev drifted from layout_expect.h");              \
    _Static_assert(offsetof(ngx_queue_t, next) == NGX_CT_QUEUE_NEXT,          \
        which " ngx_queue_t.next drifted from layout_expect.h")

#endif /* NGX_CACHE_TURBO_UNIT_LAYOUT_EXPECT_H */
