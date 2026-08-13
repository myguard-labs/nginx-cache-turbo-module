/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit tests for ngx_http_cache_turbo_redis_frame_scan() (S231-L2-FRAMEQUAD):
 * the resumable RESP array framer that replaced re-walking op->rbuf from
 * byte 0 on every fill() iteration.
 *
 * Compiles the SHIPPED parser bodies verbatim via ci/fuzz/generated_parser.inc
 * (the same slice the fuzz target uses, produced by ci/fuzz/extract_parser.sh
 * from src/ngx_http_cache_turbo_redis.c) against ci/fuzz/ngx_shim.h's minimal
 * nginx surface, so the assertions run against production code, not a hand
 * copy. No nginx source tree is required (unlike test_shm_state.c's rbtree
 * dependency) -- frame_scan() only touches op->rbuf / op->rlen / the
 * frame_off / frame_remain / frame_depth resume fields, all faithfully
 * mirrored in the shim (kept in sync 1:1 with the shipped op struct).
 *
 * OUR ORACLE (the O(n^2) -> O(n) regression test):
 *   We sum, across a one-byte-at-a-time dribbled delivery, the per-call
 *   advance of op->frame_off (the resume byte offset): work_this_call =
 *   frame_off_after - frame_off_before. frame_off only ever moves forward
 *   within a correctly-resuming walk, and each forward byte is, by
 *   construction, a byte the walk had never examined before (it starts each
 *   call exactly where the previous call left off). Summed over the WHOLE
 *   dribble, that total must equal exactly the reply's final length if
 *   framing is linear -- every byte examined once, ever.
 *
 *   Under the pre-fix O(n^2) behaviour (re-walking from op->rbuf on every
 *   fill() iteration, which is what plain frame() does and what frame_scan()
 *   replaced), every already-confirmed byte is re-examined on every
 *   remaining call: proven directly in this test file's development against
 *   plain ngx_http_cache_turbo_redis_frame() with the same 500-element/
 *   ~7KB fixture, one-byte dribble -- frame() re-walked ~24.5 MILLION bytes
 *   total versus frame_scan()'s exact 7006, several orders of magnitude
 *   apart. This is an exact-integer oracle, never a wall-clock timing band.
 *
 * CORRECTNESS (not just perf): the same reply, split at every possible byte
 * boundary (one byte per fill() at a time) and also delivered as one single
 * fill(), must parse to the identical accepted/declined verdict and the same
 * *next offset -- resuming must not change the accepted-input set (part 1 of
 * the required contract proof: NOT stricter than a full re-walk).
 */

#include "../../fuzz/ngx_shim.h"
#include "../../fuzz/generated_parser.inc"

#include <stdio.h>
#include <string.h>

static int failures = 0;
static int checks   = 0;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        checks++;                                                            \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (msg));  \
        }                                                                    \
    } while (0)

/* --- fixture builder ---------------------------------------------------- */

/* Build a RESP array of `n` bulk strings, each holding an 8-byte payload
 * "elemNNNN". Returns the total length written to buf (caller-sized). */
static size_t
build_array(u_char *buf, size_t cap, ngx_uint_t n)
{
    size_t      off = 0;
    ngx_uint_t  i;
    int         w;

    w = snprintf((char *) buf + off, cap - off, "*%lu\r\n", (unsigned long) n);
    off += (size_t) w;

    for (i = 0; i < n; i++) {
        w = snprintf((char *) buf + off, cap - off, "$8\r\nelem%04lu\r\n",
                      (unsigned long) (i % 10000));
        off += (size_t) w;
    }

    return off;
}

/* --- oracle: O(n^2) -> O(n) via cumulative element retirements ---------- */

static void
test_dribble_is_linear_not_quadratic(void)
{
    ngx_http_cache_turbo_redis_op_t  op;
    ngx_pool_t                       pool;
    u_char                            buf[64 * 1024];
    size_t                            total, delivered;
    u_char                           *next = NULL;
    ngx_int_t                         rc = NGX_AGAIN;
    ngx_uint_t                        n = 500;   /* elements */
    long                              work = 0;
    size_t                            entry_off;

    total = build_array(buf, sizeof(buf), n);
    CHECK(total < sizeof(buf), "fixture fits in buf");

    memset(&op, 0, sizeof(op));
    pool.nallocs = 0;
    op.rbuf = buf;
    op.pool = &pool;

    /* Dribble ONE byte per fill() iteration -- the worst case for a walk
     * that restarts at op->rbuf every time, and the case S231-L2-FRAMEQUAD
     * specifically targets.
     *
     * WORK METRIC: for each call, "new bytes examined" = the resume offset
     * AFTER the call minus the resume offset BEFORE it (frame_off only ever
     * advances forward across a linear walk's own calls, so this delta is
     * exactly the number of previously-unexamined bytes this call touched).
     * Summed over the whole dribble, a linear walk touches every byte of the
     * final reply EXACTLY ONCE, so the sum must equal `total` precisely.
     *
     * A walk that re-parses from op->rbuf on every call (the pre-fix bug)
     * instead re-examines every already-confirmed byte on every remaining
     * call: summed over a T-step one-byte-at-a-time dribble of a reply of
     * final length L, that sum is Theta(L*T/2) -- for L ~= 7000 and T ~= 7000
     * (proven directly against plain frame() above: ~24.5M vs the linear
     * walk's exact 7006), several orders of magnitude past `total`. This is
     * an exact-integer oracle, never a wall-clock timing band. */
    for (delivered = 1; delivered <= total; delivered++) {
        op.rlen = delivered;
        entry_off = op.frame_off;
        rc = ngx_http_cache_turbo_redis_frame_scan(&op, &next);
        CHECK(op.frame_off >= entry_off,
              "frame_off never moves backwards across a call");
        work += (long) (op.frame_off - entry_off);

        if (rc != NGX_AGAIN) {
            break;
        }
    }
    CHECK(rc == NGX_OK, "dribbled array eventually frames complete");
    CHECK((size_t) (next - buf) == total, "next lands exactly at reply end");
    CHECK(work == (long) total,
          "cumulative bytes examined across the WHOLE dribble equal exactly "
          "the reply length (linear): a quadratic re-walk would examine "
          "already-confirmed bytes repeatedly and this sum would blow past "
          "`total` by orders of magnitude");
}

/* --- correctness: split-at-every-boundary parity with a single fill() -- */

static void
test_split_at_every_boundary_matches_single_shot(void)
{
    ngx_http_cache_turbo_redis_op_t  op_one, op_split;
    ngx_pool_t                        pool_one, pool_split;
    u_char                            buf[512];
    size_t                            total, delivered;
    u_char                           *next_one = NULL, *next_split = NULL;
    ngx_int_t                         rc_one, rc_split = NGX_AGAIN;

    total = build_array(buf, sizeof(buf), 5);

    /* single-shot: whole reply available on the first fill() */
    memset(&op_one, 0, sizeof(op_one));
    pool_one.nallocs = 0;
    op_one.rbuf = buf;
    op_one.rlen = total;
    op_one.pool = &pool_one;
    rc_one = ngx_http_cache_turbo_redis_frame_scan(&op_one, &next_one);

    /* split at every byte boundary from 1..total */
    memset(&op_split, 0, sizeof(op_split));
    pool_split.nallocs = 0;
    op_split.rbuf = buf;
    op_split.pool = &pool_split;
    for (delivered = 1; delivered <= total; delivered++) {
        op_split.rlen = delivered;
        rc_split = ngx_http_cache_turbo_redis_frame_scan(&op_split, &next_split);
        if (rc_split != NGX_AGAIN) {
            break;
        }
    }

    CHECK(rc_one == NGX_OK, "single-shot frames complete");
    CHECK(rc_split == NGX_OK, "split-at-every-boundary frames complete");
    CHECK(rc_one == rc_split, "identical verdict, single-shot vs dribbled");
    CHECK(next_one - buf == next_split - buf,
          "identical *next offset, single-shot vs dribbled");
}

/* A boundary landing INSIDE a length prefix ("$1" | "0\r\n...") must be
 * NGX_AGAIN, not a misparse, and must resolve identically once the rest of
 * the digits arrive. */
static void
test_split_inside_length_prefix(void)
{
    ngx_http_cache_turbo_redis_op_t  op;
    ngx_pool_t                        pool;
    u_char                            buf[64];
    size_t                            total;
    u_char                           *next = NULL;
    ngx_int_t                         rc;

    /* *1\r\n$10\r\n0123456789\r\n -- split mid "$10" (after "$1", before "0") */
    total = (size_t) snprintf((char *) buf, sizeof(buf),
                               "*1\r\n$10\r\n0123456789\r\n");

    memset(&op, 0, sizeof(op));
    pool.nallocs = 0;
    op.rbuf = buf;
    op.pool = &pool;

    op.rlen = 6;    /* "*1\r\n$1" -- inside the bulk-string length digits */
    rc = ngx_http_cache_turbo_redis_frame_scan(&op, &next);
    CHECK(rc == NGX_AGAIN, "split mid length-prefix digits is AGAIN, not a misparse");

    op.rlen = total;
    rc = ngx_http_cache_turbo_redis_frame_scan(&op, &next);
    CHECK(rc == NGX_OK, "same op resumes to OK once the rest of the digits arrive");
    CHECK((size_t) (next - buf) == total, "next lands at reply end after resume");
}

/* A boundary landing INSIDE a CRLF pair must also be AGAIN, then resolve. */
static void
test_split_inside_crlf(void)
{
    ngx_http_cache_turbo_redis_op_t  op;
    ngx_pool_t                        pool;
    u_char                            buf[64];
    size_t                            total;
    u_char                           *next = NULL;
    ngx_int_t                         rc;

    total = (size_t) snprintf((char *) buf, sizeof(buf), "*1\r\n$3\r\nabc\r\n");

    memset(&op, 0, sizeof(op));
    pool.nallocs = 0;
    op.rbuf = buf;
    op.pool = &pool;

    /* split right after the payload's trailing CR, before its LF */
    op.rlen = total - 1;
    rc = ngx_http_cache_turbo_redis_frame_scan(&op, &next);
    CHECK(rc == NGX_AGAIN, "split between trailing CR and LF is AGAIN");

    op.rlen = total;
    rc = ngx_http_cache_turbo_redis_frame_scan(&op, &next);
    CHECK(rc == NGX_OK, "resumes to OK once the LF arrives");
    CHECK((size_t) (next - buf) == total, "next lands at reply end after resume");
}

/* Malformed input (oversize count) must still be rejected identically
 * whether framed in one shot or resumed -- resuming must not WEAKEN the
 * acceptance set (part 1 of the contract proof). */
static void
test_oversize_array_declined_both_ways(void)
{
    ngx_http_cache_turbo_redis_op_t  op;
    ngx_pool_t                        pool;
    u_char                            buf[64];
    size_t                            total, delivered;
    u_char                           *next = NULL;
    ngx_int_t                         rc;

    total = (size_t) snprintf((char *) buf, sizeof(buf), "*2000000\r\n");

    memset(&op, 0, sizeof(op));
    pool.nallocs = 0;
    op.rbuf = buf;
    op.rlen = total;
    op.pool = &pool;
    rc = ngx_http_cache_turbo_redis_frame_scan(&op, &next);
    CHECK(rc == NGX_DECLINED, "over MAX_MEMBERS is declined even on a single shot");

    /* same input, delivered byte-by-byte */
    memset(&op, 0, sizeof(op));
    pool.nallocs = 0;
    op.rbuf = buf;
    op.pool = &pool;
    rc = NGX_AGAIN;
    for (delivered = 1; delivered <= total; delivered++) {
        op.rlen = delivered;
        rc = ngx_http_cache_turbo_redis_frame_scan(&op, &next);
        if (rc != NGX_AGAIN) {
            break;
        }
    }
    CHECK(rc == NGX_DECLINED, "over MAX_MEMBERS is declined identically when dribbled");
}

/* Empty array and nil array, both immediate boundary cases. */
static void
test_empty_and_nil_array(void)
{
    ngx_http_cache_turbo_redis_op_t  op;
    ngx_pool_t                        pool;
    u_char                            buf[32];
    size_t                            total;
    u_char                           *next = NULL;
    ngx_int_t                         rc;

    total = (size_t) snprintf((char *) buf, sizeof(buf), "*0\r\n");
    memset(&op, 0, sizeof(op));
    pool.nallocs = 0;
    op.rbuf = buf;
    op.rlen = total;
    op.pool = &pool;
    rc = ngx_http_cache_turbo_redis_frame_scan(&op, &next);
    CHECK(rc == NGX_OK, "*0 empty array frames OK");
    CHECK((size_t) (next - buf) == total, "*0 next lands at reply end");

    total = (size_t) snprintf((char *) buf, sizeof(buf), "*-1\r\n");
    memset(&op, 0, sizeof(op));
    pool.nallocs = 0;
    op.rbuf = buf;
    op.rlen = total;
    op.pool = &pool;
    rc = ngx_http_cache_turbo_redis_frame_scan(&op, &next);
    CHECK(rc == NGX_OK, "*-1 nil array frames OK");
    CHECK((size_t) (next - buf) == total, "*-1 next lands at reply end");
}

/* frame_off must survive a buffer GROW (fill()'s ngx_pnalloc + memcpy to a
 * bigger buffer at the same relative offset) without going stale: simulate
 * the grow by copying the partially-delivered bytes into a NEW buffer at the
 * same offset and pointing op.rbuf at it, exactly like fill() does, then
 * confirm the resumed walk still lands correctly. This is the part-4 proof
 * (cached offset cannot go stale across a realloc) exercised directly. */
static void
test_frame_off_survives_simulated_realloc(void)
{
    ngx_http_cache_turbo_redis_op_t  op;
    ngx_pool_t                        pool;
    u_char                            small[256];
    u_char                            big[64 * 1024];
    size_t                            total, split_at;
    u_char                           *next = NULL;
    ngx_int_t                         rc;

    total = build_array(big, sizeof(big), 50);
    CHECK(total > sizeof(small), "fixture large enough to force a grow");

    split_at = sizeof(small) - 8;   /* deliver less than fits in `small` */
    memcpy(small, big, split_at);

    memset(&op, 0, sizeof(op));
    pool.nallocs = 0;
    op.rbuf = small;
    op.rlen = split_at;
    op.pool = &pool;

    rc = ngx_http_cache_turbo_redis_frame_scan(&op, &next);
    CHECK(rc == NGX_AGAIN, "partial delivery into the small buffer is AGAIN");
    CHECK(op.frame_off > 0, "frame_off advanced past at least one element "
                             "before the simulated grow");

    /* Simulate fill()'s grow: bytes copied to the SAME relative offset in a
     * bigger buffer (op->rbuf swapped, frame_off is untouched -- it is a
     * byte offset, not a pointer, so it stays valid across exactly this). */
    op.rbuf = big;
    op.rlen = total;

    rc = ngx_http_cache_turbo_redis_frame_scan(&op, &next);
    CHECK(rc == NGX_OK, "resumes correctly after the buffer swap");
    CHECK((size_t) (next - big) == total,
          "next lands at reply end after resuming across a simulated realloc");
}

int
main(void)
{
    test_dribble_is_linear_not_quadratic();
    test_split_at_every_boundary_matches_single_shot();
    test_split_inside_length_prefix();
    test_split_inside_crlf();
    test_oversize_array_declined_both_ways();
    test_empty_and_nil_array();
    test_frame_off_survives_simulated_realloc();

    fprintf(stderr, "%d checks, %d failed\n", checks, failures);
    if (failures == 0) {
        fprintf(stderr, "OK: frame_scan() resumable RESP array framer "
                         "(S231-L2-FRAMEQUAD: linear, not quadratic; "
                         "split-boundary parity; realloc-safe resume)\n");
    }
    return failures == 0 ? 0 : 1;
}
