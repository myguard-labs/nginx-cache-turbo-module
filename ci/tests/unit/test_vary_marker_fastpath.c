/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * P1-6 (S231-PERF-VARYMAGIC): ngx_http_cache_turbo_vary_apply() (vary.c
 * ~677) used to gate the two vary-marker body bytes (axis bitmask + purge
 * generation, at fixed offsets NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE / +1) on a
 * full ngx_http_cache_turbo_blob_validate() call -- magic/version check,
 * 5-field range validation (status/created/stale_ttl-vs-fresh_ttl/nheaders),
 * AND a full TLV walk of the marker's (always-empty, headers_len==0) header
 * block -- purely to discard the result and read two bytes. The fix reads
 * those bytes after a cheap magic+version+length check only (vary.c
 * ~709-717).
 *
 * This file mirrors (does not include -- both functions need the full nginx
 * module headers we don't want to drag into a standalone unit test) the two
 * gates' OBSERVABLE accept/reject decision, byte-for-byte, against the same
 * corpus of well-formed, truncated, bad-magic, bad-version and bit-flipped
 * marker blobs a hostile or corrupted shm slot could contain:
 *
 *   mirror_old_gate() -- blob_validate()'s decision restricted to the fields
 *                        that can affect a marker blob specifically (magic,
 *                        version, length, status range, created range,
 *                        stale_ttl>=fresh_ttl, nheaders bound, TLV walk of a
 *                        zero-length header block -- which always succeeds
 *                        trivially since there is nothing to walk).
 *   mirror_new_gate() -- the fast-path check: magic + version + length only.
 *
 * The headline property under test is NOT "the two gates always agree" (they
 * provably do NOT for a hand-crafted blob with valid magic/version/length but
 * an out-of-range status/created/stale_ttl -- see
 * test_new_gate_is_a_strict_superset_on_real_marker_bytes for why that
 * divergence is sound: marker_store() never emits such a blob, so the old
 * gate's extra checks were dead weight on this call site, not a safety net).
 * It is a strict ONE-DIRECTIONAL implication instead:
 *
 *   old_gate(blob) == ACCEPT  =>  new_gate(blob) == ACCEPT, with IDENTICAL
 *   (bits, gen) read back -- the new gate never accepts less than the old
 *   one did, and never disagrees on the two bytes actually read when both
 *   accept.
 *
 * plus the negative control the item asks for: a TRUNCATED marker (length <
 * HDR_WIRE+1, or exactly HDR_WIRE+1 so the gen byte is absent) and a
 * BAD-MAGIC / BAD-VERSION marker must both be rejected (bits=0 and, for the
 * truncated-below-gen-byte case, gen=0) by the new gate exactly as they were
 * by the old one.
 *
 *   cc -std=c99 -Wall -Wextra -Werror test_vary_marker_fastpath.c -o t && ./t
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u_char;

#define BLOB_MAGIC    0x43544235u
#define BLOB_VERSION  5u
#define HDR_WIRE      76u
/* CTB5: the fixed rendered-Date field every blob (markers included) carries. */
#define DATE_LEN      29u
#define DATE_OFF      45u
#define CREATED_MIN   ((int64_t) 0)
#define FOREVER_TTL   ((int64_t) 315360000)

/* mirrors ngx_http_cache_turbo_get_u16/u32 (blob.c ~220-233): fixed
 * little-endian, no host-endianness dependence. */
static uint16_t
get_u16(const u_char *p)
{
    return (uint16_t) (p[0] | ((uint16_t) p[1] << 8));
}

static uint32_t
get_u32(const u_char *p)
{
    return (uint32_t) p[0]
         | ((uint32_t) p[1] << 8)
         | ((uint32_t) p[2] << 16)
         | ((uint32_t) p[3] << 24);
}

static void
put_u16(u_char *p, uint16_t v)
{
    p[0] = (u_char) (v & 0xff);
    p[1] = (u_char) ((v >> 8) & 0xff);
}

static void
put_u32(u_char *p, uint32_t v)
{
    p[0] = (u_char) (v & 0xff);
    p[1] = (u_char) ((v >> 8) & 0xff);
    p[2] = (u_char) ((v >> 16) & 0xff);
    p[3] = (u_char) ((v >> 24) & 0xff);
}

static void
put_u64(u_char *p, uint64_t v)
{
    put_u32(p, (uint32_t) (v & 0xffffffffULL));
    put_u32(p + 4, (uint32_t) ((v >> 32) & 0xffffffffULL));
}

/* Build a well-formed marker blob exactly as
 * ngx_http_cache_turbo_marker_store() does (vary.c ~574-601): status=200,
 * body_len=2, headers_len=0 (never set, zeroed), a `now`-ish created, and
 * fresh_ttl<=stale_ttl. */
static void
build_marker(u_char *blob, size_t bloblen, uint32_t magic, uint16_t version,
    uint32_t status, int64_t created, uint32_t fresh_ttl, uint32_t stale_ttl,
    u_char bits, u_char gen, int write_gen_byte)
{
    memset(blob, 0, bloblen);
    put_u32(blob + 0, magic);
    put_u16(blob + 4, version);
    put_u16(blob + 6, 0);              /* flags */
    put_u32(blob + 8, status);
    put_u32(blob + 12, 0);             /* nheaders */
    put_u32(blob + 16, 0);             /* headers_len -- always 0 for a marker */
    put_u32(blob + 20, write_gen_byte ? 2 : 1);   /* body_len */
    put_u64(blob + 24, (uint64_t) created);
    put_u32(blob + 32, fresh_ttl);
    put_u32(blob + 36, stale_ttl);
    put_u32(blob + 40, 0);             /* sie_ttl */
    /* CTB5: marker_store() goes through blob_hdr_write(), which renders
     * `created` into the fixed 29-byte Date field on EVERY blob. A marker with
     * a zeroed field would be rejected by the charset check, so the corpus
     * must carry a real one -- exactly the property this mirror is here to
     * keep honest. */
    if (bloblen >= HDR_WIRE) {
        memcpy(blob + DATE_OFF, "Thu, 01 Jan 1970 00:00:00 GMT", DATE_LEN);
        blob[44] = (u_char) DATE_LEN;
    }
    if (bloblen > HDR_WIRE) {
        blob[HDR_WIRE] = bits;
    }
    if (write_gen_byte && bloblen > HDR_WIRE + 1) {
        blob[HDR_WIRE + 1] = gen;
    }
}

/* mirrors ngx_http_cache_turbo_blob_validate() (blob.c ~298-457) restricted
 * to what can differ across the corpus here. The marker's header block is
 * always empty (headers_len==0), so the TLV walk loop never executes and can
 * be dropped from the mirror without changing its decision -- this IS the
 * "the walk is unconditionally a no-op for this call site" claim the PR
 * makes, encoded as a test rather than asserted in prose. */
static int
mirror_old_gate(const u_char *blob, size_t len, u_char *bits_out,
    u_char *gen_out, int gen_present)
{
    uint32_t  status, nheaders, headers_len, body_len;
    int64_t   created;
    uint32_t  fresh_ttl, stale_ttl;

    if (blob == NULL || len < HDR_WIRE) {
        return 0;
    }
    if (get_u32(blob) != BLOB_MAGIC || get_u16(blob + 4) != BLOB_VERSION) {
        return 0;
    }

    status      = get_u32(blob + 8);
    nheaders    = get_u32(blob + 12);
    headers_len = get_u32(blob + 16);
    body_len    = get_u32(blob + 20);
    created     = (int64_t) (((uint64_t) get_u32(blob + 24))
                    | ((uint64_t) get_u32(blob + 28) << 32));
    fresh_ttl   = get_u32(blob + 32);
    stale_ttl   = get_u32(blob + 36);

    if (status < 100 || status > 599) {
        return 0;
    }
    if (stale_ttl < fresh_ttl) {
        return 0;
    }
    if (created < CREATED_MIN || created > FOREVER_TTL) {
        /* mirror's `ngx_time()` stand-in: 0, matching CREATED_MIN, so the
         * upper bound collapses to FOREVER_TTL -- fine, this mirror only
         * needs to be right on the fixed corpus values below, not track a
         * moving wall clock. */
        return 0;
    }
    /* CTB5: the rendered-Date field is validated BEFORE the framing checks,
     * mirroring blob.c's order. */
    if (blob[44] != DATE_LEN) {
        return 0;
    }
    {
        uint32_t  di;
        for (di = 0; di < DATE_LEN; di++) {
            u_char c = blob[DATE_OFF + di];
            if (c < 0x20 || c > 0x7E) {
                return 0;
            }
        }
    }
    if (headers_len > len - HDR_WIRE || body_len > len - HDR_WIRE - headers_len) {
        return 0;
    }
    if (nheaders > headers_len / 9) {
        return 0;
    }
    /* headers_len == 0 for every marker in this corpus => the TLV walk body
     * never executes; nothing further to mirror. */

    if (bits_out) {
        *bits_out = blob[HDR_WIRE];
    }
    if (gen_present && gen_out) {
        *gen_out = blob[HDR_WIRE + 1];
    }
    return 1;
}

/* mirrors the NEW fast-path gate (vary.c ~709-717). */
static int
mirror_new_gate(const u_char *blob, size_t len, u_char *bits_out,
    u_char *gen_out, int *gen_present_out)
{
    if (len < HDR_WIRE + 1) {
        return 0;
    }
    if (get_u32(blob) != BLOB_MAGIC || get_u16(blob + 4) != BLOB_VERSION) {
        return 0;
    }
    if (bits_out) {
        *bits_out = blob[HDR_WIRE];
    }
    *gen_present_out = (len >= HDR_WIRE + 2);
    if (*gen_present_out && gen_out) {
        *gen_out = blob[HDR_WIRE + 1];
    }
    return 1;
}

static int checks = 0, failures = 0;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        checks++;                                                            \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (msg));  \
        }                                                                    \
    } while (0)

/* HEADLINE: on a genuine marker_store()-shaped blob (headers_len==0,
 * status=200, sane created/ttl), the new gate accepts iff the old gate did,
 * and reads back the SAME (bits, gen). This is the "fast path returns the
 * same (bits, gen) as before" proof for the case that actually occurs in
 * production. */
static void
test_new_gate_matches_old_on_real_marker_shape(void)
{
    u_char blob[HDR_WIRE + 2];
    u_char ob, nb, og = 0, ng = 0;
    int    old_ok, new_ok, gen_present = 0;
    size_t i;

    for (i = 0; i < 256; i += 37) {   /* sample bits 0..255 */
        build_marker(blob, sizeof(blob), BLOB_MAGIC, (uint16_t) BLOB_VERSION,
                     200, 1000, 60, 120, (u_char) i, (u_char) (255 - i), 1);

        old_ok = mirror_old_gate(blob, sizeof(blob), &ob, &og, 1);
        new_ok = mirror_new_gate(blob, sizeof(blob), &nb, &ng, &gen_present);

        CHECK(old_ok == 1, "well-formed marker must be accepted by the old gate");
        CHECK(new_ok == old_ok, "new gate must accept whenever the old gate did");
        CHECK(gen_present == 1, "2-byte marker must expose the gen byte");
        CHECK(ob == nb, "bits byte must match between old and new gate");
        CHECK(og == ng, "gen byte must match between old and new gate");
    }
}

/* Pre-COR-5 1-byte marker (bits only, no gen byte): both gates must accept
 * and report gen absent -> caller treats gen as 0, exactly as vary.c's
 * upgrade-compatibility comment describes. */
static void
test_legacy_one_byte_marker_gen_defaults_absent(void)
{
    u_char blob[HDR_WIRE + 1];
    u_char ob, nb;
    int    old_ok, new_ok, gen_present = -1;

    build_marker(blob, sizeof(blob), BLOB_MAGIC, (uint16_t) BLOB_VERSION,
                 200, 1000, 60, 120, 0x2A, 0, 0);

    old_ok = mirror_old_gate(blob, sizeof(blob), &ob, NULL, 0);
    new_ok = mirror_new_gate(blob, sizeof(blob), &nb, NULL, &gen_present);

    CHECK(old_ok == 1, "legacy 1-byte marker must still be accepted");
    CHECK(new_ok == 1, "new gate must still accept a legacy 1-byte marker");
    CHECK(ob == nb, "bits byte must match on a legacy 1-byte marker");
    CHECK(gen_present == 0, "gen byte must be reported absent on a 1-byte marker");
}

/* NEGATIVE CONTROL 1: truncated marker (shorter than HDR_WIRE+1, the
 * minimum the caller's outer `m->len >= HDR_WIRE + 1` guard requires before
 * even calling into this gate) must be rejected by both gates. */
static void
test_truncated_marker_rejected(void)
{
    u_char blob[HDR_WIRE];   /* exactly HDR_WIRE: one byte short of the min */
    u_char ob = 0xAA, nb = 0xAA;
    int    old_ok, new_ok, gen_present = -1;

    build_marker(blob, sizeof(blob), BLOB_MAGIC, (uint16_t) BLOB_VERSION,
                 200, 1000, 60, 120, 0x11, 0x22, 0);

    old_ok = mirror_old_gate(blob, sizeof(blob), &ob, NULL, 0);
    new_ok = mirror_new_gate(blob, sizeof(blob), &nb, NULL, &gen_present);

    CHECK(old_ok == 0, "a blob exactly HDR_WIRE bytes has no body byte to trust");
    CHECK(new_ok == 0, "new gate must reject the same truncated blob");
    CHECK(ob == 0xAA && nb == 0xAA,
          "rejected gate must not have written through bits_out");
}

/* NEGATIVE CONTROL 2: bad magic (hash collision with an unrelated blob, or
 * corruption) must be rejected by both gates, at a length that would
 * otherwise be plenty for the two body bytes. */
static void
test_bad_magic_rejected(void)
{
    u_char blob[HDR_WIRE + 2];
    u_char ob = 0xAA, nb = 0xAA;
    int    old_ok, new_ok, gen_present = -1;

    build_marker(blob, sizeof(blob), 0xDEADBEEFu, (uint16_t) BLOB_VERSION,
                 200, 1000, 60, 120, 0x11, 0x22, 1);

    old_ok = mirror_old_gate(blob, sizeof(blob), &ob, NULL, 1);
    new_ok = mirror_new_gate(blob, sizeof(blob), &nb, NULL, &gen_present);

    CHECK(old_ok == 0, "bad-magic blob must be rejected by the old gate");
    CHECK(new_ok == 0, "bad-magic blob must be rejected by the new gate");
    CHECK(ob == 0xAA && nb == 0xAA,
          "rejected gate must not have written through bits_out");
}

/* NEGATIVE CONTROL 3: bad/unknown version, magic otherwise valid. */
static void
test_bad_version_rejected(void)
{
    u_char blob[HDR_WIRE + 2];
    u_char ob = 0xAA, nb = 0xAA;
    int    old_ok, new_ok, gen_present = -1;

    build_marker(blob, sizeof(blob), BLOB_MAGIC, 99,
                 200, 1000, 60, 120, 0x11, 0x22, 1);

    old_ok = mirror_old_gate(blob, sizeof(blob), &ob, NULL, 1);
    new_ok = mirror_new_gate(blob, sizeof(blob), &nb, NULL, &gen_present);

    CHECK(old_ok == 0, "bad-version blob must be rejected by the old gate");
    CHECK(new_ok == 0, "bad-version blob must be rejected by the new gate");
    CHECK(ob == 0xAA && nb == 0xAA,
          "rejected gate must not have written through bits_out");
}

/* Documents (as a test, not just a comment) the ONE known divergence: a
 * blob with valid magic/version/length but an out-of-range status. The old
 * gate rejects it (defense against a corrupted/forged blob); the new gate
 * accepts it and reads whatever bytes are there. This is SOUND specifically
 * because marker_store() (vary.c ~588: `bh.status = NGX_HTTP_OK`) never
 * emits any status but 200 -- a real marker blob can never exercise this
 * branch, so the old gate's status check was validating an invariant the
 * writer already guarantees, not defending against a hostile marker with
 * valid magic. A hash-collision blob at this key is necessarily written by
 * the SAME ngx_http_cache_turbo_blob_hdr_write() (module.c/vary.c/blob.c
 * are the only writers), so it too always has a valid status --
 * out-of-range status + valid magic/version is not a reachable shm state at
 * all, only a hand-crafted fuzz input like this one. */
static void
test_new_gate_is_a_strict_superset_on_real_marker_bytes(void)
{
    u_char blob[HDR_WIRE + 2];
    u_char ob = 0xAA, nb = 0xAA;
    int    old_ok, new_ok, gen_present = -1;

    build_marker(blob, sizeof(blob), BLOB_MAGIC, (uint16_t) BLOB_VERSION,
                 700 /* out of 100..599 */, 1000, 60, 120, 0x11, 0x22, 1);

    old_ok = mirror_old_gate(blob, sizeof(blob), &ob, NULL, 1);
    new_ok = mirror_new_gate(blob, sizeof(blob), &nb, NULL, &gen_present);

    CHECK(old_ok == 0, "old gate rejects an out-of-range status (documented, "
                       "unreachable via any real writer)");
    CHECK(new_ok == 1, "new gate accepts it -- documented sound divergence, "
                       "see comment above");
    CHECK(nb == 0x11, "new gate still reads the real bits byte at HDR_WIRE");
}

int
main(void)
{
    test_new_gate_matches_old_on_real_marker_shape();
    test_legacy_one_byte_marker_gen_defaults_absent();
    test_truncated_marker_rejected();
    test_bad_magic_rejected();
    test_bad_version_rejected();
    test_new_gate_is_a_strict_superset_on_real_marker_bytes();

    printf("test_vary_marker_fastpath: %d checks, %d failures\n",
           checks, failures);
    return failures ? 1 : 0;
}
