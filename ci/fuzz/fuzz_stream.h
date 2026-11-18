/*
 * Streaming split mode, shared by fuzz_resp_parser and fuzz_mc_parser.
 *
 * The fuzzer chooses how a reply is cut into recv() segments. The choice comes
 * from a leading CONTROL PREFIX that is never part of the reply:
 *
 *   data[0]            control byte
 *                        bits 0-3  K, the number of explicit segment lengths;
 *                                  K == 0 means dribble, one byte per segment
 *                        bits 4-7  target-specific flags (see each harness)
 *   data[1 .. 1+K)     segment lengths, byte b -> a segment of b + 1 bytes
 *   data[1+K ..]       the reply R; whatever the K segments do not cover is
 *                      delivered as one final segment
 *
 * Every oracle in the streaming blocks compares R fed in segments against R
 * (or one of its prefixes) fed whole. Both sides see exactly the bytes of R:
 * the prefix only decides WHERE the cuts fall, never WHAT the reply is. That is
 * the rule PR #248 learned the hard way: the split must not change what the
 * reply bytes are, or the reference and the split feed are no longer parsing
 * the same reply and the comparison means nothing.
 *
 * The whole-input blocks of each harness still parse data[0..size) as a reply,
 * so the hand-written corpus of complete replies keeps its value there; the
 * corpus entries named NN_stream_* carry a control prefix for these blocks.
 */

#ifndef NGX_CACHE_TURBO_FUZZ_STREAM_H
#define NGX_CACHE_TURBO_FUZZ_STREAM_H

#include <stddef.h>
#include <stdint.h>

/* Dribble mode stops cutting after this many one-byte segments and delivers
 * the rest in one piece, so a 4 KiB input costs at most ~1k re-parses. */
#define NGX_FUZZ_STREAM_MAX_DRIBBLE  1024

typedef struct {
    const uint8_t  *seg;        /* K segment-length bytes            */
    size_t          nseg;       /* K                                 */
    unsigned        flags;      /* control bits 4-7, shifted down    */
    const uint8_t  *reply;      /* R                                 */
    size_t          len;        /* |R|                               */
} ngx_fuzz_stream_t;

/* Decode the control prefix. Returns 0 when the input is empty (no control
 * byte). A truncated segment list is clamped to the bytes present, leaving an
 * empty reply. */
static int
ngx_fuzz_stream_decode(const uint8_t *data, size_t size, ngx_fuzz_stream_t *s)
{
    size_t  k;

    if (size == 0) {
        return 0;
    }

    k = data[0] & 0x0f;
    if (k > size - 1) {
        k = size - 1;
    }

    s->seg = data + 1;
    s->nseg = k;
    s->flags = data[0] >> 4;
    s->reply = data + 1 + k;
    s->len = size - 1 - k;
    return 1;
}

/* End offset (exclusive) of segment `step`, which starts at `pos` (< len). */
static size_t
ngx_fuzz_stream_end(const ngx_fuzz_stream_t *s, size_t step, size_t pos)
{
    size_t  n;

    if (s->nseg == 0) {
        n = step < NGX_FUZZ_STREAM_MAX_DRIBBLE ? 1 : s->len - pos;

    } else if (step < s->nseg) {
        n = (size_t) s->seg[step] + 1;

    } else {
        n = s->len - pos;
    }

    return n > s->len - pos ? s->len : pos + n;
}

#endif /* NGX_CACHE_TURBO_FUZZ_STREAM_H */
