/*
 * Minimal nginx surface for fuzzing the cache-turbo memcached reply parser
 * (ngx_http_cache_turbo_mc_parse), v13.
 *
 * Like ngx_shim.h (the RESP-parser shim) but for the memcached TEXT-protocol
 * GET reply parser: it reads attacker-influenceable bytes — a memcached reply
 * from a shared, possibly-compromised or buggy L2 — out of op->rbuf doing
 * header-line scanning + <bytes> length arithmetic against op->rbuf + op->rlen.
 * Same OOB-read / integer-handling bug class the runtime suite can't reach.
 *
 * The parser body itself is NOT copied — extract_mc_parser.sh slices it from the
 * shipped src/ngx_http_cache_turbo_memcached.c into generated_mc_parser.inc at
 * build time, so the fuzzer always exercises production code with no drift.
 * This header reuses ngx_shim.h's faithful ngx_strlchr/ngx_atoi/CR/LF and adds
 * the tiny extra surface the memcached parser needs (ngx_strncmp, ssize_t, the
 * reduced op struct, the MC_MAX_VALUE guard).
 */

#ifndef NGX_CACHE_TURBO_FUZZ_SHIM_MC_H
#define NGX_CACHE_TURBO_FUZZ_SHIM_MC_H

#include <sys/types.h>      /* ssize_t */

#include "ngx_shim.h"       /* ngx_int_t/u_char/ngx_str_t, ngx_strlchr, ngx_atoi,
                             * CR, LF, NGX_OK/AGAIN/DECLINED */

/* nginx ngx_string.h: ngx_strncmp is a thin cast over strncmp. The parser calls
 * it on u_char* against string literals ("END", "VALUE "). */
#define ngx_strncmp(s1, s2, n)  strncmp((char *) (s1), (char *) (s2), n)

/* The 1 MiB single-item ceiling the parser enforces. Kept in sync with the
 * #define in src/ngx_http_cache_turbo_memcached.c — extract_mc_parser.sh FAILS
 * the build if the shipped value drifts, so this can never silently diverge. */
#define NGX_HTTP_CACHE_TURBO_MC_MAX_VALUE  (1024 * 1024)

/*
 * The op struct reduced to exactly the two fields the parser body reads: the
 * accumulated reply buffer (rbuf) and how many bytes are in it (rlen). The
 * shipped struct has many more fields (connection, pool, events); the parser
 * touches none of them.
 */
typedef struct {
    u_char  *rbuf;
    size_t   rlen;
} ngx_http_cache_turbo_mc_op_t;

#endif /* NGX_CACHE_TURBO_FUZZ_SHIM_MC_H */
