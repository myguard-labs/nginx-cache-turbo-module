# Fuzzing

Coverage-guided (libFuzzer) fuzzing of the module's attacker-controlled
parsers. Three targets, each built from the SHIPPED source by its own
`extract_*.sh` slicer (no hand-maintained copy):

- **`fuzz_resp_parser`** → the three Redis (RESP) reply parsers (below).
- **`fuzz_mc_parser`** → `ngx_http_cache_turbo_mc_parse()` (v13), the memcached
  TEXT-protocol GET reply parser. Reads a memcached reply from a shared,
  possibly-compromised L2 — `VALUE <key> <flags> <bytes>[ <cas>]\r\n<data>` —
  scanning the header line for spaces/CRLF and doing `<bytes>`-length pointer
  arithmetic against `op->rbuf .. op->rbuf + op->rlen`. Same OOB-read / length-
  check bug class as the RESP target. Sliced by `extract_mc_parser.sh` into
  `generated_mc_parser.inc`; shim is `ngx_shim_mc.h`; corpus is `corpus_mc/`.
- **`fuzz_norm_args`** → `ngx_http_cache_turbo_normalized_args_variable()`,
  which builds `$cache_turbo_normalized_args` from the **fully attacker-
  controlled** request query string: it splits on `&`/`=` with pointer
  arithmetic, drops denied params, stable-sorts the rest, then sizes and
  writes a `?`-prefixed buffer. Bug classes: an OOB-read in the splitter
  and an OOB-write if the size computation ever under-counts the build
  loop. The harness feeds non-NUL-terminated args (exact-sized alloc) so
  ASAN catches both. `vary_suffix` / `var_set` / `name_denied` are stubbed
  (see `ngx_shim_args.h`): the write bound is computed from the same
  kept-token set it writes, so it is invariant to which tokens are dropped
  or whether a Vary suffix is appended.

## RESP reply parsers

The `fuzz_resp_parser` target covers the three Redis (RESP) reply parsers in
`../src/ngx_http_cache_turbo_redis.c`:

| function | reply shape |
|---|---|
| `ngx_http_cache_turbo_redis_parse`       | bulk string (`GET`) — `$<len>\r\n<bytes>\r\n` |
| `ngx_http_cache_turbo_redis_parse_array` | array (`SMEMBERS`) — `*<count>\r\n` then N bulk strings |
| `ngx_http_cache_turbo_redis_parse_scan`  | `SCAN` 2-tuple — `[ cursor, [ keys… ] ]` |

These parse bytes from a shared, possibly buggy or compromised L2, doing
length-line and bulk-string pointer arithmetic against `op->rbuf .. op->rbuf +
op->rlen`. A single off-by-one in a CRLF scan or a missing length bound is a
worker-crashing out-of-bounds read or a signed-overflow UB — exactly the bug
class coverage-guided fuzzing finds and the runtime suite misses.

## No copy drift

The fuzz target does **not** contain a copy of the parser. `extract_parser.sh`
slices the three function bodies (and the `MAX_MEMBERS` guard) verbatim out of
the shipped source into `generated_parser.inc` at build time, and asserts the
`MAX_REPLY`/`MAX_MEMBERS` size constants still match the shim. If a signature,
body, or constant changes upstream, the next build picks it up — or fails loudly
rather than fuzz stale code. `ngx_shim.h` supplies the minimal nginx surface the
parsers touch (`op` struct, a malloc-backed pool, and verbatim `ngx_atoi` /
`ngx_strlchr`) with faithful upstream semantics.

The harness feeds a buffer sized **exactly** to `op->rlen` with **no** trailing
NUL, so ASAN turns any read at or past the end into an immediate, reproducible
heap-buffer-overflow. On `NGX_OK` it also asserts every returned `ngx_str_t`
points back into the input buffer.

## Build & run locally

```bash
# needs clang with libFuzzer (clang >= 6)
bash fuzz/build.sh                 # -> fuzz/fuzz_resp_parser (ASan+UBSan+fuzzer)
cd fuzz
./fuzz_resp_parser -max_total_time=60 corpus/
```

A crash drops a `crash-*` reproducer; re-run it with
`./fuzz_resp_parser crash-<id>` to reproduce. Add the reproducer to `corpus/`
(named `regress_*`) so it becomes a permanent regression seed.

## CI

`.github/workflows/fuzzing.yml` runs this monthly (1st of the month) and on
manual dispatch, mirroring the `valgrind` / `codeql` heavy-job cadence. The
build-time ASan+UBSan suite in `build-test.yml` is the per-change gate.

## Findings

- **`regress_scan_cursor_len_overflow`** — the `SCAN` cursor bulk-string length
  was used in `end - p < len + 2` without first bounding it by `MAX_REPLY`
  (unlike `parse()` and the member loops). A cursor length of `INT64_MAX`
  overflowed `len + 2` (UBSan signed-overflow). Fixed by adding the
  `len > MAX_REPLY → NGX_DECLINED` guard; the seed is kept so the bug can never
  return silently.
