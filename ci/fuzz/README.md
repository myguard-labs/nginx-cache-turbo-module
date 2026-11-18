# Fuzzing

Coverage-guided (libFuzzer) fuzzing of the module's attacker-controlled
parsers. Registered targets (see below), each built from the SHIPPED source by
its own `extract_*.sh` slicer (no hand-maintained copy):

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
- **`fuzz_auto_classify`** → `ngx_http_cache_turbo_auto_skip()` (the backend
  preset classifier: preset registry + `cookie_has`), fed an attacker-controlled
  `Cookie` header / request URI / args. Bug classes: OOB reads in the cookie
  substring / value-predicate scans and the URI/arg matchers. Sliced by
  `extract_auto_classify.sh` into `generated_auto_classify.inc`.
- **`fuzz_cache_control`** → the origin `Cache-Control` / `Surrogate-Control`
  parser: `cc_token` (quoted-string / quoted-pair aware directive scan),
  `cc_has`, `cc_parse_delta` (saturating delta-seconds), `cc_delta` and
  `cc_delta_all` (every field-line walk over an `ngx_list_t`). Bug classes: an
  OOB-read at/over `last` on exact-sized, non-NUL-terminated values and an
  integer overflow in the delta accumulator. Sliced by `extract_cache_control.sh`
  into `generated_cache_control.inc`; shim is `ngx_shim_cc.h`; corpus is
  `corpus_cache_control/` (duplicated/conflicting directives, quoted
  delimiters, unterminated quotes, `=` without value, 20+ digit and signed
  deltas, NUL/CTL/obs-text, 1000 directives/lines). Oracle: an independent
  reference model in the harness; `-1` is the only negative result and a delta
  saturates at `NGX_MAX_TIME_T_VALUE`.
- **`fuzz_vary`** → the origin `Vary` classifier:
  `classify_vary_next_token` (comma/whitespace tokeniser),
  `classify_vary_classify_token` (per-axis verdict) and `vary_ignore_match`
  (`cache_turbo_vary_ignore` lookup), driven in the shipped caller's loop shape.
  Bug classes: an OOB read over the end of an exact-sized, non-NUL-terminated
  value and a fail-open verdict. Sliced by `extract_vary.sh` into
  `generated_vary.inc`; shim is `ngx_shim_vary.h`; corpus is `corpus_vary/`
  (`*`, empty tokens, comma/whitespace runs, case variants, 1000 tokens,
  over-long names, NUL, ignore-list modes). Oracle: an independent reference
  model plus a fail-closed property (a non-ignored token outside the four
  whitelisted axes must leave `nocache` set and `bits` 0).

- **`fuzz_cookie_args`** → the client Cookie index and query-string parsers in
  `match.c`: `cookie_index_parse_one` (+ its `cookie_index_add` helper),
  `cookie_ac_scan_one`, `argparse_tail_count` and `argparse_build` (+ `hexval`,
  `qs_first_mangled`). Inputs are exact-sized, non-NUL-terminated Cookie header
  values (`;` without a space, empty names, `=` inside values, quoted values,
  duplicates, 4096 crumbs) and query strings (`&&`, bare `=`, truncated
  `%`-escapes, `+`, 10000 args). Bug classes: an OOB read at/over the end of a
  value, a write past the span array / pair array if the counting walk and the
  recording walk disagree, and a Cookie/arg mis-split. Sliced by
  `extract_cookie_args.sh` (verbatim type blocks from `module.h` plus the
  functions from `match.c`; fails closed if any one is missing) into
  `generated_cookie_args.inc`; shim is `ngx_shim_cookie_args.h` (a recording
  pool whose allocations are exact heap blocks); corpus is
  `corpus_cookie_args/`. Oracle: ASan/UBSan plus independent reference models,
  and a bound oracle - `argparse_tail_count` equals the reference count, the
  recorded span count never exceeds the computed capacity and an overflowed
  array is allocated at exactly `capacity * sizeof(span)`. Layout: byte 0 flags
  (failing pool, empty needle, NULL automaton, NULL data), byte 1 needle mask,
  byte 2 tail-offset selector, then `0xFF`-separated sections (query string,
  then up to 8 Cookie header values). The 10000-arg and 4096-crumb seeds exceed
  libFuzzer's default 4096-byte limit, which it raises to the largest seed.

- **`fuzz_control_inputs`** → the operator/origin control-input parsers:
  `hexdecode` (`purge.c`, tag-set member hex to key bytes; + the `match.c`
  `hexval` helper), `body_filter_tag_split` (`filters.c`, origin
  Surrogate-Key / Cache-Tag tokeniser capped at `MAX_TAGS` entries of
  `MAX_TAG_LEN` bytes) and the admin warm-list splitter in `admin.c`: `warm`
  (`,`/`\n` split, CR trim, `?query` suffix split, percent-decode into an exact
  allocation, `warm_max` fan-out cap), `warm_uri_is_safe`, `warm_raw_is_safe`
  and `warm_file_finish` (the `WARM_LINE_MAX_LEN` gate). Bug classes: an OOB
  read at/over the end of an exact-sized, non-NUL-terminated buffer, a write
  past `seen[]` or the decode allocation, a cap that stops holding, and a
  CR/NUL/CTL byte or `..` segment reaching the subrequest. Sliced by
  `extract_control_inputs.sh` (the cap defines from `module.h` / `admin.c` plus
  the functions; fails closed if any one is missing) into
  `generated_control_inputs.inc`; shim is `ngx_shim_control_inputs.h` (verbatim
  nginx `ngx_unescape_uri`, an exact-block pool with a fail-at index, and
  recorders standing in for `warm_one` and `send_json`); corpus is
  `corpus_control_inputs/`. Oracle: ASan/UBSan plus independent reference models
  and a cap oracle - tag count never exceeds `MAX_TAGS`, every tag is
  1..`MAX_TAG_LEN` bytes, the successful warm subrequests never exceed
  `warm_max` and equal the reply, and a list with a line over
  `WARM_LINE_MAX_LEN` fires nothing. Layout: byte 0 flags (`warm_max`
  selector, `warm_one` failure schedule, pool failure, tag resume), byte 1 pool
  failure index, then the hex string, the tag value (each ended by `0xFF`) and
  the warm list (the rest). **Ownership deviation:** `ngx_http_arg` (the
  `?url=` / `?url_file=` / `?tag=` / `?key=` lookup) is nginx core, not module
  code, so it is not driven; the in-tree query readers are warm's `?query`
  suffix split and its percent-decoder, both covered here. `hexval` is
  also sliced into `fuzz_cookie_args` and `fuzz_auto_classify` (argparse
  helper); here it is asserted only through `hexdecode`.

### Function ownership (match.c auto-classify FUZZ-EXTRACT block)

`fuzz_auto_classify` compiles match.c with `NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO`
defined, which compiles OUT every `!FUZZ_SHIM_AUTO` function and compiles IN the
legacy per-pair predicate path. Each function below is actively driven by exactly
one target; the other target either never compiles it or only reaches it as an
unasserted feeder.

| function | owner | note |
|---|---|---|
| `cookie_index_add`, `cookie_index_parse_one` | `fuzz_cookie_args` | `!FUZZ_SHIM_AUTO`: not compiled into `fuzz_auto_classify` |
| `cookie_ac_scan_one` | `fuzz_cookie_args` | `!FUZZ_SHIM_AUTO`: not compiled into `fuzz_auto_classify` |
| `argparse_tail_count`, `argparse_build` (+ `hexval`, `qs_first_mangled`) | `fuzz_cookie_args` | always compiled, so `fuzz_auto_classify` also runs them as the front half of `auto_skip` with no assertion on their output; the span/size bound oracle lives only here |
| `hexdecode`, `body_filter_tag_split`, `warm`, `warm_uri_is_safe`, `warm_raw_is_safe`, `warm_file_finish` | `fuzz_control_inputs` | not in `match.c`; compiled into no other target |
| `cookie_pred_one_next_pair`, `cookie_pred_one_split` (+ `_dispatch`, `cookie_pred`) | `fuzz_auto_classify` | `FUZZ_SHIM_AUTO`-only; driven through `auto_skip` over the preset predicate rows, so NOT sliced into `fuzz_cookie_args` |
| `cookie_byteset_build`, `cookie_contains`, `cookie_has`, `qs_eq`, `arg_match`, `uri_prefix`, `auto_skip`, preset registry | `fuzz_auto_classify` | unchanged |

## Target registry

`targets.tsv` is the single list of fuzz targets (tab-separated, header row,
columns `name source corpus dict extract`; `dict` is `-` when none). `build.sh`,
`run-concurrent.sh` (no-arg default), `ci/tools/precommit-tests.sh`, the PR
regression/60s steps in `static.yml` and both Deep fuzz lanes read it through
`targets.sh`, so a new target needs one registry row (plus its harness, slicer
and corpus) and is built, replayed on every PR and long-fuzzed in Deep. Deep
lane `a` runs the first half of the rows (rounded up), lane `b` the rest.
`targets.sh validate` fails naming the first bad row (missing source, corpus,
dict or slicer, wrong column count, empty/duplicate name); it is covered by
`ci/tests/test_fuzz_targets_registry.py`.

## RESP reply parsers

The `fuzz_resp_parser` target covers the three Redis (RESP) reply parsers in
`../src/ngx_http_cache_turbo_redis.c`:

| function | reply shape |
|---|---|
| `ngx_http_cache_turbo_redis_parse`       | bulk string (`GET`) — `$<len>\r\n<bytes>\r\n` |
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
bash ci/fuzz/build.sh                 # -> ci/fuzz/fuzz_* (ASan+UBSan+fuzzer, all four targets)
cd ci/fuzz
./fuzz_resp_parser -max_total_time=60 corpus/
```

A crash drops a `crash-*` reproducer; re-run it with
`./fuzz_resp_parser crash-<id>` to reproduce. Add the reproducer to `corpus/`
(named `regress_*`) so it becomes a permanent regression seed.

## CI

`.github/workflows/fuzzing.yml` is a **fast regression gate on every PR/push**
(120s/target on all four parsers) plus manual dispatch. Long discovery fuzzing
(hours/target) lives in `ci-deep.yml` (monthly cron + dispatch). The build-time
ASan+UBSan suite in `build-test.yml` is the other per-change gate.

## Findings

- **`regress_scan_cursor_len_overflow`** — the `SCAN` cursor bulk-string length
  was used in `end - p < len + 2` without first bounding it by `MAX_REPLY`
  (unlike `parse()` and the member loops). A cursor length of `INT64_MAX`
  overflowed `len + 2` (UBSan signed-overflow). Fixed by adding the
  `len > MAX_REPLY → NGX_DECLINED` guard; the seed is kept so the bug can never
  return silently.
