# refactor.md — compaction analysis, `nginx-cache-turbo-module`

Measured 2026-08-17. Scope: can this codebase be compacted/simplified by
deduplication, crunching, or splitting?

## Relationship to `nginx-skeleton-module/ci/PROMPT.md` — read this first

This document **does not override, amend, or reinterpret** any directive in
`/opt/myguard/labs/nginx-skeleton-module/ci/PROMPT.md`. Where the two could be
read as touching the same ground, PROMPT.md wins and this file yields.

Three specific non-collisions, stated so a future session does not have to
re-derive them:

1. **Different jobs.** PROMPT.md is a CI-standard adoption run (42 steps, 8
   phases, PRs 1–3). This file is a source-layout analysis of one already-adopted
   module. Neither is a phase of the other.
2. **PROMPT.md's "the only C refactor in the job" refers to the decision seam**
   (phase 3, steps 8–10: decision logic to `*_scan.c` taking `(u_char *, size_t)`).
   That sentence bounds *the adoption job*, not this module's own maintenance. It
   is not a prohibition on unrelated refactoring.
3. **PROMPT.md's "Existing behaviour is not in scope"** binds a worker executing
   the adoption run ("You are moving CI, not rewriting the module"). It does not
   bind ordinary module maintenance requested directly by the user.

**If an adoption run is ever active on this repo, it takes precedence and this
file is suspended for the duration** — PROMPT.md's branch and PR rules ("one
branch and at most one target PR per group", fixed PR1/PR2/PR3 boundaries, "never
delete a gate the target already has") are absolute, and work from this file must
not share a branch with an adoption PR or land inside one. Cleanup falling out of
an adoption run has its own home: PROMPT.md's optional **PR4**. Work from this
file is not PR4 material and should not be filed there.

Current adoption state, checked 2026-08-17: `ci/tests/unit/run.sh` and
`ci/fuzz/build.sh` both exist, so the skeleton standard is already adopted. There
is no `src/*_scan.c`; per PROMPT.md step 8 this module is the legitimate **fifth
outcome** — decision logic is not separable into a scan seam in the reference's
shape. Nothing in this file changes that assessment.

## Prior art — MAINT-SPLIT is already done, do not redo it

`memory/labs/nginx-cache-turbo-module/TODO-archive.md:3352` holds the
**MAINT-SPLIT epic**, user-approved 2026-08-14, executed across ~15 PRs
(#282–#310). Its closing line: *"MAINT-SPLIT is fully drained; nothing above
CCN 29 remains."*

Re-measured today, that holds:

| metric | value |
|---|---|
| avg CCN across `src/` | 7.4 |
| worst function | `redis_frame_scan` CCN 33 |
| lizard warnings | 38 / 371 fns (10%) |
| files in `src/` | 8 `.c` + 2 `.h` (was 1 + 1) |

Already landed there: `conf.c`, `admin.c`, `internal.h` split out;
`merge_loc_conf` 56→3; `redis_conf` 51→6; `admin_handler` 43→5;
`access_handler` 130→8; `body_filter` 145→17; `header_filter` 44→5. The 19k-line
test harness was split into `ci/tools/areas/`.

**MAINT-SPLIT drained complexity (CCN). It did not drain file size.** That gap is
what remains.

## Findings by axis

Three axes were measured independently (structure map, clone detection,
dead-code/complexity). They land very unevenly.

| ask | verdict |
|---|---|
| deduplication | ~nothing. jscpd: **0 clones at ≥25 lines, 0.00%** |
| crunching | ~nothing. **0 uncalled functions** of 371; 1 dead field; 3 dead macros |
| splitting | **the real lever.** 6,600 ln (45%) extractable without touching hot path |

### Duplication — not the lever

jscpd found zero clones at ≥25 lines. Not a broken tool: thresholds 15/10/5 yield
13/42/107 clones, so the detector was working. Only pair reaching 25 lines is two
RESP array parsers in `redis.c` (`parse_array:2889-2913` vs
`parse_scan:3021-3043`) — identical prologue, then legitimately diverging on shape
validation.

The hypothesised "repeated error-log + return blocks" **does not exist**: 26
`ngx_log_error` calls total, zero log-then-return sequences.

Real items:

- **`ngx_conf_log_error` + `return NGX_CONF_ERROR`: 59 of 72 uses.** The one
  genuine macro candidate. `conf.c` 33, `module.c` 39.
- 5 copies of the nginx `headers_out.headers.part` list-walk in `module.c`.

### Dead code — essentially none

- **0 uncalled functions** of 371.
- **3 unused macros** of 169: `ST_MISS 0` (`internal.h:336`), `SR_NONE 0`
  (`internal.h:349`), `DEFAULT_BETA` (`module.h:132`). The first two are the
  zero-valued members of enum-like families; the code relies on `pcalloc` zeroing
  rather than naming them, so they are documentation of a zero baseline, not
  weight. Removing them is a judgement call, not an obvious win. `DEFAULT_BETA`
  may be real drift — grep the conf defaults before dropping.
- **`stale_hit:1` (`module.h:1498`) is genuinely dead.** Its comment says "for
  X-Cache", but stale status is now passed as a literal string argument to
  `ngx_http_cache_turbo_serve()` (e.g. `"STALE-BREAKER"` at `module.c:7124`).
  Superseded and safe to drop. Verified individually, not inferred from a grep
  count.
- **21 cppcheck "should have static linkage" hits are FALSE POSITIVES** against
  the deliberate `internal.h` seam. Do not act on them.

### Splitting — where the value is

`module.c` is 14,682 lines / 208 top-level functions, but only **7,315 NLOC** —
~39% of the file is comment. Per the MAINT-SPLIT archive those comments carry
load-bearing reasoning (locking windows, refcount escapes, ordering contracts) and
**move WITH their code, never dropped.** This is redistribution, not deletion; the
headline line count is not fat to trim.

Cross-group call graph is sparse: 37 group→group edges, and only **11 functions**
are called from more than one foreign group. Those 11 are the entire
header-export surface a split needs.

| # | proposed file | source range | lines | risk |
|---|---|---|---|---|
| A | `_presets.c` (data only) | `module.c:2301-4031` | 1731 | none — 1 `extern` |
| B | `_blob.c` (SHA-256 + blob) | `module.c:682-1123` | 442 | leaf, calls nothing outside |
| C | `_vary.c` | `module.c:13128-13986` | 859 | clean after B |
| D | `_match.c` (cookie/arg/URI) | `module.c:4032-5427` | 1396 | pairs with A |
| H | config tail → existing `_conf.c` | `:11464-12797` + `:14347-14682` | 1670 | mechanical, 3 edges |
| G | `_purge.c` | `:2118-2300` + `:12798-13127` | 513 | non-contiguous halves |
| E | `_filters.c` | `module.c:9218-11463` | 2246 | HOT PATH |
| F | `_access.c` | `module.c:5428-8107` | 2680 | HOT PATH, heaviest importer |

A+B+C+D+G+H ≈ 6,600 lines (45%) without touching the request hot path.

**A is the standout:** `module.c:2301-4031` is 1,731 lines of CMS preset data
tables with **zero functions**. Two consumers only (`auto_skip:5108`,
`key_cookie:5254`), both via `const ngx_http_cache_turbo_preset_t *`. Extraction
cost is one `extern` in `_internal.h`.

Ordering matters: A → B → {C, D} → H → G → E → F.

## Recommended first PR — near-zero risk

1. Extract **`_presets.c`** (1,731 ln, pure data, one `extern`).
2. Extract **`_blob.c`** (442 ln, leaf group).
3. Drop **`stale_hit:1`** (`module.h:1498`).
4. Fix the **cppcheck fail-open** (below).

~2,173 lines out. Pure moves, so the byte-identical-body oracle applies.

### Toolchain fail-open — land regardless

`cppcheck` aborts with `preprocessorErrorDirective` at `module.h:395` unless
`-DNGX_PTR_SIZE=8` is supplied. **A bare run scans nothing useful and reads as
clean.** Same fail-open class as the four MAINT-T0 gates. Pin the define in the
lint config.

Working invocation:

```sh
cppcheck --enable=unusedFunction,style --inline-suppr -DNGX_PTR_SIZE=8 \
  -DNGX_HAVE_ATOMIC_OPS=1 -I src --suppress=missingInclude \
  --suppress=missingIncludeSystem --suppress=unusedStructMember src/
```

## Then — separate PRs, ascending risk

- `_vary.c` (859) · `_match.c` (1,396) · config tail → `_conf.c` (1,670) ·
  `_purge.c` (513).
- **`purge_request`** (`module.c:2118`) — nesting depth 7, 179 lines, CCN 19.
  Cheapest local win; guard-clause inversion, locally verifiable, no concurrency
  or parser exposure. (Depth measured by brace counting — lizard's nesting-depth
  column reports 0 for every C function here and must not be trusted on this
  codebase.)
- **`shm_store*` params struct.** `shm_claim_locked` (`shm.c:1051`) and
  `shm_resolve_miss` (`shm.c:1248`) take 9 params, `shm_store_if` (`shm.c:904`)
  takes 8, `shm_store`/`shm_store_locked` take 7. Several params share compatible
  types, so **a transposition compiles silently today**; one struct closes the
  class and the compiler verifies every call site. ⚠ hot path — benchmark the L1
  lookup before and after, do not assume it is free.
- The `ngx_conf_log_error` macro (59 sites).

## Leave alone — deliberate

- **`shm_breaker_state`** (`shm.c:1756`, 307 lines) and the
  **`redis_frame`/`redis_frame_scan`** pair (`redis.c:2506`/`:2679`, CCN 28/33).
  Highest-risk code in the module: shared memory under concurrent workers, and a
  RESP parser on hostile input. Refactoring either for the metric alone is a bad
  trade without a full `/audit-concurrency` or `/audit-parser` pass on the diff
  plus a differential test.
  ⚠ Live gate, `memory/labs/nginx-cache-turbo-module/TODO.md:175`: **any `redis.c`
  decomposition PR must run `fuzz_resp_parser`.**
- **High-CCN RFC predicates.** `header_admissible_name` (`module.c:9408`) scores
  CCN 24 across 25 NLOC purely by enumerating the RFC 9110 token charset as a
  15-case `switch`. A 256-byte lookup table drops the score and makes the RFC
  correspondence unauditable. Same for `not_modified_etag`,
  `emit_surrogate_key_parse`. **CCN is measuring the spec here, not the code** —
  resist any blanket "get CCN under 20" push.
- **`classify_vary_classify_token`** (`module.c:13329-13346`) unless test-pinned
  first. It is a textbook table-driven candidate, but the comment at `:13325`
  reads *"Do not reorder or collapse these arms"* — arm order is load-bearing for
  RFC 9110 12.5.5, and the terminal `else` deliberately refuses to cache an
  unrecognised Vary axis. Cache-poisoning-critical. Needs a test asserting each
  arm's verdict plus an unknown-axis case **before** any rewrite.
- The 21 cppcheck static-linkage hits (see above).

## Redis vs memcached — noted, not recommended yet

All 24 memcached functions have a same-named redis counterpart, so **100% of
`memcached.c`'s 1,178 function-lines are parallel structure** against 36% of
`redis.c`'s. Redis carries 33 extra functions (TLS, SCAN, tags, locks) with no
memcached analogue.

A backend vtable abstraction already exists (`module.h:965`, `:2011`), with
memcached deliberately leaving `tag`/`scan`/`lock` slots NULL. The parallelism is
interface-level by design, not copy-paste. The right shape, if pursued, is a
shared connect/keepalive/backoff/read-loop layer with redis retaining its
protocol-specific extensions — **not a symmetric merge**. Large, and it touches
the fuzz-gated parser file. Not part of the recommended sequence.

## Preconditions before any of this starts

- **Branch.** Verified 2026-08-18: the checkout is on `main`, clean. (An earlier
  reading of `docs/proofread-guides` came from the superrepo's session-start
  status snapshot and was stale — that branch exists on the remote but is not
  checked out here.) The MAINT-SPLIT hazard note still binds: two branches both
  touching `module.c`/`module.h` **will** conflict, so these steps stay serial,
  one PR each, rebased before each merge.
- **Per-step gate** (from the MAINT-SPLIT archive, user-set 2026-08-14 — carry it
  forward unchanged):
  1. Self-review the diff locally before the PR opens. Never post a review on our
     own PR.
  2. `lizard` before/after on touched files; CCN delta in the PR body. Numbers,
     not prose.
  3. `ast-grep` structural check on every move/extract — grep cannot prove a move
     was mechanical. Use `ast-grep run`; in C, pin the first argument.
  4. Verify moved bodies are **byte-identical** where a step claims a pure move.
  5. **No test edits in a move/extract PR.** A move needing a test change is not a
     move.
  6. `review-lint.sh` (absolute path, >2 min).
  7. Full remote CI green — parser/memory/concurrency code, so no local-only
     verdict.
  8. Rebase and REBUILD before trusting green; this work moves the same files
     repeatedly and a green run against a stale base proves nothing.
- File splits change `config`; a wrong `ci-build.sh` flavor prints `unsupported
  flavor` and **exits 0** — check `.so` mtime, never exit status.
