# perf profile of the L1 hit path (P2-2)

Reference `perf record`/`perf report` results for `ci/tools/perf-profile.sh`,
gating P4-1 ("W-TinyLFU admission control", `[NEEDS-ZIPF]`) and P4-2 ("reduce
hit-path lock residency", `[NEEDS-PROFILE]`) in
`memory/labs/nginx-cache-turbo-module/PLAN-optimize.md`. See
[BENCHMARK.md](BENCHMARK.md) for the throughput/latency comparison against
`proxy_cache`; this document is about *where the CPU time inside the L1 hit
path actually goes*, which BENCHMARK.md's aggregate rps/p50/p99 numbers cannot
show.

> **Superseded rankings — read [Re-profile 2026-08-27](#re-profile-2026-08-27-main--8a4e367) first.**
> The 2026-08-19 runs A/B/C below are kept as the historical record, but their
> `ngx_shmtx_*` shares predate PERF-AUD-01..17, PERF-AUD2-01/04/05/06 and CTB5.
> On current `main` the aggregate fell 28.85% -> 8.00% at `WORKERS=16`. Do not
> quote a number from this section as current.

Measured 2026-08-19 on a 32-core `Intel(R) Core(TM) i9-14900HX`, Debian 13
(trixie), kernel 7.1.3, loopback, `perf_event_paranoid=1`. Build:
`ci-build.sh nginx 1.31.3 profile` (`-O2 -g -fno-omit-frame-pointer`, dynamic
module, no sanitizers/NGX_DEBUG_PALLOC). Workload: `tiny` (200 B) only, per
PLAN-optimize.md P2-2 — at this size the fixed per-hit cost (lock acquire,
lookup, header restore) is close to 100 % of the work, so this is the size
that discriminates the P4-1/P4-2 rankings; `medium`/`large` would be dominated
by memcpy and answer nothing about lock residency.

## Method

`ci/tools/perf-profile.sh` stands up one `cache_turbo` L1-shm edge server
(same shape as `bench.sh` mode C), primes it, verifies **every** measured
request is an L1 HIT via the module's own Prometheus counters (never assumed
from config), then wraps a `wrk` load pass in `perf record -F 999
--call-graph fp -p <worker pid(s)>` for 15 s. `perf report --no-children -g
none` gives the FLAT self-time ranking (perf's default `--children` view
makes every caller up to `main()` inherit 100% of callee time, which buries
the actual hot leaf functions under call-tree roots).

Three passes, holding everything else fixed except `WORKERS`/concurrency, to
see the shm-mutex go from uncontended to contended:

| Run | workers | wrk -c | hit ratio | rps | p50 | p99 | shmtx self-time |
| --- | --: | --: | --: | --: | --: | --: | --: |
| A | 1 | 8 | 100.00% | 162391 | 49us | 60us | **0.73%** |
| B | 8 | 32 | 100.00% | 446656 | 68us | 148us | **9.48%** |
| C | 16 | 64 | 100.00% | 450557 | 123us | 2.28ms | **28.85%** |

Hit ratio verified from `cache_turbo_hits_total` /
`cache_turbo_misses_total` / `cache_turbo_stale_serves_total` deltas around
each `wrk` pass — 100.00 % in all three, i.e. every sampled request really was
an L1 hit and this is genuinely the hit path, not a miss/origin path in
disguise.

**`unresolved_symbol_pct` 0.00 % was measuring something narrower than its
name implies, not "symbols fully resolved".** The metric
(`ci/tools/perf-profile.sh:294-301` as of 2026-08-19) only summed rows whose
symbol column literally contained `[unknown]` or the substring `unknown` —
the case where a sample's IP falls in NO mapped DSO at all. It never matched
a row like `0x000000000026368a`: `perf` DID resolve that address to a DSO
(`libcrypto.so.3`, confirmed below), it just had no name for it because the
installed `.so` ships stripped of that local symbol — `perf`'s own
convention for "DSO known, symbol unknown" is a bare hex address, which
contains neither `[unknown]` nor `unknown` and was invisible to the old
filter. So the genuinely-unresolved 13.53%-self-time row below (2026-08-19
run A) sat in the top 15 while the script reported 0.00% unresolved for that
same run — the metric was correct for what it checks (no-DSO-mapping
frames) but that check is a strict subset of "unresolved symbol", and the
name promised the wider claim. Fixed in this PR
(`ci/tools/perf-profile.sh` now also matches a bare `0x[0-9a-f]+` symbol
column). Confirmed on an unrelated **2026-08-23 M1 re-run** (fresh `perf
record`, same profile build shape, box-condition-dependent so not
numerically comparable to 2026-08-19 — see "13.53% is box-condition
dependent" in PLAN-hitpath-2026-08-23.md): the same address still appears,
now at 1.62% self-time, and the fixed metric reports
`unresolved_symbol_pct=11.32` (283 unresolved rows that run, all mapping
into `libcrypto.so.3`; see below), correctly nonzero where the old formula
said 0.00%.

Run A (`WORKERS=1`) is the baseline: with a single worker nothing else can
ever hold the zone mutex, so it can only show the LOCK'S OWN UNCONTENDED
FAST-PATH COST, never contention. Runs B/C push worker count and wrk
concurrency up together (`WORKERS<=nproc`, `nproc`=32) so multiple workers
genuinely race for the same shared-memory zone mutex — the only way P4-1's
"lock contention on the shm mutex" framing can show up in a profile at all.

## Top self-time symbols

Run A (`WORKERS=1`, uncontended — for reference only, no lock signal to read):

```text
13.53%  ossl_fnv1a_hash [libcrypto.so.3]   (was: 0x...26368a, see note below)
 7.79%  ngx_http_parse_header_line
 7.22%  _int_malloc
 6.66%  ngx_http_cache_turbo_add_header
 6.45%  skb_defer_free_flush          [kernel]
 5.91%  _raw_spin_lock                [kernel — network stack, not shmtx]
 5.69%  _raw_spin_lock_irqsave        [kernel]
 5.07%  tcp_current_mss               [kernel]
 4.80%  skb_clone_tx_timestamp        [kernel]
 4.04%  ngx_http_variable_request
 ...
 (ngx_shmtx_lock/unlock/wakeup combined: 0.73%, not in top 15)
```

**Resolved (M1, 2026-08-23):** `0x000000000026368a` is `ossl_fnv1a_hash`,
`crypto/hashtable/hashfunc.c:20` in `libcrypto.so.3` (Debian
`libssl3t64` 3.5.6-1~deb13u2, build ID `b3fddf655e166a9e68483b6a9125ce717013e7c0`
— matches the box's installed `/usr/lib/x86_64-linux-gnu/libcrypto.so.3`
byte for byte). `nm -D` on that `.so` has no entry for the address or the
name — it is a local/static symbol, stripped from the shared object's
dynamic symbol table, which is why `perf`'s own resolver (which only reads
a DSO's own symtab) could map the sample to the DSO but not to a name.
Proved via `debuginfod.debian.net` with no package install:

```console
$ DEBUGINFOD_URLS=https://debuginfod.debian.net \
    eu-addr2line -f -e /usr/lib/x86_64-linux-gnu/libcrypto.so.3 0x26368a
ossl_fnv1a_hash
./build_shared/../crypto/hashtable/hashfunc.c:20:14
```

Cross-checked against `perf report -i perf.data --sort=dso,symbol -g none
--no-children`, which places the same address under the `libcrypto.so.3` DSO
group — confirming `perf` had the DSO mapping all along and only lacked the
name. `debuginfod-find` itself is not installed on this box; `eu-addr2line`
(elfutils, already present) speaks the debuginfod protocol directly via
`DEBUGINFOD_URLS`, so no `apt-get` was needed.

**Is this the cache-key digest? NO.** `ossl_fnv1a_hash` is OpenSSL 3.x's
internal hashtable hash function (`crypto/property/property.c`'s
`lh_QUERY_hfn_thunk` and friends use the same table implementation), used by
libcrypto's property/provider-fetch machinery to look up an algorithm
implementation by name — not the SHA-256 compression itself
(`sha256_block_data_order`, a *separate* unresolved-hex row in the same
run, 1.21% self-time on the 2026-08-23 re-run). `cache_turbo`'s cache-key
digest calls `EVP_sha256()` + `EVP_DigestInit_ex()` on every request
(`src/ngx_http_cache_turbo_blob.c:95`, `ngx_http_cache_turbo_digest_init()`,
on the hit path via `ngx_http_cache_turbo_digest()`); in OpenSSL 3.x that
convenience path re-resolves the SHA-256 provider implementation through a
libctx hashtable lookup on *every call* rather than caching a
once-fetched `EVP_MD *`, and `ossl_fnv1a_hash` is that lookup's hash
function — so the cost is real and is downstream of the digest call site,
but it is OpenSSL 3's per-call provider-fetch tax, not digest computation.
Left as a D3 design-fork input, not actioned here (M1 is resolve-only).

Run B (`WORKERS=8`, wrk `-c32`):

```text
 3.54%  ngx_shmtx_lock                 <- #1 user-space symbol
 2.21%  ngx_http_cache_turbo_header_admissible   (P4-3's target — visible too)
 1.66%  nft_do_chain                   [kernel, netfilter]
 1.61%  tcp_ack                        [kernel]
 1.37%  entry_SYSRETQ_unsafe_stack     [kernel]
 1.36%  select_idle_core               [kernel, scheduler]
 1.35%  skb_defer_free_flush           [kernel]
 1.19%  ngx_http_cache_turbo_access_handler
 1.11%  ngx_http_header_filter
 1.10%  tcp_rcv_established            [kernel]
 ...
 (ngx_shmtx_* combined: 9.48%)
```

Run C (`WORKERS=16`, wrk `-c64`):

```text
11.50%  ngx_shmtx_lock                 <- clear #1, more than 2nd+3rd combined
 1.81%  tcp_ack                        [kernel]
 1.62%  _raw_spin_lock_irqsave         [kernel]
 1.53%  ngx_http_cache_turbo_header_admissible
 1.53%  tcp_rcv_established            [kernel]
 1.51%  select_idle_core               [kernel]
 1.39%  skb_release_data               [kernel]
 1.30%  nft_do_chain                   [kernel]
 1.21%  skb_defer_free_flush           [kernel]
 1.08%  tcp_recvmsg_locked             [kernel]
 ...
 (ngx_shmtx_* combined: 28.85%)
```

Full `perf.data` + `perf-report.txt` for all three runs are not committed
(regenerated per run under `ci/tools/perf-out/`, gitignored — perf.data alone
was 3–61 MB per pass); the table and symbol excerpts above are the durable
record. Re-run with `ci/tools/perf-profile.sh` to regenerate.

## Re-profile 2026-08-27 (`main` @ `8a4e367`)

Re-run per the cycle-4 handoff: the standing run B/C numbers came from an older
base, and PERF-AUD-01..17, PERF-AUD2-01/04/05/06 and CTB5 have merged since.
Same box, same harness, same `tiny`/base-key workload; build
`BUILD_ROOT=$PWD/.build-perf ci/tools/ci-build.sh nginx 1.31.3 profile`
(verified: nginx/1.31.3, `with debug_info`, `not stripped`, 0 sanitizer symbols
in the `.so` — the exit code alone was not trusted). Hit ratio verified 100.00%
from the module's own counters on both passes.

| Run | workers | wrk -c | hit ratio | rps | p50 | p99 | shmtx self-time | unresolved |
| --- | --: | --: | --: | --: | --: | --: | --: | --: |
| W1 | 1 | 8 | 100.00% | 191717 | 39us | 115us | **0.90%** | 2.51% |
| W16 | 16 | 64 | 100.00% | 498485 | 106us | 2.48ms | **8.00%** | 0.93% |

Against the 2026-08-19 baseline, holding worker count fixed:

| metric | 2026-08-19 | 2026-08-27 | delta |
| --- | --: | --: | --- |
| `ngx_shmtx_lock` self, W=16 | 11.50% | **3.10%** | -8.40pp |
| `ngx_shmtx_*` aggregate, W=16 | 28.85% | **8.00%** | -20.85pp |
| `ngx_shmtx_*` aggregate, W=1 | 0.73% | 0.90% | +0.17pp (noise) |
| rps, W=16 | 450557 | 498485 | +10.6% |

W1 (`WORKERS=1`, wrk `-c8`) — uncontended, no lock signal to read:

```text
 2.94%  nft_do_chain                              [kernel, netfilter]
 2.71%  ngx_http_cache_turbo_access_handler       <- #1 user-space symbol
 2.40%  ngx_http_header_filter
 2.27%  __memmove_avx_unaligned_erms
 1.86%  entry_SYSRETQ_unsafe_stack                [kernel]
 1.37%  net_rx_action                             [kernel]
 1.21%  ngx_vslprintf
 1.16%  __tcp_transmit_skb                        [kernel]
 1.04%  nf_conntrack_tcp_packet                   [kernel]
 0.98%  ngx_http_parse_request_line
 ...
 (ngx_shmtx_* combined: 0.90%; ngx_slab_*_locked: absent from the report)
```

W16 (`WORKERS=16`, wrk `-c64`) — contended:

```text
 3.10%  ngx_shmtx_lock                            <- still #1 user-space, but see below
 2.48%  ngx_http_cache_turbo_access_handler
 2.34%  available_idle_cpu                        [kernel, scheduler]
 1.92%  _raw_spin_lock_irqsave                    [kernel]
 1.66%  skb_release_data                          [kernel]
 1.57%  nft_do_chain                              [kernel, netfilter]
 1.52%  __memmove_avx_unaligned_erms
 1.44%  net_rx_action                             [kernel]
 1.40%  tcp_ack                                   [kernel]
 1.31%  tcp_sendmsg_locked                        [kernel]
 1.20%  entry_SYSRETQ_unsafe_stack                [kernel]
 1.20%  tcp_recvmsg_locked                        [kernel]
 1.19%  ngx_http_cache_turbo_blob_cleanup
 1.14%  _copy_from_iter                           [kernel]
 1.08%  native_queued_spin_lock_slowpath          [kernel]
 ...
 (ngx_shmtx_* combined: 8.00%; ngx_slab_*_locked: absent from the report)
```

### What changed in the ranking

- **`ngx_shmtx_lock` is still the #1 user-space symbol under contention, but it
  no longer dominates.** The 2026-08-19 note "more than 2nd+3rd combined" is no
  longer true: 3.10% against 2.48% + 1.19%. Most of the W16 top-15 is now kernel
  network/scheduler work, not module work — the profile has shifted from
  lock-bound toward network-bound.
- **`ngx_http_cache_turbo_access_handler` is the highest-value module-owned
  target now** — #2 at W16 (2.48%) and the #1 user-space symbol at W1 (2.71%),
  i.e. above `ngx_shmtx_*` in the uncontended case, so its cost is real work on
  the hit path rather than a contention artifact.
- **`ngx_http_cache_turbo_blob_cleanup`** appears at 1.19% at W16 and is absent
  from W1's top-15 — contention-scaled, worth a look alongside lock residency.
- **`ngx_http_cache_turbo_header_admissible`** (P4-3's target, 2.21%/1.53% in the
  old runs) has dropped out of both top-15s.
- **`ngx_http_header_filter` at 2.40% (W1)** is up from run B's 1.11%, but this
  does **not** reopen D4. D4 was closed on its correctness clause — the header
  block is not constant across hits (`Age`, `X-Cache`, `Surrogate-Key`, the 304
  and 206 branches) — which a profile cannot overturn. It is absent from W16's
  top-15.

### Routing decision

Per the cycle-4 handoff's own rule ("shmtx materially reduced -> re-rank; the
2026-08-25 ruling simply stands"): **the stripe carve stays CLOSED.** This
re-profile is the "real profile" that ruling named as the bar for reconsidering,
and it moves the number in the direction that keeps the row shut, not open. The
untried lock angle remains RESIDENCY / acquisition COUNT (shorter critical
sections, batching, fewer acquisitions) — never sharding the pool.

Raw `perf.data` + `perf-report.txt` under `ci/tools/perf-out/w1/` and
`ci/tools/perf-out/w16/` (gitignored, not committed); the excerpts above are the
durable record.

**Only the aggregate symbol-level tables above (`perf report`, function-level)
were committed for this run — no `--sort srcline` per-line breakdown was
captured or preserved.** A prior scoping pass cited specific per-line numbers
(e.g. an `ngx_crc32.h` line range at ~1% self-time) as if they were measured
here; they were not, and cost a full worker cycle chasing a change that
measurement later showed removes zero work. Any future srcline-level claim
must be re-measured with `perf report --sort srcline` (or equivalent) and
committed to this file before it is used to scope work — do not reconstruct
or estimate one from the aggregate numbers above.

## Verdict

> **P4-2's verdict below is the 2026-08-19 reading and is now PARTLY
> SUPERSEDED.** The direction still holds — `ngx_shmtx_lock` still scales with
> worker pressure and is still the #1 user-space symbol at `WORKERS=16` — but
> the magnitude does not: as of 2026-08-27 on `main` @ `8a4e367` the figures are
> 0.90% / — / 3.10% (aggregate 8.00%), not 0.73% / 3.54% / 11.50% (aggregate
> 28.85%). "Ahead of every other cache_turbo function" is also no longer a
> comfortable margin: `access_handler` sits 0.62pp behind it. See
> [Re-profile 2026-08-27](#re-profile-2026-08-27-main--8a4e367).

- **P4-2 ("reduce hit-path lock residency") — CONFIRMED.**
  `ngx_shmtx_lock` alone rises from 0.73 % → 3.54 % → 11.50 % self-time as
  worker/concurrency pressure on the shared zone mutex increases, becoming
  the single largest user-space symbol in the profile at both `WORKERS=8` and
  `WORKERS=16` — ahead of every kernel networking symbol and every other
  cache_turbo function. Total `ngx_shmtx_*` self-time (lock + unlock +
  wakeup) reaches 28.85 % at `WORKERS=16`. p99 latency also degrades
  non-linearly between run B and C (148 µs → 2.28 ms) while rps stays flat
  (446k → 450k) — the classic signature of a saturated critical section, not
  more useful work getting done. This is a real, measurable, and large cost
  on the `tiny` hit path exactly where PLAN-optimize.md's P4-2 row said to
  look (`access.c:1210`, held across `vary_apply`, the lookup,
  `stale_window`/`effective_load`, `req_bounds`, `touch_lru`). **P4-2 is
  worth paying for.**

- **P4-1 ("W-TinyLFU admission control") — profiling cannot confirm or
  refute this one; it is the WRONG TOOL for the claim.** P4-1's stated payoff
  is hit-RATIO improvement under a skewed/Zipf key distribution (fewer
  one-hit-wonders evicting resident hot entries), not CPU time on the hit
  path — a `perf` profile of a 100 %-hit single-key `tiny` workload cannot
  observe an admission-control effect because there is no eviction pressure
  in this workload at all (one hot key, generous zone, nothing ever evicted).
  What this profile DOES show, incidentally, is that `store_locked`/
  `alloc_evict` (P4-1's insertion point) do not appear anywhere in the
  self-time top 15 of any run — unsurprising on a pure-hit workload, and not
  evidence either way about P4-1's ranking. **P4-1 needs the P2-1 Zipf
  harness (`ci/tools/zipfbench.sh`), already landed in PR #352, to validate
  — not this tool.** Recorded here so a future session doesn't re-attempt
  proving P4-1 from a perf profile.

## CI

Not wired into CI. `perf record` needs a build with debug symbols and frame
pointers (a separate `ci-build.sh … profile` build from every existing CI
job), costs 15–20 s of sustained load per pass, and its usefulness is
qualitative (read the symbol list) rather than a pass/fail assertion — there
is no meaningful automatic gate to write against a flat symbol table without
also asserting exact percentages that will drift with kernel version, NIC
driver, and hardware between CI runs. Kept as a manually-run bench, same
category as `ci/tools/bench.sh`/`ci/tools/soak.sh`.
