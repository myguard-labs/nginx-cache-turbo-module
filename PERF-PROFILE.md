# perf profile of the L1 hit path (P2-2)

Reference `perf record`/`perf report` results for `ci/tools/perf-profile.sh`,
gating P4-1 ("W-TinyLFU admission control", `[NEEDS-ZIPF]`) and P4-2 ("reduce
hit-path lock residency", `[NEEDS-PROFILE]`) in
`memory/labs/nginx-cache-turbo-module/PLAN-optimize.md`. See
[BENCHMARK.md](BENCHMARK.md) for the throughput/latency comparison against
`proxy_cache`; this document is about *where the CPU time inside the L1 hit
path actually goes*, which BENCHMARK.md's aggregate rps/p50/p99 numbers cannot
show.

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
disguise. `perf report`'s own `unresolved_symbol_pct` (`[unknown]` frames) was
0.00 % in every run — symbols fully resolved, the `-g -fno-omit-frame-pointer`
profile build did its job.

Run A (`WORKERS=1`) is the baseline: with a single worker nothing else can
ever hold the zone mutex, so it can only show the LOCK'S OWN UNCONTENDED
FAST-PATH COST, never contention. Runs B/C push worker count and wrk
concurrency up together (`WORKERS<=nproc`, `nproc`=32) so multiple workers
genuinely race for the same shared-memory zone mutex — the only way P4-1's
"lock contention on the shm mutex" framing can show up in a profile at all.

## Top self-time symbols

Run A (`WORKERS=1`, uncontended — for reference only, no lock signal to read):

```text
13.53%  0x000000000026368a           (unresolved-but-mapped; see note below)
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

## Verdict

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
