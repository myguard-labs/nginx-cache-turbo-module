# Benchmarking nginx-cache-turbo

How fast does cache-turbo serve, and how does that compare to the alternatives?
This page documents the method, a reproducible harness, and a reference result
set. For what the module *is* and how to configure it, see
[README.md](README.md); for the correctness/stability story (does it survive
churn under ASAN/valgrind?) see [`tools/soak.sh`](ci/tools/soak.sh) — a different
question from the one here.

> **TL;DR.** On a stock-defaults nginx build, cache-turbo serves cached pages
> **23–37 % faster than nginx's own `proxy_cache`** for small/medium bodies and
> **~10 % faster** for multi-megabyte bodies, at lower median latency. Tail
> (p99) is lower for small/medium bodies; on `large` it is at parity with
> proxy_cache — see "On `large` p99 specifically" below before quoting it.
> Versus going to the origin every time, any cache (turbo or proxy_cache) is
> **20–25× faster** — caching is the big win; beating proxy_cache is the
> incremental one.

---

## TL;DR numbers

Stock `-O` build, loopback, 100 % cache hit, single hot key, 10 s/run @ 50
connections. Full environment + caveats below — **read them before quoting any
absolute number.**

| Payload | metric | origin&nbsp;direct | proxy_cache | **cache_turbo&nbsp;(shm)** | cache_turbo&nbsp;(redis) |
|---|---|--:|--:|--:|--:|
| **tiny** 200 B   | req/s | 23.3k | 492.7k | **604.9k** | 605.6k |
|                  | p50   | 336 µs | 59 µs | **48 µs** | 47 µs |
|                  | p99   | 7.89 ms | 145 µs | **115 µs** | 114 µs |
| **medium** 200 KB| req/s | 14.7k | 41.4k | **56.8k** | 56.7k |
|                  | p50   | 1.84 ms | 711 µs | **522 µs** | 522 µs |
|                  | p99   | 12.35 ms | 2.18 ms | **1.46 ms** | 1.53 ms |
| **large** 4 MB   | req/s | 1.0k | 2.51k | **2.75k** | 2.86k |
|                  | p50   | 27.0 ms | 11.85 ms | **10.04 ms** | 9.90 ms |
|                  | p99   | 216.7 ms | 25.52 ms | 37.38 ms | 31.09 ms |

**cache_turbo vs proxy_cache:** tiny **+23 %**, medium **+37 %**, large **+10 %**.

---

## How to reproduce

The harness is [`tools/bench.sh`](ci/tools/bench.sh). It needs `wrk`
(`apt-get install wrk`) and, for the Redis run, a local `redis-server`.

```console
# 1. Build a stock-defaults nginx + the dynamic module.
#    The "nginx" mode = empty --with-cc-opt (nginx's own -O), no
#    NGX_DEBUG_PALLOC, no --with-debug. NOT a sanitizer build.
$ eval "$(ci/tools/ci-build.sh nginx 1.31.1 nginx)"     # exports binary= module=

# 2. Run the matrix (tiny+medium by default; add large + the Redis tier).
$ SIZES="tiny medium large" \
  REDIS="redis://127.0.0.1:6379/0" \
  MODULE="$module" \
  ci/tools/bench.sh "$binary" 10 50                      # 10 s/run, 50 connections
```

`tools/bench.sh <nginx-binary> [duration_s] [concurrency]`, env knobs:

| var | meaning | default |
|---|---|---|
| `SIZES`   | subset of `tiny medium large` | `tiny medium` |
| `REDIS`   | DSN → adds the L2-Redis run (D) | unset (D skipped) |
| `MODULE`  | path to the `.so` for a dynamic build (adds `load_module`) | unset (assume static) |
| `THREADS` | wrk worker threads | `min(conc, nproc)` |

> ⚠️ **Build matters more than anything.** A debug/ASAN binary is 10–50× slower
> and tells you nothing about real throughput. Use the `nginx` mode above. The
> sibling `tools/ci-build.sh ... asan` and `tools/soak.sh` are for the *opposite*
> job: proving the module doesn't corrupt memory under load. Don't benchmark
> those binaries.

---

## Method

`bench.sh` stands up **one** nginx process holding an origin plus four edge
servers on separate ports, so every contender shares the same backend, payloads,
kernel, and CPU — only the cache layer differs:

| run | label | what it is |
|---|---|---|
| **A** | `origin-direct`     | edge proxies straight to origin, no cache — the **floor** |
| **B** | `proxy_cache`       | nginx's built-in `proxy_cache` (disk-backed) — the **competitor** |
| **C** | `cache_turbo-shm`   | cache-turbo, L1 shared-memory only |
| **D** | `cache_turbo-redis` | cache-turbo + an L2 Redis tier (only if `REDIS=` set) |

For each `(size, run)` cell the harness:

1. **Primes** the key and *verifies it is actually cached* — it loops requests
   until the response reports `X-Cache: HIT` (C/D) or `X-Cache-Status: HIT` (B).
   If it never hits, the run **aborts** rather than silently benchmarking the
   origin. This is the single most important guard: a "fast" cache result that
   secretly missed is worthless.
2. Runs **one warm-up** `wrk` pass and discards it (TCP windows, shm fault-in).
3. Snapshots cache-turbo's Prometheus counters, runs the **measured** `wrk
   --latency` pass, snapshots again, and derives the **HIT %** for that pass from
   `cache_turbo_hits_total + stale_serves_total` over the total. A primed
   long-TTL run that shows < 100 % means something bypassed the cache —
   investigate before trusting the rps.

### Workload shape

- **Payloads:** random base64 of 200 B (`tiny`), 200 KB (`medium`), 4 MB
  (`large`) — same generator as `tools/soak.sh`, so the two tools exercise the
  same capture and serve paths. Note this exercises the multi-buf serve chain
  (P4-5): a 4 MB body is emitted as ~128 zero-copy 32 KB bufs into one
  refcounted blob, not as one buffer.
- **Steady state, not churn:** big zones (64 MB) + long TTL (60 s) so the run is
  a **pure-hit** measurement — no eviction, no revalidation. That isolates raw
  serve cost. (Eviction/SWR/single-flight under churn are what `soak.sh`
  stresses, deliberately not measured here.)
- **Keying:** one hot key per size → maximal cache locality, best case.
- `access_log off`, `worker_processes auto`.
- `cache_turbo_max_size 16m` on C/D (the default `1m` would refuse the 4 MB
  body; `proxy_cache` has no default size cap).

---

## Reference environment

The numbers in this doc were produced here. **They are loopback, single-box
numbers — treat the *gaps between runs* as the signal, not the absolute rps.**

| | |
|---|---|
| CPU       | Intel Core i9-14900HX (32 threads) |
| RAM       | 31 GiB |
| OS        | Debian 13 (trixie), kernel 6.12.90 |
| Compiler  | gcc 14.2.0 |
| nginx     | 1.31.1, `--with-compat`, empty `--with-cc-opt` (stock `-O`), dynamic `.so` |
| load gen  | wrk 4.1.0 (epoll) |
| L2        | redis 8.8.0, loopback |
| run       | 10 s/run, 50 connections, 32 wrk threads, warm-up discarded |
| date      | 2026-06-13 |

---

## Reading the numbers

- **req/s** — throughput, higher is better.
- **p50 / p99** — median and 99th-percentile request latency, lower is better.
  p99 is the tail: the slowest 1 % of requests, i.e. the "sometimes it's slow"
  a user actually notices.
- **HIT %** — fraction served from cache; 100 % confirms we measured the cache,
  not the backend.

**Two separate wins.** *Caching at all* (A → any cache) buys ~20–25×: on `tiny`,
23k → ~600k rps, because a hit skips the whole upstream round-trip. *cache-turbo
over proxy_cache* (B → C) is the incremental win this module exists for.

**Why the edge over proxy_cache shrinks as bodies grow** — tiny +23 %, medium
+37 %, large +10 %. For small bodies the wall-clock is dominated by cache
bookkeeping (lookup, header assembly), where cache-turbo's RAM path is leaner
than proxy_cache's disk-cache machinery.

For a 4 MB body the cache layer is a small share of the total, so the gap
narrows — but **not** because "every contender pays the same memcpy". An
earlier revision of this page said exactly that and it was wrong in
cache-turbo's favour: a cache-turbo hit does **not** pay proxy_cache's copy.
The body is served straight out of the shm slab, pinned by a refcount for the
life of the response (`ngx_http_cache_turbo_serve()`), so there is no
cache→request copy at all, while proxy_cache reads the body through its own
file/buffer machinery. What actually dominates at 4 MB is the kernel-side cost
of pushing the bytes out the socket plus the client's own read, which is
common to both — and that common floor, not a shared memcpy, is what compresses
the relative gap.

**On `large` p99 specifically.** Throughput and p50 are clearly ahead
(~3.1–3.3k vs ~2.4–2.5k rps; ~8.6 ms vs ~12.7 ms p50), but p99 is roughly at
**parity** with proxy_cache and jitters to either side between runs — measured
across four 5-pass runs, cache-turbo landed anywhere in 29.8–34.3 ms against
proxy_cache's 23.4–32.3 ms. Treat the `large` p99 column as "no reliable
difference", not as a win or a loss; the run-to-run spread on a loopback
single-box bench is larger than the gap. An earlier note here attributed the
`large` p99 to "multi-buffer serves have more scheduling variance", which was
doubly wrong: the serve was a *single* buffer at the time, and when it was
later split into a 32 KB multi-buf chain (P4-5) the p99 did not measurably
move in either direction.

**Redis ≈ shm, by design.** An L1 (RAM) hit **never touches Redis** — Redis is
read only on an L1 *miss* and written through on store. So on a 100 %-hit bench
the Redis tier is invisible to throughput; its payoff is sharing one cache across
a *fleet* of boxes (warm a cold box from a peer's fill), which a single-box bench
cannot show.

---

## What this does NOT measure

This is a best-case, steady-state micro-benchmark. It is honest about hits and
nothing else. It deliberately omits:

- **Misses, eviction, and the cold-fill path** — big zones + one hot key means
  nothing is ever evicted and almost nothing misses.
- **Stale-while-revalidate / single-flight / autotune** under real churn — see
  `tools/soak.sh` for the path that stresses those.
- **Network reality** — loopback has no RTT, no loss, no TLS, no real client
  concurrency mix.
- **Real key distributions** — production traffic is many keys with a long tail,
  not one hot key. See [`tools/zipfbench.sh`](#zipf-multi-key-hit-ratio--throughput-harness)
  below for the harness that covers this.
- **Cross-box L2 behaviour** — the whole point of the Redis tier, untestable on
  one host.

For correctness/stability under those harder conditions, that is `soak.sh`'s job,
not this one.

---

## Zipf multi-key hit-ratio + throughput harness

`bench.sh` above answers "how fast is a hit"; it cannot answer "how often do we
get one" — it primes every key first, so HIT % is ~100 % by construction on a
single hot key. [`tools/scanbench.sh`](ci/tools/scanbench.sh) covers one specific
churn shape (a one-shot crawl against a hot set). Neither exercises a real
multi-key request distribution, so neither can validate anything that depends on
*which* key gets evicted: admission policy, eviction ordering, or working-set
sizing. [`tools/zipfbench.sh`](ci/tools/zipfbench.sh) fills that gap.

It drives a **Zipf(s)-distributed** stream of requests over a configurable
key-space — a small number of keys take most of the traffic, with a long tail,
the shape real cache traffic actually has — from **multiple concurrent
workers** (`xargs -P`, real parallel `curl` processes, not a serial loop), with
**no priming pass**: whatever misses, misses, because the distribution and the
zone size say it should.

### What it measures

- **HIT ratio** — from the edge access log's `$cache_turbo_status` field (a
  logging variable; an `add_header` readback of it is documented elsewhere in
  this file as unreliable on the deciding request, so the harness reads the
  log the same way `scanbench.sh` does).
- **p50 / p99 latency** — from `curl -w '%{time_total}'` per request.
- **Origin request count** — read from the **origin's own access log**, not
  inferred from the edge's status counts. This is the number that matters
  most: it is the real offload figure, and an edge-side HIT/MISS tally can be
  wrong under concurrent fills or a status variable that races the response
  write. The origin log has no cache-status field at all — it is ground truth
  for "did a request reach the backend", independent of what the edge believes
  about itself.

### How to run it

```console
$ eval "$(ci/tools/ci-build.sh nginx 1.31.3 nginx)"     # exports binary= module=
$ KEYS=5000 ZIPF_S=1.0 ZONE=8m WORKERS=8 REQS=20000 \
  ci/tools/zipfbench.sh "$binary" "$module"
```

| var | meaning | default |
|---|---|---|
| `KEYS`    | size of the key-space | `5000` |
| `ZIPF_S`  | Zipf exponent — higher = more skewed toward a few hot keys | `1.0` |
| `ZONE`    | `cache_turbo_zone` size | `8m` |
| `BODY`    | body bytes per key | `2048` |
| `WORKERS` | concurrent client workers | `8` |
| `REQS`    | total requests issued | `20000` |
| `PASSES`  | measured passes, reports the median | `1` |

### Choosing parameters

`KEYS * BODY` vs `ZONE` is the knob that puts a run into or out of the eviction
regime **on purpose**:

- `KEYS * BODY` well under `ZONE` → the whole key-space fits, nothing is
  evicted — useful as the *fitting* baseline arm of a comparison.
- `KEYS * BODY` well over `ZONE`, or a flatter `ZIPF_S` (closer to 0, less
  skewed) → the working set overflows the zone and eviction/admission policy
  is actually exercised — the *overflowing* arm.

A real discrimination run pairs the two: same `KEYS`/`BODY`/`WORKERS`/`REQS`,
`ZONE` sized to hold the working set in one arm and deliberately too small in
the other, and reads the HIT ratio gap between them.

**Reference pair** (nginx 1.31.3, `stock -O` build, loopback, `WORKERS=8`,
`BODY=2048`, `REQS=8000`, single pass, 2026-08-19):

| arm | KEYS | ZIPF_S | ZONE | HIT ratio | origin requests |
|---|--:|--:|--:|--:|--:|
| fitting | 200 | 1.0 | 8m | **97.5 %** | 200 / 8000 |
| overflowing | 5000 | 0.7 | 256k | **7.0 %** | 7444 / 8000 |

The 90-point gap is the harness discriminating on a real configuration
difference, not noise — same request count, same body size, same worker count,
only the zone-vs-working-set ratio changed. (Note it does not read a clean
100 % even in the fitting arm: with no priming pass, the first request to any
key is always a MISS, so a fully-resident zone still shows a small, expected
miss floor near `KEYS / REQS`.)

### ⚠ Two self-invalidation traps — copied from `scanbench.sh`

Both were hit while writing this harness. Both produce a plausible-looking
number that actually means the run measured **nothing**:

1. **`ZONE` far bigger than `KEYS * BODY`.** The whole key-space fits, nothing
   is ever evicted, HIT ratio saturates near 100 % regardless of `ZIPF_S` or
   whatever admission policy is under test. A "100 % HIT, looks great" result
   here proves the harness isn't exercising eviction at all — not that the
   config being compared is good.
2. **`ZONE` far smaller than the Zipf head, or `REQS` too low** for the hot
   keys to repeat before their first eviction. The effective working set never
   survives long enough to register a HIT, and every arm reads ~0 % regardless
   of what's being compared.

**A result of 0-vs-0 or 100-vs-100 between two configurations you expected to
differ means "re-tune `ZONE`/`KEYS`/`ZIPF_S`/`REQS`", never "no effect".** The
script detects both degenerate bands itself (HIT ≤ 0.5 % or ≥ 99.5 %) and exits
non-zero with `INVALID RUN` instead of printing a clean-looking number, so a
mis-tuned run cannot be mistaken for a real result further down the pipeline.

---

## See also

- [README.md](README.md) — what the module is, every directive, configuration.
- [`tools/bench.sh`](ci/tools/bench.sh) — pure-hit throughput/latency harness.
- [`tools/scanbench.sh`](ci/tools/scanbench.sh) — scan-resistance under a
  one-shot crawl against a hot set.
- [`tools/zipfbench.sh`](ci/tools/zipfbench.sh) — Zipf multi-key hit-ratio,
  throughput and origin-offload harness (this section).
- [`tools/soak.sh`](ci/tools/soak.sh) — correctness/stability soak under ASAN/valgrind.
- [Monitoring (Prometheus + Grafana)](README.md#monitoring-prometheus--grafana)
  — the same counters bench.sh reads for its HIT % column.
