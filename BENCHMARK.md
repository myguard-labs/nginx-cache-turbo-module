# Benchmarking nginx-cache-turbo

How fast does cache-turbo serve, and how does that compare to the alternatives?
This page documents the method, a reproducible harness, and a reference result
set. For what the module *is* and how to configure it, see
[README.md](README.md); for the correctness/stability story (does it survive
churn under ASAN/valgrind?) see [`tools/soak.sh`](ci/tools/soak.sh) — a different
question from the one here.

> **TL;DR.** On a stock-defaults nginx build, cache-turbo serves cached pages
> **23–37 % faster than nginx's own `proxy_cache`** for small/medium bodies and
> **~10 % faster** for multi-megabyte bodies, at lower median and tail latency.
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
  same single-/multi-buffer serve paths.
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
than proxy_cache's disk-cache machinery. For a 4 MB body the time is dominated by
*copying the bytes out the socket*, which every contender pays equally — the
cache layer is noise next to the memcpy, so the gap collapses. (The `large` p99
also goes slightly the other way: multi-buffer serves have more scheduling
variance.)

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
  not one hot key.
- **Cross-box L2 behaviour** — the whole point of the Redis tier, untestable on
  one host.

For correctness/stability under those harder conditions, that is `soak.sh`'s job,
not this one.

---

## See also

- [README.md](README.md) — what the module is, every directive, configuration.
- [`tools/bench.sh`](ci/tools/bench.sh) — this harness.
- [`tools/soak.sh`](ci/tools/soak.sh) — correctness/stability soak under ASAN/valgrind.
- [Monitoring (Prometheus + Grafana)](README.md#monitoring-prometheus--grafana)
  — the same counters bench.sh reads for its HIT % column.
