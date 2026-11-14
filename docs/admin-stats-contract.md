# Current admin statistics contract

`ci/tests/stats-contract.json` records the ordered JSON keys and Prometheus
families, including HELP and TYPE. The JSON renderer emits a compact object and
newline; Prometheus emits HELP, TYPE and one zone-labelled sample per family.
The admin location's effective `lock_ttl` occurs only in JSON. `cost_ms` maps
to `cache_turbo_regen_cost_ms`; `breaker_state` is a string in JSON and 0, 1,
or 2 in Prometheus. Other Prometheus names use the JSON key with the
`cache_turbo_` prefix and, for counters, `_total` suffix. This describes the
current output, including the historical TYPE choices.

A scrape reads counters separately, not as a globally atomic snapshot.
The capacity scalars `used_bytes`, `zone_reserved_bytes` and `zone_size_bytes`
are sampled together under the slab mutex in O(1) time, then rendered after
unlock. `zone_size_bytes` is the full configured mapping; reserved bytes are
that size minus wholly free slab pages. Reserved bytes include allocator
metadata, fixed zone allocations and bin slack, while the existing used gauge
keeps its payload/metadata charge semantics. Empty, full and reloaded zones
satisfy `used_bytes <= zone_reserved_bytes <= zone_size_bytes`. GET and
HEAD, including the legacy `autotune=1` query, do not force autotuning. A scrape
reads the breaker's stored state; it does not advance an expired OPEN breaker.

The zone directive accepts a nonempty nginx configuration token. The nginx
configuration parser determines which bytes can be represented. Quoted tokens
can represent a quote, a backslash, and a newline. The schema renderer now
escapes these as `\"`, `\\` and `\n` in Prometheus label values. This intentionally
repairs the historical literal insertion of these bytes, which could produce
invalid exposition. Labels needing no escaping retain their exact historical
bytes. JSON keys and string values use JSON escaping, including control bytes;
the zone name is not a JSON field. The focused test covers these label cases,
punctuation and an ordinary name, plus empty-name rejection.

A private typed descriptor table supplies names, historical HELP/TYPE, source
member offsets and per-format order. One bounded snapshot contains the backend
stats and the admin location's effective `lock_ttl`; it adds no shared state.
The renderer first measures descriptor prose, escaped labels and full atomic or
signed time widths, then allocates once and bounds every append. Overflow or a
short buffer fails closed without sending partial JSON or exposition. This
admin-only work introduces no cache request-path allocation or lock. The
capacity sample adds one bounded admin-only mutex hold.

The table maps each field to every production writer function and its relevant
conditional classes. Function names omit the common `ngx_http_cache_turbo_`
prefix; `access`, `filters`, `shm`, `module`, `autotune`, and `conf` refer to
the corresponding `src/ngx_http_cache_turbo_*.c` files. All shared fields are
also initialized by `shm:shm_init_zone`. Reads in renderers, probes and purge
completeness calculations are not writers.

<!-- markdownlint-disable MD013 -- source mapping table -->

| JSON field(s) | Writers and conditions beyond initialization |
| --- | --- |
| hits | `access:access_l1_serve_fresh`, `access_l2_promote_serve`, `access_cold` (fresh entry found on either cold-resolution path) |
| misses | `access:decline_ambiguous_request`, `access_prologue` (bypass or expired/policy paths), `access_breaker_gate`, `access_min_uses`, `cold_resume_locked`, `access_cold`, `access_handler`, `cold_wait` (timeout/resume/fallback paths) |
| stale_serves | `access:access_l1_serve_stale`, `access_only_if_cached`, `access_breaker_gate`, `cold_wait` (stale and error fallback delivery paths) |
| refreshes | `access:access_l1_serve_stale` (refresh initiation), `filters:header_filter_freshen_304` |
| evictions | `shm:shm_evict_one` (both LRU victim branches) |
| l2_hits, l2_misses | `access:access_l2_promote_serve`, `access_l2_miss_account`, respectively |
| lock_waits | `access:cold_wait` (entering wait) |
| min_uses_skips | `access:access_min_uses`, `access_cold` (below-threshold paths) |
| l2_neg_skips | `access:access_l2_marker_get`, `access_l2_neg_memo` |
| bypasses | `access:decline_ambiguous_request`, `access_prologue` (bypass branches) |
| refuse_set_cookie, refuse_encoded, refuse_cache_control, refuse_require_header | `filters:capture_count_refusal` (corresponding reason branches) |
| refuse_vary_unsafe | `filters:header_filter_capture` (unsafe Vary branch) |
| refuse_authorization | `access:access_eligible`, `filters:capture_count_refusal` |
| refuse_partial, refuse_head | `filters:capture_count_head_partial` (corresponding request/response branch) |
| cost_ms | Derived in `shm:shm_stats` from `cost_sum_ms` and `cost_count`, both advanced by `autotune:autotune_record_cost` |
| autotuned_beta, autotuned_load | `autotune:autotune_recompute_locked` publishes both only for a nonnegative verdict |
| breaker_state | `shm:shm_breaker_state` (OPEN promotion and lease reclaim), `shm_breaker_record` (failure/open, probe success/close and failure/reopen transitions) |
| breaker_opens | `shm:shm_breaker_record` (successful CLOSED-to-OPEN transition) |
| sie_serves | `filters:header_filter_try_sie`, `body_filter_midbody_rescue`, `access:cold_wait` |
| breaker_serves | `access:access_only_if_cached`, `access_breaker_gate` |
| origin_failures | `filters:header_filter_record_breaker` (response failure and retry-failure replay) |
| varidx_drops | `filters:body_filter_varidx_store` (pre-transport index write failure) |
| tag_index_drops, tag_cap_drops | `filters:body_filter_tag_index` (index write failure and tag cap truncation, respectively) |
| bg_inflight | `module:warm_one` (bounded reservation and error unwind), `bginflight_cleanup` (subrequest pool cleanup) |
| sketch_gen, sketch_bumps, admission_refused | `shm:sketch_halve`, `shm_sketch_bump`, `shm_admit`, respectively |
| used_bytes | `shm:shm_alloc_evict` (successful allocation), `shm_free_locked` (free or underflow clamp) |
| markers | `shm:shm_store_marker` (new marker), `shm_evict_one` (both LRU branches), `shm_drop_locked` |
| lock_ttl | `conf:lock_ttl_conf` parses and clamps; `conf:merge_presets` sets the effective admin-location configuration |

<!-- markdownlint-enable MD013 -->

`shm:shm_init_zone` reuses the old shared zone on reload, retaining all of the
shared values above, including an OPEN breaker, while a fresh zone is initialized
anew. A full stop and start creates fresh shared memory: the fields initialize to
zero, except `breaker_state` starts CLOSED. `lock_ttl` is location configuration
and is re-parsed and merged on reload or restart, not inherited as a shared
counter. The focused runtime test checks hits and misses over reload and full
restart; the other fields' lifecycle here is traced from the initialization and
reuse paths, not individually exercised across a reload.

The lifetime counters (`hits`, `misses`, `stale_serves`, `refreshes`,
`evictions`, `l2_hits`, `l2_misses`, `lock_waits`, `min_uses_skips`,
`l2_neg_skips`, `bypasses`, all `refuse_*`, `breaker_opens`, `sie_serves`,
`breaker_serves`, `origin_failures`, `varidx_drops`, `tag_index_drops`, and
`tag_cap_drops`) are `ngx_atomic_t` and increment with unsigned machine-word
arithmetic. They wrap modulo the atomic width, with no saturating or reset
operation on overflow. Nginx's `ngx_atomic_t` is a volatile unsigned atomic word;
its precise width follows the nginx platform. The module rejects a 32-bit
pointer layout and asserts sufficient atomic width for its breaker word
(`module.h` packed-probe layout guard), so do not infer support for a 32-bit
build. `sketch_gen`, `sketch_bumps`, and `admission_refused` are mutex-protected
`ngx_uint_t` counters and wrap modulo that unsigned native width; sketch aging
resets the cursor, not `sketch_gen` or the lifetime `sketch_bumps` value.

`markers` is an atomic live gauge: insertion adds and actual removal subtracts;
its arithmetic is modular if bookkeeping overflows or underflows. `bg_inflight`
is an atomic live gauge incremented only when a nonzero cap is configured;
zero cap means unlimited and does not track inflight work. Reservation and
cleanup use unsigned atomic addition/subtraction, with an upper-cap check on
reservation and no saturation on subtraction. `used_bytes` is a mutex-protected
`ngx_uint_t` gauge: successful allocation adds with native unsigned arithmetic;
free subtracts if sufficient, otherwise logs an alert and clamps to zero. These
gauges can decrease and are not lifetime counters.

`cost_ms` is an unsigned integer quotient of independently read atomic
`cost_sum_ms` and `cost_count`; zero count produces zero. Both accumulators wrap
modulo atomic width, so a wrapped count can trigger that zero sentinel and the
quotient is not a monotonic counter. `autotuned_beta` and `autotuned_load` are
atomic stored verdicts rather than accumulators: recomputation takes unsigned
window differences, keeps the previous values for a negative/insufficient-data
verdict, and otherwise publishes the calculated values with beta/load clamps.
Zero beta means use the preset; zero or 1000 load means baseline. Intermediate
unsigned window arithmetic follows native width and can wrap before the final
clamp. Neither value is promised monotonic.

`breaker_state` is a string derived from the low state bits of a packed atomic
word (Prometheus emits the corresponding 0/1/2). The generation bits wrap under
their masks and promotion skips the zero lease sentinel; the packed probe's
generation and relative timestamp each use their documented masked widths.
The displayed state is a state-machine result, not an increasing counter.
`lock_ttl` is a signed `time_t` rendered only in JSON; explicit zero is rejected
and oversized configuration is clamped to `NGX_HTTP_CACHE_TURBO_TTL_MAX`, so
it has configuration/clamp semantics rather than counter wrap semantics. None
of these individually read fields form a globally atomic snapshot, and the
unlocked diagnostics do not establish a concurrency-consistent capacity
inequality.
