# The stripe seam: classification and the s3c debt

Status as of this document: **the seam is a shape, not a striping.**
`NGX_HTTP_CACHE_TURBO_STRIPES` is 1, every hot path pins stripe 0, and bumping
N today would not stripe anything — it would carve N pools nothing routes to.
This file records which call sites are key-directed, why none of them can be
converted yet, and exactly what s3c owes.

## The two resolvers

`src/ngx_http_cache_turbo_module.h` defines both, and they are the only code
allowed to index `->stripes[]`:

| resolver | takes | returns | for |
| --- | --- | --- | --- |
| `ngx_http_cache_turbo_stripe_of(z, key)` | a 32-bit key hash | `&z->stripes[key % z->nstripes]` | state belonging to ONE cache key |
| `ngx_http_cache_turbo_zone_stripe(z)` | nothing | `&z->stripes[0]`, hard-wired | state belonging to the WHOLE zone |

`ngx_http_cache_turbo_zone_sh(z)` / `_zone_pool(z)` / `_zone_mutex(z)` are sugar
over the **zone-wide** resolver.

At N == 1 the two are indistinguishable: `anything % 1 == 0`, so `stripe_of()`
returns `&stripes[0]` for every possible input. That identity is what makes the
seam safe to introduce, and it is also why nothing about it can be tested at the
shipped N — see `ci/tests/unit/test_stripe_resolver.c`, which compiles the
production resolver bodies at a forced N of 8 and 7 to get the arithmetic under
assertion at all.

## Call-site census

Measured over `src/*.c`:

- **~290** sites use the zone-wide resolver or its sugar macros.
- **0** sites call `stripe_of()`. Its only appearance in a `.c` file is inside a
  comment in `shm_init_zone()`.

So every lookup, store, purge and eviction in the module currently takes stripe
0's mutex, whatever N says.

## Classification

### Genuinely zone-wide — correct as written at any N

Init and teardown (`ngx_http_cache_turbo_shm_init_zone`), the admin/Prometheus
stats reader, the autotune recompute (`src/ngx_http_cache_turbo_autotune.c`),
the breaker state machine (`shm_breaker_state`, `shm_breaker_record`,
`shm_brk_probe_age`), and `shm_purge_all`.

These read or write state that is a property of the zone, not of a key. Under
s3c most of them still want a single home, so pinning stripe 0 stays right — the
exceptions are called out under **residual debt** below.

### Key-directed — must resolve from the key's hash once N > 1

Eighteen functions, all in `src/ngx_http_cache_turbo_shm.c`. This list is the
authoritative one; it is duplicated as the `KEY_DIRECTED` ledger in
`ci/tools/lint-stripe-seam.sh`, which fails the build if the two disagree with
the code:

`shm_lookup`, `shm_store`, `shm_store_locked`, `shm_store_if`,
`shm_store_marker`, `shm_purge_key`, `shm_freshen`, `shm_drop_locked`,
`shm_admit`, `shm_claim`, `shm_claim_locked`, `shm_unstub`, `shm_owns`,
`shm_resolve_miss`, `shm_l2_neg_check`, `shm_l2_neg_set`,
`shm_varidx_pending_set`, `shm_touch_lru`.

Each already receives the key's 32-bit `hash` (or its owner's node), so no
signature change is needed to convert them — the hash is in scope at every one.

## Why none of them is converted in this change

**A key-directed site cannot be converted before the pools are carved.** The
conversion is not a spelling change, because these functions do not touch only
per-key state. Every one of them interleaves per-key work with zone-shared work
*inside a single mutex hold*:

- `shm_store_locked` inserts into `zone_sh(z)->rbtree`
  (`src/ngx_http_cache_turbo_shm.c:1636`), links the node into `zone_sh(z)->lru`,
  and mutates `used_bytes` via `shm_alloc_evict` / `shm_free_locked`
  (`shm.c:1331`, `shm.c:1348-1356`) and `n_entries` (`shm.c:822`, `shm.c:1370`).
- `shm_lookup` descends `zone_sh(z)->rbtree` (`shm.c:376-377`).
- `shm_admit` reads and mutates the shared count-min `sketch`
  (`shm.c:637-707`), which is one array for the whole zone.
- `shm_claim_locked` stamps `ctn->refresh_owner` from the zone-global
  `owner_seq` counter (`shm.c:2041`, `shm.c:2071`).

Converting *only the mutex* to `stripe_of()` while the rbtree, LRU, `used_bytes`,
`n_entries` and `sketch` still live on stripe 0 would mean holding stripe K's
mutex while mutating stripe 0's structures. That is precisely the
lock-pool-A / free-into-pool-B corruption the seam exists to prevent — it would
be *worse* than the status quo, because today's uniform stripe-0 pinning is at
least consistent.

The prerequisite is therefore the s3c pool carving, not a call-site sweep. That
is the honest sequencing, and it is why this change ships the *verification*
(the resolver test and the ledger lint) rather than a conversion that cannot be
made safe yet.

## Residual s3c debt

Beyond carving N `(sh, shpool)` pairs, each of these needs an explicit
fan-out-or-pin decision. Left as-is at N > 1, each is a real defect, not a
cosmetic one:

| what | file:line | what breaks at N > 1 |
| --- | --- | --- |
| `used_bytes` accounting | `src/ngx_http_cache_turbo_shm.c:1331`, `:1348`, `:1349`, `:1356` | Per-stripe once pools are carved. The stats reader at `shm.c:1938` would otherwise report only stripe 0's bytes, and the eviction pressure test would run against a fraction of the zone. |
| `n_entries` | `shm.c:822`, `:1259`, `:1285`, `:1370`, `:2337` | Same: must become a per-stripe count, summed for reporting. |
| `n_protected` + the protected-LRU cap | `shm.c:769`, `:786`, `:865`, `:873` | The cap is computed as a percentage of `n_entries`. Per-stripe counts with a zone-wide cap (or vice versa) silently mis-sizes the protected segment. |
| the LRU queues (`lru`, `lru_protected`) | `shm.c:865-873`, and `shm_evict_one` | Eviction walks one shared LRU. Per-stripe LRUs mean eviction can only free memory from the stripe under pressure; a zone-wide LRU cannot be walked without taking every stripe's mutex. This is the single largest s3c design decision. |
| the count-min `sketch` | `shm.c:637-707` | One array shared by all stripes, mutated under whichever mutex the caller holds. Either it moves per-stripe (changing admission accuracy) or it needs its own lock. |
| `owner_seq` | `shm.c:2041`, `:2071` | Single-flight refresh-lease IDs. Per-stripe sequences would collide across stripes unless the ID is widened with the stripe index. |
| `shm_purge_all` | `shm.c:1415` | Walks one LRU under one mutex in batches. Must iterate every stripe. |
| the stats snapshot | `shm.c:1873`, `:1938` | Must sum across stripes; it currently reads stripe 0 alone. |

The zone-global atomic counters (`hits`, `misses`, `breaker_*`, `refuse_*`,
autotune's `snap_*`) are deliberately **not** in this table: they are atomics on
the zone's single `sh`, not slab-allocated per-key state, and pinning them to
stripe 0 stays correct. They are read without the zone mutex today and would
continue to be.

## Maintaining the ledger

`ci/tools/lint-stripe-seam.sh` enforces two things:

1. No site reaches a stripe's pool outside the two resolvers (the original
   s3b check).
2. The `KEY_DIRECTED` ledger matches reality — a row marked `pending` whose
   function starts calling `stripe_of()` fails the build, and so does a row
   marked `converted` whose function does not.

When a key-directed function is converted, flip its row to `converted` **and**
update this file's debt table in the same commit. When a new key-directed
function is added, add a `pending` row here and there; the lint cannot infer
key-directedness on its own, so an unlisted function is the one gap that stays a
review responsibility.
