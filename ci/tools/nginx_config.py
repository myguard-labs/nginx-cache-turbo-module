"""Generated nginx.conf template for the runtime test suite.

Extracted from test_runtime_base.py (MAINT-T2): nginx_config() is a single
large f-string builder, not test logic, so it lives here on its own. It is
re-exported from test_runtime_base so the area modules' `from
test_runtime_base import *` chain keeps resolving it -- see the explicit
import there.

This module is a LEAF: it must never import from test_runtime_base. The two
names nginx_config() needs from the old file (PORT_OFFSETS, _errlog_level)
were moved down here with it and are re-exported upwards instead. An import
in the other direction is a cycle that only fails when nginx_config is the
first of the pair to be imported -- an order the suite never takes, so it
stays green while any other entrypoint dies at import time.
"""

from __future__ import annotations

import os
import pathlib

# AUD-CIPORT3: single registry every fixture port -- main()'s visible
# allocation block AND the ad-hoc ports a handful of test bodies stand up on
# their own (a second nginx instance, a fake dirty memcached) -- must draw
# from. All offsets are relative to args.port (== ng.port for the primary
# instance). A collision here is invisible to anyone reading only the
# allocation block in main(), which is exactly how #167 claimed +25 for
# redis_tls_untrusted while test_mc_dirty_reply_not_pooled() already owned it
# via `ng.memcached_port + 1` -- and only found out ~12 minutes into a CI run
# via "OSError: [Errno 98] Address already in use". _check_port_registry()
# turns that into an immediate, named startup failure instead.
PORT_OFFSETS: dict[str, int] = {
    "origin": 11,
    "redis": 21,
    "redis_auth": 22,
    "redis_tls": 23,
    "memcached": 24,
    "mc_dirty_reply": 25,  # test_mc_dirty_reply_not_pooled(): ng.port + this
    "mc_drop_reply": 26,   # test_memcached_replyless_peer_arms_backoff()
    "l2_cross_instance_fill_b": 5,       # test_l2_cross_instance_fill()
    "l2_memcached_cross_instance_fill_b": 6,  # test_l2_memcached_cross_instance_fill()
    "redis_tls_untrusted": 27,
    "redis_tls_expired": 28,
    # AUD-PURGE-HONESTY1: deliberately NEVER bound. Reserved here so the
    # registry check keeps any future fixture off it -- the "L2 is down" test
    # needs a port that reliably REFUSES, and a port nobody reserved is a port
    # somebody eventually binds.
    "redis_dead": 29,
    "redis_dirty_reply": 30,  # test_redis_dirty_reply_not_pooled()
}


def _errlog_level() -> str:
    """error_log level for the harness nginx, overridable for diagnosis.

    Defaults to `notice`, which is what CI and every normal run want. Set
    TEST_CT_ERRLOG=debug to make the module's ngx_log_debug sites (memo skips,
    cold-wait give-ups, L2 verdicts) land in logs/error.log -- the cheap way to
    identify WHICH uri tripped a zone-global counter assertion in a long suite,
    instead of bisecting a couple of hundred tests by hand.

    The binary must be built --with-debug for `debug` to do anything; the
    harness build is (see objs/ngx_auto_config.h). Debug on a full suite is a
    large log, hence opt-in rather than the default.
    """
    lvl = os.environ.get("TEST_CT_ERRLOG", "notice").strip() or "notice"
    allowed = {"debug", "info", "notice", "warn", "error", "crit", "alert", "emerg"}
    if lvl not in allowed:
        raise SystemExit(f"TEST_CT_ERRLOG={lvl!r} is not an nginx log level "
                         f"(one of: {', '.join(sorted(allowed))})")
    return lvl


def nginx_config(root: pathlib.Path, port: int, module: pathlib.Path | None,
                 origin_port: int, workers: int,
                 redis_port: int | None = None,
                 redis_auth_port: int | None = None,
                 redis_password: str | None = None,
                 redis_tls_port: int | None = None,
                 redis_tls_ca: str | None = None,
                 memcached_port: int | None = None,
                 fault_injection: bool = False,
                 sr_off: bool = False,
                 redis_tls_untrusted_port: int | None = None,
                 redis_tls_expired_port: int | None = None) -> str:
    """Build the generated nginx.conf for the test server.

    !! ASCII ONLY -- everything returned here, INCLUDING COMMENTS, is written
    with encoding="ascii" (see Nginx.write_config). A single non-ASCII byte
    anywhere in this function (a stray arrow, dash, or warning sign pasted into
    a location comment) raises UnicodeEncodeError before a single test runs, and
    the traceback points at write_text, not at the comment you added. Use "!!",
    "->" and plain hyphens.
    """
    load = f"load_module {module};\n" if module else ""

    # S8 reload arm: the SAME zone (srz) with the directive flipped to `off`.
    # Written into the conf only for the post-reload pass, so a real
    # `nginx -s reload` hands the already-PROTECTED nodes in the surviving zone
    # to a worker whose effective protected_pct is now 0. See
    # test_s8_reload_on_to_off_drains_protected.
    sr_directive = ("cache_turbo_scan_resistant off;" if sr_off
                    else "cache_turbo_scan_resistant on;")

    # DSN auth+db (v5): a backend reached via a full redis://user:pass@host/db
    # DSN, and a plain SELECT-db (no auth) backend on the main instance.
    dsn_loc = ""
    if redis_auth_port is not None:
        dsn_loc += f"""
        # full DSN: AUTH (password) + SELECT db 2, two-reply preamble
        location /l2auth/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            cache_turbo_redis redis://:{redis_password}@127.0.0.1:{redis_auth_port}/2;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUTH+SELECT DSN with a keepalive pool (v15 + v5 combined): a pooled
        # reused connection must skip the AUTH/SELECT preamble entirely (it was
        # already authenticated + SELECTed when first opened). See
        # test_l2_keepalive_no_auth_replay.
        location /l2authka/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            cache_turbo_redis redis://:{redis_password}@127.0.0.1:{redis_auth_port}/2 keepalive=4 keepalive_timeout=30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
"""
    if redis_port is not None:
        dsn_loc += f"""
        # SELECT-only preamble (db 1, no auth) on the main instance
        location /l2db/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            cache_turbo_redis 127.0.0.1:{redis_port} db=1;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
"""
    if redis_tls_port is not None:
        dsn_loc += f"""
        # rediss:// TLS, verifying the server cert against our test CA
        location /l2tls/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            cache_turbo_redis rediss://127.0.0.1:{redis_tls_port}/0 tls_ca={redis_tls_ca} tls_name=localhost;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # v15-2: TLS keepalive pool -- idle TLS conns cached + reused across ops
        # (handshake + AUTH/SELECT skipped on reuse over the persistent channel).
        location /l2tlska/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            cache_turbo_redis rediss://127.0.0.1:{redis_tls_port}/0 tls_ca={redis_tls_ca} tls_name=localhost keepalive=4 keepalive_timeout=30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
"""
    if redis_tls_untrusted_port is not None:
        # AUD-TLS1: nginx is told to trust the SAME CA as /l2tls/ (redis_tls_ca),
        # but this backend's cert is signed by a DIFFERENT CA. With a working
        # SSL_CTX_set_verify(PEER) the handshake must fail chain verification;
        # the L2 write-through must never reach this server.
        dsn_loc += f"""
        # rediss:// TLS, server cert signed by an UNTRUSTED CA (AUD-TLS1)
        location /l2tlsuntrusted/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            cache_turbo_redis rediss://127.0.0.1:{redis_tls_untrusted_port}/0 tls_ca={redis_tls_ca} tls_name=localhost;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-L2-BACKOFF (TLS follow-up): same untrusted-CA backend as
        # /l2tlsuntrusted/ above, but with connect_backoff armed. Every
        # request's TLS handshake fails cert verification -- a TERMINAL
        # handshake failure, not a TCP connect refusal -- so this proves the
        # backoff also arms off the TLS path, not just a plain-TCP connect()
        # error. cache_turbo_lock off for the same reason as /l2backoff/: one
        # L2 attempt per request, exact counter deltas.
        location /l2tlsbackoff/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 1s;
            cache_turbo_lock  off;
            cache_turbo_redis rediss://127.0.0.1:{redis_tls_untrusted_port}/0 tls_ca={redis_tls_ca} tls_name=localhost prefix=ctbotls: connect_backoff=5000ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
"""
    if redis_tls_expired_port is not None:
        # Same trusted CA as /l2tls/ (chain trust is fine), but the leaf cert's
        # own validity window is already expired. Must also be rejected.
        dsn_loc += f"""
        # rediss:// TLS, server cert EXPIRED (chain-trusted CA) (AUD-TLS1)
        location /l2tlsexpired/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            cache_turbo_redis rediss://127.0.0.1:{redis_tls_expired_port}/0 tls_ca={redis_tls_ca} tls_name=localhost;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
"""

    # SK-A2: the surrogate-key locations that carry NO cache_turbo_redis are
    # emitted unconditionally. They used to sit inside redis_loc, so a run
    # without --redis-server dropped them while run_all() still called their
    # tests -- the "works without an L2 tag index" claim was exactly the case
    # that never ran. /skoff/ stays in redis_loc (it needs Redis to consume the
    # tag and suppress the COR-0 "no effect" warning).
    sk_loc = f"""
        # cache_turbo_surrogate_key: emit the tag list downstream as a
        # Surrogate-Key header for a fronting CDN. Deliberately NO cache_turbo_redis
        # here -- the emit must work without an L2 tag index. SK-A1: BOTH the MISS
        # and every later HIT carry the header, because a CDN POP that lost its own
        # copy refills from our HIT and would otherwise cache an untagged object.
        location /sk/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_tag      "blog news blog";
            cache_turbo_surrogate_key on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # surrogate_key with the tag value from a query arg (upstream-controlled
        # stand-in) so the cap/dedup carries into the emitted header.
        location /skcap/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_tag      $arg_t;
            cache_turbo_surrogate_key on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
"""

    # L2 (v2b): a location wired to a Redis backend. Scoped to /l2/ only so the
    # L1-only tests (purge, eviction, ...) are unaffected. Emitted only when a
    # RedisServer is running, so the no-redis path still config-tests.
    redis_loc = ""
    if redis_port is not None:
        redis_loc = f"""
        # L2: write-through on store + sync fill on L1 miss
        location /l2/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            # S231-DEFAULTS: pinned off. retain_ttl = max(stale_window,
            # sie_window) folds keep_stale's window into the L2 (Redis) PTTL
            # (module.c ~7705) -- left at the new 24h default,
            # test_l2_write_through's PTTL bound (<=120s, i.e. valid*4) would
            # fail because the stored blob would carry a ~24h TTL instead.
            cache_turbo_keep_stale off;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # C-S5-a: RFC-1 request Cache-Control serve verdict evaluated against
        # the L2 (Redis) arm, not L1 (module.c:5296). An L2 entry can be
        # YOUNGER than the L1 copy (a peer refreshed it), so the verdict must
        # be re-run on the L2 blob's own created/fresh_ttl rather than reusing
        # the L1 verdict.
        #
        # NOTE: `cache_turbo_purge on` is NOT an L1-only drop. purge_request()
        # calls clcf->backend->del() unconditionally whenever a backend is
        # configured (module.c ~1711, "Drop from L2 too, so a purge can't be
        # silently refilled from Redis") -- and this location configures one,
        # so a PURGE here empties BOTH tiers. To leave L2 populated while
        # emptying L1 there is no directive: capture the blob with
        # redis.get_raw(), PURGE, then redis.set_raw() it back.
        location /reqccl2/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_purge    on;   # drops L1 AND L2 -- see the note above
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            add_header           X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUD-L2-PROMOTE-RACE: dedicated L2 location with NO cache_turbo_purge
        # (unlike /reqccl2/, whose PURGE would DEL the L2 key too -- this test
        # needs to seed L1 and L2 independently via raw redis writes, never
        # through the module's own PURGE) and cache_turbo_bypass on the SAME
        # key ($uri, so a bypassed and a non-bypassed request share one L1/L2
        # slot). A bypassed request on this URI never touches redis at all
        # (module.c: bypass returns NGX_DECLINED before the L1 lookup/lock,
        # straight to origin, straight to a plain store()), so it can land a
        # NEWER L1 write from a different worker while another request is
        # still inside the L2-promote critical section.
        #
        # cache_turbo_test_l2_promote_hold_ms is the load-bearing knob: the
        # actual race window (between the resumed L2-hit handler's own
        # already-unlocked L1 re-check and its store_if() call) is pure CPU
        # with no I/O or yield point in between -- unreachable from black-box
        # HTTP timing regardless of how the L2 GET itself is delayed. The hold
        # blocks the CURRENT worker for exactly that gap so a concurrent
        # bypass write from a DIFFERENT worker can land inside it
        # deterministically. TEST_FAULTS-only; see the field comment in
        # ngx_http_cache_turbo_module.h. Drives
        # test_l2_promote_race_never_overwrites_newer_l1_entry.
        location /l2promo/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=5s;
            cache_turbo_bypass   $arg_nocache;
            cache_turbo_test_l2_promote_hold_ms 2000;
            add_header           X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # L2 negative memo (L13). Same shape as /l2/ above (no keepalive, so
        # every L2 op is exactly one countable Redis connection) plus a 3s memo,
        # so a repeated cold miss on the same key skips the L2 GET entirely. The
        # window is deliberately longer than the test's request burst and
        # shorter than the suite, so expiry is observable within one test.
        #
        # min_uses 4 is load-bearing for the TEST, not for the feature: without
        # it request 1 stores the (cacheable) origin response and request 2 is a
        # plain L1 HIT that never reaches the L2 consult at all -- so the test
        # would "pass" by measuring zero Redis traffic for the wrong reason.
        # Keeping the key below the store threshold holds every request on the
        # cold-miss path, which is the only path the memo is on.
        location /l2neg/ {{
            cache_turbo                  l2negz;
            cache_turbo_key              $uri;
            cache_turbo_valid            30s;
            cache_turbo_min_uses         4;
            cache_turbo_l2_negative_ttl  3;
            cache_turbo_redis            127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # SUITE-1 / Codex MAJOR-1: the OUTAGE test gets its own location with a
        # deliberately LONG memo, and it cannot share /l2neg/'s 3s one.
        #
        # The outage test asserts that a post-recovery request was NOT memo-
        # skipped (delta == 0). That assertion only means anything while a memo
        # would still be live if the bug were present: the memo is stamped on
        # second-granularity ngx_time(), so `l2_negative_ttl 3` is 2-3s
        # effective, while redis.start() is Popen + wait_port() + a FLUSHALL
        # subprocess carrying a 10s timeout. If the restart outruns the memo,
        # the post-recovery request does a REAL GET and delta == 0 passes even
        # with the arm-on-failure bug restored -- the test goes green for the
        # wrong reason. That is not hypothetical: it is why the negative control
        # for this test passed in the first place.
        #
        # 60s is far longer than any plausible restart, so a delta of 0 is
        # attributable to the fix rather than to the memo having expired. The
        # sibling repeat-GET test still needs the SHORT window (it asserts
        # expiry within one test), which is why this is a separate location and
        # not a bump of /l2neg/.
        location /l2negout/ {{
            cache_turbo                  l2negoutz;
            cache_turbo_key              $uri;
            cache_turbo_valid            30s;
            cache_turbo_min_uses         4;
            cache_turbo_l2_negative_ttl  60;
            cache_turbo_redis            127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # L2 negative memo, LIFETIME arm. DEFAULT min_uses (1) on purpose.
        #
        # This location exists to measure the memo across its whole window in the
        # config the feature actually SHIPS in. Two traps had to be avoided at once,
        # and both were hit for real while writing this (2026-07-19):
        #
        # 1. A high min_uses (4, or 32) keeps the key uncached, but it ALSO stops
        #    the request before the v10 cold-miss claim(): count_miss returns
        #    NGX_DECLINED and the handler returns early. claim() is what marks the
        #    node `refreshing`, which is the mechanism that used to mask the memo --
        #    so on such a location the masking bug CANNOT occur and a negative
        #    control reintroducing it still passes. The test would assert nothing.
        #
        # 2. At min_uses 1 the cold path runs in full (claim() included), but a
        #    cacheable response STORES on request 1 and every later request is a
        #    plain L1 HIT that never reaches L2 -- zero GETs for the wrong reason.
        #
        # 3. min_uses 1 + an uncacheable response keeps every request cold, but with
        #    the v10 cold-miss lock ON the winner never stores (the response is
        #    uncacheable), so followers PARK on the stub and the cold-wait re-poll
        #    sets l2_neg_force -- which bypasses the memo by design. Measured
        #    2026-07-19: 2 requests in 5s, the second issuing 50 forced GETs.
        #
        # So: min_uses 1 (real cold path) + uncacheable origin (never stores) +
        # cache_turbo_lock off (no parking, no forced re-polls). This location
        # measures memo LIFETIME in the config the feature ships in.
        #
        # NOTE: there is deliberately NO test here for "the memo is consulted on a
        # node another request marked `refreshing`" (CodeRabbit CR-A / Codex #4).
        # That state is not reachable from outside the module: the memo is checked
        # once per request BEFORE the cold-miss single-flight, and a request that
        # arrives while a claim is held becomes a WAITER, whose re-poll sets
        # l2_neg_force and bypasses the memo by design. Six formulations were tried
        # (serial and 12-way concurrent, min_uses 1/4/32, lock on and off); every
        # one passed with the coupling deliberately restored. See issues.md.
        location /l2neglife/ {{
            cache_turbo                  l2neglifez;
            cache_turbo_key              $uri;
            cache_turbo_valid            30s;
            cache_turbo_lock             off;
            cache_turbo_l2_negative_ttl  3;
            cache_turbo_redis            127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # L2 negative memo, min_uses interaction: the memo rides on the SAME
        # counter node min_uses uses, so this location exercises both writing to
        # one node. min_uses 3 exceeds the test's request count, so every request
        # stays below the threshold and each one both counts a min_uses skip and
        # consults the memo -- the overlapping state that would hide a clobber.
        # The CR-B test drives UNCACHEABLE responses through here, so a winner
        # never stores and a follower can park on the single-flight. Two SEPARATE
        # deadlines govern that, and they are easy to confuse:
        #
        #   lock_ttl 1s      -- how long a CLAIM stays valid (when a stub goes
        #                       stale and may be taken over by a new winner).
        #   lock_timeout 2s  -- how long a WAITER parks before giving up and
        #                       going to origin itself (module.c: wait_deadline
        #                       = now + lock_timeout).
        #
        # !! lock_timeout MUST stay well under fetch()'s 5s client timeout. Both
        # defaulted to 5s, so a waiter that parked the full deadline released at
        # ~5.000s while the client aborted at 5.000s -- a photo finish decided by
        # scheduling jitter, which is exactly the 1-in-N red this test showed on
        # slower CI runners (PR #77, run 29708006339 attempt 1). Pinning it to 2s
        # makes the park end strictly before the client gives up, so a real
        # teardown regression surfaces as a legible assertion rather than a
        # timeout whose cause is ambiguous.
        location /l2negmu/ {{
            cache_turbo                  l2negmuz;
            cache_turbo_key              $uri;
            cache_turbo_valid            30s;
            cache_turbo_min_uses         3;
            cache_turbo_lock_ttl         1s;
            cache_turbo_lock_timeout     2s;
            cache_turbo_l2_negative_ttl  3;
            cache_turbo_redis            127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # L2 keepalive pool (v15): idle Redis connections cached per worker and
        # reused across ops, instead of connect()+close per op. As of the
        # per-fingerprint pool (v16), each distinct connection profile gets its
        # OWN bucket, cap and timeout -- so this plain location's keepalive value
        # is honoured for the plain profile regardless of what any TLS location
        # (/l2tlska/) or auth location (/l2authka/) configures, and no profile can
        # starve another out of a shared cap. (Before v16 the cap was latched
        # once per worker by the first keepalive-enabled location and the plain
        # and TLS working sets had to be summed into one value here -- that
        # workaround is retired.)
        location /l2ka/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms keepalive=8 keepalive_timeout=30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Keepalive security-context isolation: these locations share one Redis
        # address and pool but select different DBs. Separate L1 zones and the
        # same key shape ensure only Redis connection state distinguishes them.
        location /l2ka0/ {{
            cache_turbo          ka0;
            cache_turbo_key      $arg_k;
            cache_turbo_valid    30s;
            cache_turbo_redis    127.0.0.1:{redis_port} db=0 prefix=kais: timeout=250ms keepalive=8 keepalive_timeout=30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /l2ka1/ {{
            cache_turbo          ka1;
            cache_turbo_key      $arg_k;
            cache_turbo_valid    30s;
            cache_turbo_redis    127.0.0.1:{redis_port} db=1 prefix=kais: timeout=250ms keepalive=8 keepalive_timeout=30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # L2 with a short fresh TTL so the L1 copy expires in-test (stale window
        # = valid*4 = 4s), exercising the expired-L1 -> consult-L2 path (P6).
        location /l2e/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_stale_mult 1;
            # S231-DEFAULTS: pinned off. keep_stale widens the blob's sie_ttl
            # field the same way a response stale-if-error does (module.c
            # ~7705, S2.2) -- left at the new 24h default,
            # test_sie_ttl_stored_in_blob's "no stale-if-error header -> sie_ttl
            # == 0" negative control would fail (sie_ttl would carry
            # fresh_ttl+86400 instead).
            cache_turbo_keep_stale off;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # RFC-2 (CTB4): origin emits stale-if-error=30; the store path records an
        # absolute serve-on-error window (fresh + 30) in the blob's sie_ttl. L2 so
        # the raw blob can be read back and the field unpacked. valid 60s => the
        # stored fresh_ttl is 60 and sie_ttl is 90.
        location /siettl/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    60s;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # V-HANG-2 single-flight guard rail. The give-up added for V-HANG-2 must
        # fire only on a cold-wait RE-POLL, never on a first pass -- otherwise
        # every cold-miss loser bypasses the wait loop and the burst stampedes.
        #
        # Reproducing that needs an L2 blob that is PRESENT but UNSERVEABLE while
        # a burst arrives, WITHOUT the regens being explainable by ordinary
        # re-expiry. /l2sie/ cannot do it: its cache_turbo_valid is 1s, so entries
        # legitimately re-expire mid-burst and 40 regens is correct behaviour
        # there (verified against stock -- identical counts).
        #
        # So: fresh_ttl 30s (a regen stays fresh for the whole burst, hence any
        # stampede is real) but stale_mult 1, so the FIRST entry is unserveable
        # 30s after it is stored. The test primes, expires the L2 object by hand,
        # and bursts -- see test_l2_unserveable_giveup_still_single_flights.
        location /sfgu/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_stale_mult 1;
            cache_turbo_lock_ttl 5s;
            # NOT an L1-only drop: purge_request() calls backend->del()
            # unconditionally when a backend is configured (module.c ~1711),
            # and this location configures one, so a PURGE empties BOTH tiers.
            # This comment previously claimed otherwise and is the documented
            # origin of that error (issues.md OBS-2, mis-scoped twice).
            cache_turbo_purge    on;

            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S1.2: stale_mult 1 collapses stale_window == fresh_ttl (1s), so a
        # stale-if-error=3600 response's sie window (3601s) is far wider than
        # the stale window. Proves the L2 key's retain_ttl covers sie, not
        # just stale_window. See test_l2_retain_ttl_covers_sie.
        location /l2sie/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_stale_mult 1;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # tagged objects: every response under /l2t/ joins the "blog" and
        # "news" tag sets, so a purge-by-tag can drop them across both tiers.
        location /l2t/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            cache_turbo_tag      "blog news";
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # PERF-2: tag value taken from a query arg (upstream-controlled stand-in)
        # so the cap/dedup on cache_turbo_tag can be exercised.
        location /l2tcap/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            cache_turbo_tag      $arg_t;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # surrogate_key OFF (default): tag set but no downstream header. Proves the
        # directive gates the emit -- a plain cache_turbo_tag user is unaffected.
        # Redis is attached so the tag has its normal purge-by-tag consumer and
        # the COR-0 "no effect" warning does not fire (an unconsumed tag would).
        # A DISTINCT prefix (sk:) + unique tag names keep this location's SADDs out
        # of the shared ct:tag:* sets other L2 tests assert exact counts on (the
        # truncation test fills ct:tag:news to exactly 350 -- a stray SADD from
        # here would race it to 351 under the multi-worker runner).
        location /skoff/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=sk: timeout=250ms;
            cache_turbo_tag      "skoff-a skoff-b";
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # COR-5 (Redis-backed): auto-Vary + PURGE with an L2 backend. Each variant
        # store SADDs its L2 key into a per-base variant-index set; a PURGE of the
        # base URI SMEMBERS that set and drops every variant from L1 + L2 + the
        # index set, then deletes the node-local marker. The next request for each
        # axis value misses to origin (proves cross-tier variant invalidation).
        location /cor5/ {{
            cache_turbo          main;
            cache_turbo_key      $request_uri;
            cache_turbo_valid    30s;
            cache_turbo_auto_vary on;
            cache_turbo_purge    on;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # cross-node dogpile (v4-2): fresh TTL 2s -> stale_until = valid*4 = 8s,
        # a wide window so both lock tests have timing slack; aggressive beta so
        # a stale read reliably rolls a refresh; lock_ttl 5s = the Redis SET NX
        # PX hold (long enough to cap a multinode burst, short enough to model a
        # crashed peer's lock self-healing by PX expiry).
        # cache_turbo_lock off isolates the STALE-path NX under test from the v10
        # cold-path NX (otherwise the cold prime's NX would linger for lock_ttl
        # into the stale burst). Cold-path cross-node single-flight is covered by
        # /coldl2/ below.
        location /lock/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    2s;     # stale window: serveable until t+8s
            cache_turbo_beta     5000;   # aggressive: refresh likely while stale
            cache_turbo_lock_ttl 5s;     # cross-node NX PX = 5000ms
            cache_turbo_lock     off;    # isolate stale-path NX (see comment)
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # self-heal variant: SHORT lock_ttl (2s) so BOTH the per-box L1 refresh
        # lock and the cross-node NX PX clear quickly once the 'crashed' peer's
        # lock expires; wide stale window (valid*4 = 8s) leaves room to observe
        # the post-expiry regen.
        location /lockh/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    2s;     # stale window: serveable until t+8s
            cache_turbo_beta     5000;
            cache_turbo_lock_ttl 2s;     # local + NX hold = 2000ms
            cache_turbo_lock     off;    # isolate stale-path NX (see /lock/)
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # cold-miss single-flight (v10), cross-node: two nginx nodes share this
        # Redis. A concurrent cold burst across both collapses to ~1 origin fetch
        # -- the node that wins the SET NX PX regenerates + writes L2; the other
        # node's local winner loses the NX and waits for the L2 write-through.
        location /coldl2/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_lock_ttl 5s;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUD-NXLOCK-OWNER: same shape as /coldl2/ (cold-miss, L2-backed, lock
        # default ON) but with cache_turbo_no_store so the cross-node NX winner's
        # response is non-cacheable and the header filter's unstub() fires
        # immediately (module.c ~7861) instead of waiting for the pool cleanup
        # backstop. lock_ttl is LONG (30s) so the leaked L1 lease -- if the fix
        # regresses -- cannot expire mid-test and mask the bug (a short TTL lets
        # claim() ADOPT the stub instead of parking, making a buggy build look
        # exactly as fast as a fixed one). cache_turbo_key is a FIXED string,
        # not $uri, so /coldl2ns_probe/ below can hash to the identical L1 node
        # while never touching Redis -- see that location's comment for why.
        location /coldl2ns/ {{
            cache_turbo           main;
            cache_turbo_key       "aud-nxlock-owner-probe";
            cache_turbo_valid     30s;
            cache_turbo_lock_ttl  30s;
            cache_turbo_no_store  $arg_private;
            cache_turbo_redis     127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUD-NXLOCK-OWNER probe: same zone (main) and the SAME fixed key as
        # /coldl2ns/, but no cache_turbo_redis / cache_turbo_lock_ttl override
        # of its own -- cache_turbo_lock stays default ON but there is no L2
        # backend configured here, so clcf->backend->lock is never armed and a
        # claim() on this location can never fire (or park on) the Redis NX
        # lock. It can only ever see the SHARED zone's L1 node for that key.
        # This is what lets the test tell "L1 stub still refreshing" (the bug)
        # apart from "Redis NX lock still held by design" (expected, and NOT
        # what this item is about -- unlock() is intentionally never called
        # for the cross-node lock, so a second /coldl2ns/ request always parks
        # on Redis regardless of the L1 fix).
        location /coldl2ns_probe/ {{
            cache_turbo           main;
            cache_turbo_key       "aud-nxlock-owner-probe";
            cache_turbo_valid     30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # admin endpoint that is itself L2-aware: a single-key purge here must
        # also DEL the entry from Redis (P6), not just drop L1.
        location = /_cache_l2 {{
            cache_turbo_admin    main;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            allow 127.0.0.1;
            deny all;
        }}

        # SUITE-1: stats endpoint for the /l2neg/ zone. l2_neg_skips is per-zone
        # and the admin handler emits exactly ONE zone's stats, so a test that
        # isolates /l2neg/ into `l2negz` must read the counter HERE -- reading
        # /_cache (which is `cache_turbo_admin main`) would report a zone this
        # location no longer writes, making `delta == 0` trivially true.
        location = /_cache_l2neg {{
            cache_turbo_admin    l2negz;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            allow 127.0.0.1;
            deny all;
        }}

        # SUITE-1: same pairing for the long-memo outage location. A zone
        # without its own admin endpoint cannot be measured at all.
        location = /_cache_l2negout {{
            cache_turbo_admin    l2negoutz;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            allow 127.0.0.1;
            deny all;
        }}

        # SUITE-1 (s128): the other half of the l2neglifez/l2negmuz split. A
        # private zone without its own admin endpoint cannot be measured at all
        # -- the helper would keep reading `main`, a zone the location no longer
        # writes, and every delta assertion would be trivially satisfied.
        location = /_cache_l2neglife {{
            cache_turbo_admin    l2neglifez;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            allow 127.0.0.1;
            deny all;
        }}

        # /l2negmu/ writes BOTH l2_neg_skips and min_uses_skips, so this endpoint
        # is what _admin_min_uses_skips() must read for that location too.
        location = /_cache_l2negmu {{
            cache_turbo_admin    l2negmuz;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
            allow 127.0.0.1;
            deny all;
        }}

        # Literal Redis glob metacharacters in a prefix must stay literal during
        # SCAN-based all-purge; only the module-appended final '*' is a wildcard.
        location = /_cache_l2glob {{
            cache_turbo_admin    main;
            cache_turbo_redis    127.0.0.1:{redis_port} prefix=ct*: timeout=250ms;
            allow 127.0.0.1;
            deny all;
        }}

        # AUD-SCAN1. Two admin endpoints on their OWN Redis prefix (ctscan:) so
        # a multi-page SCAN walk can be driven without touching any other L2
        # test's keyspace. They also sit in their OWN redis db (7): SCAN pages
        # are buckets of the whole db's hash table, not matched keys, so a db
        # shared with other tests makes "5 keys fit in one page" depend on how
        # much everyone else left behind. db 7 is FLUSHDB'd by these tests,
        # which also resets the table to its initial size.
        # /_cache_scanwalk has the production page cap;
        # /_cache_scancap lowers it to 2 pages (TEST_FAULTS-only directive) so
        # the "abandon the walk, report INCOMPLETE" branch is reachable without
        # materialising a 268M-key keyspace. Same `main` zone: these tests
        # assert on the L2 walk, not on the L1 count.
        location = /_cache_scanwalk {{
            cache_turbo_admin    main;
            cache_turbo_redis    127.0.0.1:{redis_port} db=7 prefix=ctscan: timeout=2s;
            allow 127.0.0.1;
            deny all;
        }}

        location = /_cache_scancap {{
            cache_turbo_admin    main;
            cache_turbo_redis    127.0.0.1:{redis_port} db=7 prefix=ctscan: timeout=2s;
            cache_turbo_test_scan_max_pages 2;
            allow 127.0.0.1;
            deny all;
        }}

        # S231-L2-SCANTIME. The deadline is checked at a page boundary and only
        # AFTER the cursor==0 completion return, so a walk that finishes never
        # evaluates it. A bare "unmeetable" 1ms deadline therefore does NOT make
        # the abort deterministic: 6000 keys at COUNT 256 complete in ~24 pages,
        # and on a fast runner the whole walk can finish inside one tick of
        # ngx_current_msec (nginx's CACHED clock) having never checked. That is
        # a race against runner speed, and it is what made this test red on CI
        # and green locally.
        #
        # The hold is what makes it deterministic: 40ms per page boundary puts
        # the SECOND boundary ~40ms in, far past a 5ms deadline, on any runner.
        # The deadline is 5ms rather than 1ms so it still exceeds a real page
        # round-trip -- the abort is explained by elapsed wall-clock, not by a
        # deadline no walk could ever meet. The page cap stays at its production
        # value so only the deadline can explain an abort at scan_pages < cap.
        #
        # /_cache_scandeadlineoff is the negative control: same shape and the
        # same per-page hold, deadline disabled, so it must still complete
        # normally. Sharing the hold is what makes it a control for the DEADLINE
        # rather than for the hold.
        #
        # The hold blocks the worker INSIDE the SCAN read handler while the 2s
        # read timer keeps running, so the control's keyspace is deliberately
        # small (see _scan_fill's n at the call site): a full ~24-page walk at
        # 40ms/page would spend ~1s of the 2s budget and stall the single worker
        # for that whole time. The control only has to prove that a walk which
        # crosses a held page boundary still completes when the deadline is
        # off -- two pages is enough to prove that, and 6000 keys is not.
        location = /_cache_scandeadline {{
            cache_turbo_admin    main;
            cache_turbo_redis    127.0.0.1:{redis_port} db=7 prefix=ctscan: timeout=2s scan_deadline=5ms;
            cache_turbo_test_scan_page_hold_ms 40;
            allow 127.0.0.1;
            deny all;
        }}

        location = /_cache_scandeadlineoff {{
            cache_turbo_admin    main;
            cache_turbo_redis    127.0.0.1:{redis_port} db=7 prefix=ctscan: timeout=2s scan_deadline=0;
            cache_turbo_test_scan_page_hold_ms 40;
            allow 127.0.0.1;
            deny all;
        }}

        # AUD-PURGE-HONESTY1: admin endpoint whose L2 is DOWN -- the registry's
        # redis_dead offset is reserved and never bound, so the connect is
        # refused and scan_del returns NGX_ERROR without ever walking a page.
        # Its own prefix so a stray success here cannot disturb another test.
        location = /_cache_scandown {{
            cache_turbo_admin    main;
            cache_turbo_redis    127.0.0.1:{port + PORT_OFFSETS["redis_dead"]} prefix=ctdown: timeout=250ms;
            allow 127.0.0.1;
            deny all;
        }}

        # O4.4-i L2 half. Mirrors /brkion/ and /brkioff/, but with a Redis L2
        # configured so the breaker fallback is served from the L2 blob path --
        # the arming call site the L1 pair above provably cannot reach. Their own
        # `brkil2z` zone: the L1 pair leaves its breaker OPEN, and a shared zone
        # would let that state decide these requests.
        location /brkil2on/ {{
            cache_turbo                    brkil2z;
            cache_turbo_key                $uri;
            # valid 1s + keep_stale 300s. The entry is past its x4 stale
            # window within ~4s (so rem_stale <= 0, which is the L2 arming
            # site's precondition -- module.c ~5203), while keep_stale
            # pushes the REDIS retention window out to 300s via sie_ttl
            # (retain_ttl = max(stale_window, sie_window), module.c ~7705)
            # so the blob is still in L2 to be armed from.
            #
            # `cache_turbo_purge on` is what makes the L1 copy ABSENT rather
            # than merely expired -- the test PURGEs both keys and rewrites
            # the blob back into Redis (PURGE is L2-aware and DELs the key
            # too, module.c ~1711, so the order matters). Eviction via a
            # filler loop was tried and rejected: brkil2z eviction is LRU and
            # left the OFF key resident, which is exactly what made the OFF
            # half of the test vacuous for three sessions.
            cache_turbo_valid               1s;
            cache_turbo_keep_stale        300s;
            cache_turbo_purge               on;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            cache_turbo_redis              127.0.0.1:{redis_port} prefix=brkil2: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location /brkil2off/ {{
            cache_turbo                    brkil2z;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;   # see /brkil2on/
            cache_turbo_keep_stale        300s;
            cache_turbo_purge               on;   # see /brkil2on/
            cache_turbo_breaker            off;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            cache_turbo_redis              127.0.0.1:{redis_port} prefix=brkil2: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-L2-BACKOFF: per-worker L2 connect backoff. Same dead peer as
        # /_cache_scandown (redis_dead offset, never bound -> every connect
        # is refused), but wired to a normal GET/miss location so it goes
        # through ngx_http_cache_turbo_redis_get -> launch(), the fail-fast
        # choke point, not the admin scan path.
        #
        # /l2backoff/ arms a 5s window: request 1 pays the real refused
        # connect() (the ordinary per-request path), request 2 must fail
        # fast on the SAME worker without another connect attempt. Both are
        # indistinguishable from the client's perspective (both a plain L2
        # miss -> origin serve) -- the oracle is the X-Cache-Turbo-Test-L2-
        # Backoff counter (TEST_FAULTS-only), never response equality.
        # cache_turbo_lock off: this location's job is purely to exercise the
        # L2 connect path, not the cold-miss cross-node NX lock. With locking
        # on, a dead L2 peer makes every miss retry through the cold-miss
        # WAIT poll (module.c's cold_wait_ev/cold_wait_timeout), which was
        # measured to leave a timer armed past its owning request's response
        # in a way that can outlive a since-closed keepalive connection and
        # crash the worker on shutdown (pre-existing race, unrelated to L2
        # backoff, ledgered in issues.md). Locking off avoids that path
        # entirely and is irrelevant to what this fixture tests.
        location /l2backoff/ {{
            cache_turbo                    main;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_lock               off;
            cache_turbo_redis              127.0.0.1:{port + PORT_OFFSETS["redis_dead"]} prefix=ctbo: timeout=250ms connect_backoff=5000ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Negative control: connect_backoff=0 (disabled) against the SAME
        # dead peer -- every request must pay its own connect failure, so the
        # counter never moves no matter how many requests land back to back.
        # Same cache_turbo_lock off reasoning as /l2backoff/ above.
        location /l2backoffoff/ {{
            cache_turbo                    main;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_lock               off;
            cache_turbo_redis              127.0.0.1:{port + PORT_OFFSETS["redis_dead"]} prefix=ctboo: timeout=250ms connect_backoff=0;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Exact RESP-boundary gate. The test's fake peer appends one partial
        # reply byte after every GET/SET response. keepalive must reject both
        # the GET parser's and the fire-and-forget drain's dirty boundaries.
        location /redisdirty/ {{
            cache_turbo                    main;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_lock               off;
            cache_turbo_redis              127.0.0.1:{port + PORT_OFFSETS["redis_dirty_reply"]} prefix=ctdirty: timeout=250ms keepalive=4 keepalive_timeout=30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-COLDWAIT-UAF repro: live redis (cache_turbo_lock default ON),
        # short lock_timeout so the 100ms cold_wait poll fires repeatedly
        # against LOSER requests parked behind a same-key cross-node NX
        # lock while the winner regenerates from a deliberately slow
        # origin. This is the fixture that reproduces the cold-wait poll
        # timer double-free (issues.md "cold-wait poll timer double-frees
        # the request"): a loser's kept-alive connection is aborted by the
        # client WHILE parked in cold_wait, independently of the poll
        # timer; nginx's own connection-close path can finalize+free `r`
        # before the already-armed cold_wait_ev fires via
        # ngx_event_expire_timers(), which then calls
        # ngx_http_cache_turbo_cold_wait_timeout() -> ...
        # -> ngx_http_finalize_request() a second time on freed memory.
        location /coldwaituaf/ {{
            cache_turbo                    main;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_lock_timeout        2s;
            cache_turbo_redis              127.0.0.1:{redis_port} prefix=ctcw: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
"""

    # L2 memcached (v13): a location wired to the memcached backend instead of
    # Redis. Emitted only when a MemcachedServer is running; scoped to /mc/ so it
    # never disturbs the Redis or L1-only locations. Distinct prefix (mc:) so its
    # keys can't collide with the Redis suite's ct: namespace.
    mc_loc = ""
    if memcached_port is not None:
        mc_loc = f"""
        # L2 memcached: write-through on store + sync fill on L1 miss
        location /mc/ {{
            cache_turbo            main;
            cache_turbo_key        $uri;
            cache_turbo_valid      30s;
            cache_turbo_memcached  127.0.0.1:{memcached_port} prefix=mc: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # L2 memcached with a keepalive pool (D-O1): idle pooled conns must carry
        # a close-on-readable handler. When the memcached server drops an idle
        # pooled conn, epoll wakes c->read; a NULL handler there SIGSEGVs the
        # worker. Exercised by test_mc_keepalive_server_close_survives.
        location /mcka/ {{
            cache_turbo            main;
            cache_turbo_key        $uri;
            cache_turbo_valid      30s;
            cache_turbo_memcached  127.0.0.1:{memcached_port} prefix=mck: timeout=250ms keepalive=4 keepalive_timeout=30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # MC-A2: SAME memcached peer as /mcka/ but keepalive explicitly 0. The
        # documented contract is a fresh connection per op; before the fix
        # mc_connect looked the pool up by peer address only, so this location
        # borrowed (and, because ka_save does check zero, then CLOSED) sockets
        # /mcka/ had pooled -- draining another location's pool. Exercised by
        # test_mc_keepalive_zero_does_not_drain_pool.
        location /mcka0/ {{
            cache_turbo            main;
            cache_turbo_key        $uri;
            cache_turbo_valid      30s;
            cache_turbo_memcached  127.0.0.1:{memcached_port} prefix=mck0: timeout=250ms keepalive=0;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Short idle timeout (D-O1): a pooled conn left idle past 1s must be
        # dropped by mc_ka_close_handler's ev->timedout branch, not leak/crash.
        # Exercised by test_mc_keepalive_idle_timeout_drops.
        location /mckashort/ {{
            cache_turbo            main;
            cache_turbo_key        $uri;
            cache_turbo_valid      30s;
            cache_turbo_memcached  127.0.0.1:{memcached_port} prefix=mcks: timeout=250ms keepalive=4 keepalive_timeout=1s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # D-O2: a keepalive location pointed at a DELIBERATELY MISBEHAVING fake
        # memcached (PORT_OFFSETS["mc_dirty_reply"], stood up only by
        # test_mc_dirty_reply_not_pooled on the PRIMARY instance). The address is
        # derived from memcached_port, not from this instance's own `port`: a
        # second nginx (test_l2_memcached_cross_instance_fill's instance B) runs
        # on a different port but must still point at the one fake memcached.
        # A reply that does not frame cleanly at
        # a boundary (trailing junk past END/STORED, a server error, a timeout)
        # must NOT be returned to the pool -- the connection is closed instead, so
        # a reuse never resumes mid-reply. Same keepalive size as /mcka/.
        location /mcdirty/ {{
            cache_turbo            main;
            cache_turbo_key        $uri;
            cache_turbo_valid      30s;
            cache_turbo_memcached  127.0.0.1:{memcached_port + PORT_OFFSETS["mc_dirty_reply"] - PORT_OFFSETS["memcached"]} prefix=mcd: timeout=250ms keepalive=4 keepalive_timeout=30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # memcached-backed admin: a single-key purge here must also delete the
        # entry from memcached (not just drop L1).
        location = /_cache_mc {{
            cache_turbo_admin      main;
            cache_turbo_memcached  127.0.0.1:{memcached_port} prefix=mc: timeout=250ms;
            allow 127.0.0.1;
            deny all;
        }}

        # S231-L2-BACKOFF, memcached side. Same dead-peer/cache_turbo_lock off
        # shape as /l2backoff/ above (redis_dead offset -- never bound, plain
        # TCP refuse works identically for either driver's connect()).
        location /mcbackoff/ {{
            cache_turbo            main;
            cache_turbo_key        $uri;
            cache_turbo_valid      1s;
            cache_turbo_lock       off;
            cache_turbo_memcached  127.0.0.1:{port + PORT_OFFSETS["redis_dead"]} prefix=mcbo: timeout=250ms connect_backoff=5000ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # A peer on this port accepts and reads the GET, then closes without a
        # reply. A successful local send must not clear the connection's
        # unproven state: the read-side EOF must arm connect_backoff. no_store
        # prevents the response body from becoming a normal cached entry.
        location /mcdrop/ {{
            cache_turbo            main;
            cache_turbo_key        $uri;
            cache_turbo_valid      1s;
            cache_turbo_lock       off;
            cache_turbo_no_store   $arg_private;
            cache_turbo_memcached  127.0.0.1:{port + PORT_OFFSETS["mc_drop_reply"]} prefix=mcdrop: timeout=250ms connect_backoff=5000ms;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
"""

    # Backend-inheritance regression (precedence bug FIXED 2026-06-12): a parent
    # location naming cache_turbo_memcached (memcached=1) enclosing a child that
    # names cache_turbo_redis. The child MUST drive its own address with the Redis
    # backend, not inherit the parent's memcached=1 (the merge would otherwise
    # select the memcached driver for a redis:// address). Needs BOTH L2 servers.
    mcinh_loc = ""
    if memcached_port is not None and redis_port is not None:
        mcinh_loc = f"""
        location /mcinh/ {{
            cache_turbo            main;
            cache_turbo_key        $uri;
            cache_turbo_valid      30s;
            cache_turbo_memcached  127.0.0.1:{memcached_port} prefix=mc: timeout=250ms;
            proxy_pass http://127.0.0.1:{origin_port}/;

            # child overrides the parent's memcached backend with Redis
            location /mcinh/child/ {{
                cache_turbo_redis  127.0.0.1:{redis_port} prefix=ct: timeout=250ms;
                proxy_pass http://127.0.0.1:{origin_port}/;
            }}
        }}
"""
    mc_loc += mcinh_loc

    fault_loc = ""
    if fault_injection:
        fault_loc = f"""
        # CI-only allocation fault injection. These directives are compiled only
        # by ci/tools/ci-build.sh and are absent from production/package builds.
        location /allocfail/ {{
            cache_turbo                         main;
            cache_turbo_key                     $uri;
            cache_turbo_valid                   30s;
            cache_turbo_test_restore_alloc_fail on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location /allocfailst/ {{
            cache_turbo                         main;
            cache_turbo_key                     $uri;
            cache_turbo_valid                   301 30s;
            cache_turbo_test_restore_alloc_fail on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location /allocfailsie/ {{
            cache_turbo                         main;
            cache_turbo_key                     $uri;
            cache_turbo_valid                   1s;
            cache_turbo_stale_mult              1;
            cache_turbo_test_restore_alloc_fail on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # CI-only: force the body filter onto the file-backed delegate path
        # (the sendfile-abort branch) deterministically, without depending on
        # directio/O_DIRECT fs alignment. Nothing must ever store here.
        location /forcefile/ {{
            cache_turbo                    main;
            cache_turbo_key                $uri;
            cache_turbo_valid              30s;
            cache_turbo_test_force_file_buf on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUD-STORE-ERR-STUB: force the body filter's l1->store() to fail
        # deterministically, so a cold-miss winner's stub cleanup path is
        # reachable without depending on real slab exhaustion timing.
        #
        # lock_ttl is LONG (30s) on purpose: the leaked stub must still hold a
        # LIVE lease when the second request arrives, or claim() adopts the
        # expired stub instead of parking on it and the test stops
        # discriminating (see test_store_failure_cleans_up_cold_stub). The
        # oracle is the lock_waits counter, so nothing here waits out a
        # timeout -- lock_timeout stays short to bound the buggy-build park.
        location /storefail/ {{
            cache_turbo                  storefailz;
            cache_turbo_key              $uri;
            cache_turbo_valid            30s;
            cache_turbo_lock_ttl         30s;
            cache_turbo_lock_timeout     2s;
            cache_turbo_test_store_fail  on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUD-STORE-ERR-STUB: admin endpoint for /storefail/'s private zone
        # (storefailz), same reasoning as /_cache_s71 -- /_cache is bound to
        # `main` and would read a lock_waits counter this zone never writes,
        # and (unlike s71z) `main` is never quiescent: it is shared by 166
        # other locations, so an exact-equality assert against it is
        # order-dependent on whatever else in the suite happens to park in
        # cold_wait() between this test's two samples.
        location = /_cache_storefail {{
            cache_turbo_admin    storefailz;
            allow 127.0.0.1;
            deny all;
        }}

        # S231-SIE-MIDBODY: same short fresh/stale window + "sieserve" marker
        # convention as /sieserve/ so a warmed key gets a serve-on-error
        # snapshot armed (sie_armed), but the fault fires in the BODY filter
        # instead of driving the origin to a real 5xx -- cache_turbo_test_
        # midbody_abort treats the first arriving body buffer as a mid-body
        # origin death regardless of what status the origin actually sent.
        # This is the header-filter trigger's blind spot: that trigger only
        # ever sees r->headers_out.status, and a mid-body death arrives with
        # headers already serialised as a normal 200. Drives
        # test_sie_midbody_rescue.
        location /midbody/ {{
            cache_turbo                  main;
            cache_turbo_key              $uri;
            cache_turbo_valid            1s;
            cache_turbo_stale_mult       1;
            cache_turbo_keep_stale       off;
            cache_turbo_test_midbody_abort on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-SIE-MIDBODY negative control: identical fault directive, but
        # NO stale-if-error window ever gets armed (no "sieserve" marker in
        # the key, so sie_armed stays 0 for every request). Proves the fault
        # cannot fabricate a body out of nothing -- with nothing armed the
        # rescue's own `ctx->sie_armed` guard must refuse it and the
        # (truncated-by-the-fault) response must pass through unchanged.
        location /midbodycold/ {{
            cache_turbo                  main;
            cache_turbo_key              $uri;
            cache_turbo_valid            30s;
            cache_turbo_test_midbody_abort on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
"""

    return f"""{load}worker_processes {workers};
pid {root}/nginx.pid;
error_log {root}/logs/error.log {_errlog_level()};

events {{ worker_connections 512; }}

http {{
    access_log off;

    cache_turbo_zone name=main 16m;

    # DOC-A2: the front-controller redirect replaces r->uri, so preset URI rules
    # and cache_turbo_bypass_uri (both compare r->uri) stop seeing the real
    # route. $request_uri still carries it -- the pattern docs/xenforo.md now
    # prescribes for private routes behind a front controller.
    map $request_uri $ctir_private_route {{
        default 0;
        ~^/ctir-fixed/(?:api|login|account)(?:[/?]|$) 1;
    }}
    cache_turbo_zone name=tiny 8m;   # small zone for eviction test (R6)
    # S8: 32k == the enforced minimum (8 * pagesize). Deliberately the SMALLEST
    # legal zone so a few hundred unique keys genuinely overflow it and force
    # real eviction -- an 8m zone holds tens of thousands of these tiny bodies,
    # so the scan would evict nothing and every S8 assertion would pass for the
    # wrong reason.
    cache_turbo_zone name=srz 64k;    # S8 scan-resistant ON (explicit)
    cache_turbo_zone name=sroffz 64k; # P3-1 default-on control (directive absent)
    cache_turbo_zone name=srexpz 64k; # S8 explicit `off` control (pre-P3-1 flat LRU)
    cache_turbo_zone name=shmref 16m; # refresh-under-pressure (R6b)
    cache_turbo_zone name=at 16m;    # autotune raise/clamp/off (v4-3)
    cache_turbo_zone name=atl 16m;   # autotune load-adaptive stale widen (v4-4)
    cache_turbo_zone name=ati 16m;   # autotune insufficient-data (v4-3)
    cache_turbo_zone name=atch 16m;  # autotune churn-disqualify (v4-3)
    cache_turbo_zone name=ka0 8m;    # Redis keepalive DB-isolation test
    cache_turbo_zone name=ka1 8m;    # Redis keepalive DB-isolation test
    # S2.3: 64k == enforced minimum, same reasoning as S8's srz -- a handful of
    # unique keys genuinely overflow this zone and force real LRU eviction,
    # unlike an 8m/16m zone where the contract test would pass for the wrong
    # reason (nothing ever gets evicted). Drives the no-reaper contract test.
    cache_turbo_zone name=ksevz 64k; # keep_stale no-reaper / LRU-only-reclaim (S2.3)
    # O4.4-i arming-site control. Its OWN zone, not `main`: the test trips the
    # breaker and leaves it OPEN, which would make the older black-box
    # test_breaker_arming_gated_on_breaker_enable() (also on `main`) serve its
    # tripping request from the fallback instead of reaching the dead origin.
    cache_turbo_zone name=brkiz 16m;
    # /breakeron/ and /breakeroff/'s own zone (S231-DEFAULTS) -- see the
    # comment on /breakeron/ below for why this can no longer share `main`.
    cache_turbo_zone name=brkonoffz 16m;
    # S231-DEFAULTS: own zone for /brkdefault/ (compiled-in shipped-default
    # breaker), same reasoning as brkiz above -- tripping it must not perturb
    # /breakeron/'s state on `main`.
    cache_turbo_zone name=brkdefz 16m;
    # S232-BYPASS-STALE: own zone for /bstale/, same isolation reasoning as
    # brkiz -- tripping the breaker there must not perturb any other location.
    cache_turbo_zone name=bstalez 16m;
    # S232-BYPASS-STALE: a SECOND zone for the tests that must run against a
    # CLOSED breaker. breaker_open is 30s, so a test that trips /bstale/ leaves
    # that zone's breaker OPEN far longer than the suite takes to reach the
    # next test -- sharing one zone made the no-trip controls 503 on a breaker
    # someone else tripped, measuring nothing about their own subject.
    cache_turbo_zone name=bstalecz 16m;
    # S232-BYPASS-STALE: a THIRD zone for the never-primed control, which trips
    # its own breaker. It cannot share bstalez: the feature test trips that one
    # and breaker_open holds it OPEN for 30s, so this test's own priming
    # request would 503 on someone else's breaker before it measured anything.
    cache_turbo_zone name=bstalenz 16m;
    # S232-BYPASS-STALE: a FOURTH zone for the safety control, which also trips
    # its own breaker. Every bypass-stale test that trips one needs a private
    # zone: breaker_open holds the state OPEN for 30s, far longer than the gap
    # between two tests, so a shared zone makes the SECOND test 503 on the
    # FIRST test's breaker before it can prime.
    cache_turbo_zone name=bstalesz 16m;
    # O4.4-i L2 half. A SECOND private zone for the L2-backed arming pair
    # (/brkil2on/, /brkil2off/). Separate from brkiz because the L1 pair leaves
    # its own breaker OPEN and the two must not share a breaker state; separate
    # from `main` for the same reason brkiz is. Deliberately TINY (64k) so an
    # entry stored here is evicted from L1 promptly, which is what forces the
    # fallback to come from L2 rather than from an L1 hit -- an L1 hit would
    # bump the l1 counter and prove nothing about the L2 site.
    cache_turbo_zone name=brkil2z 64k;
    # O4.4-d: private zone for the breaker-policy-divergence config-time
    # warning tests. Its OWN zone, not `main` or `brkiz`: both already carry
    # a first-seen breaker policy from other locations, so reusing them would
    # make the "identical tuple, no warning" negative control depend on
    # matching an unrelated fixture's numbers instead of on the two injected
    # locations agreeing with each other.
    cache_turbo_zone name=brkpolz 16m;
    # S7.1: private zone for the breaker_serves/origin_failures counter tests.
    # Its OWN zone, not `brkiz` or `main` -- both already carry breaker trips
    # from other tests by the time these run, and a delta-based assertion
    # needs a breaker that starts CLOSED so the "tripping request reaches the
    # dead origin, the NEXT one is the counted breaker_serves" sequencing
    # (same two-fetch shape as test_breaker_arming_gated_on_breaker_enable) is
    # unambiguous. Its own admin endpoint (/_cache_s71) for the same reason
    # l2negz needed /_cache_l2neg: /_cache is bound to `main` and would read a
    # counter this zone never writes.
    cache_turbo_zone name=s71z 16m;
    # H7.3a: private zone for the Prometheus breaker_opens_total/breaker_state
    # coverage. NOT s71z -- s71z's breaker is left OPEN by test_breaker_counters
    # by the time this runs in run_all()'s ordering, which would make this
    # test's own prime fetch (expected 200, CLOSED) 503 instead. Same
    # "own zone" reasoning as brkiz/s71z above, just one more private zone
    # because s71z is already spent by the time H7.3a needs a CLOSED breaker.
    cache_turbo_zone name=h73z 16m;
    # S7.2: private zone for $cache_turbo_serve_reason coverage. NOT s71z --
    # s71z's breaker is already tripped OPEN by test_breaker_counters by the
    # time this runs in run_all()'s ordering, which would make this test's
    # own FRESH/STALE priming (expects a CLOSED breaker, 200s) collide with a
    # leftover OPEN state. Also needs its own zone for the BREAKER-503 arm: a
    # SECOND uri on the SAME zone, never primed, so it hits breaker_unavailable()
    # once the first uri's dead-origin fetch trips the breaker OPEN -- reusing
    # s71z would let /s71brk/'s trip leave it OPEN too early or too late
    # relative to this test's own sequencing.
    cache_turbo_zone name=sr72z 16m;
    cache_turbo_zone name=s231ncz 16m;   # S231-NOCACHE-OUTAGE (breaker gets tripped OPEN)
    cache_turbo_zone name=s231nccz 16m;  # S231-NOCACHE-OUTAGE negative control (breaker CLOSED)
    cache_turbo_zone name=s231ncvz 16m;  # S231-NOCACHE-OUTAGE ordering (auto-Vary)
    # O4.5: private zone for the breaker LIFECYCLE runtime coverage (state
    # machine end-to-end: OPEN on N failures, zero origin contact while OPEN,
    # 503+Retry-After on a cold key, CLOSE via the post-open probe). Own zone,
    # not s71z/brkiz/h73z/sr72z -- every one of those is left in a tripped or
    # otherwise non-CLOSED state by an earlier test in run_all()'s ordering,
    # and this test needs to observe the FULL CLOSED->OPEN->(probe)->CLOSED
    # cycle from a known-clean start. A short 2s breaker_open (vs. the 30s
    # every other breaker fixture uses) keeps the CLOSE-via-probe assertion
    # fast without idling the suite.
    cache_turbo_zone name=o45z 16m;
    # O4.5 negative control: identical shape, breaker OFF -- proves the OPEN
    # zone's zero-origin-contact result above is caused by the breaker, not
    # some other widening (e.g. keep_stale). Own zone so its origin hit count
    # is never polluted by o45z's traffic.
    cache_turbo_zone name=o45offz 16m;
    # O4.5 / O4.2-f: private zone for the header-filter recording-block pins
    # (success/failure sense of the argument; a cache-turbo HIT records
    # nothing). Own zone so its origin_failures counter cannot be moved by
    # o45z's own trip.
    cache_turbo_zone name=o45hitz 16m;
    # O4.5 / O4.2-f: SEPARATE zone for the POSITION pin only (recording
    # happens before the SIE rewrite). Threshold=1 means the very failure
    # this claim exercises trips the zone's breaker OPEN, and a SECOND trip
    # on a shared zone would hit the pre-origin gate instead of the origin
    # -- own zone so o45hitz's own claim-1 trip (recorded separately) cannot
    # leave this claim's zone already OPEN, or vice versa.
    cache_turbo_zone name=o45hitposz 16m;
    # SUITE-1: private zone for /l2neg/. l2_neg_skips is PER-ZONE
    # (z->sh->l2_neg_skips, module.c:4832), and the outage test asserts a delta
    # of exactly 0 over one request, so any other location writing that counter
    # inside the window fails an assertion about a different URI.
    #
    # !! Scope of that risk, corrected: the increment at module.c:4832 is gated
    # on `clcf->l2_negative_ttl > 0` (module.c:4822), and only FOUR locations
    # in this config set it -- /l2neg/, /l2negout/, /l2neglife/, /l2negmu/.
    # The ~40 other locations sharing `main` are NOT counter writers and never
    # could be, so the "zone bleed from ~40 locations" story is wrong; the real
    # contention was always between these FOUR siblings.
    #
    # As of s128 all four sit in private zones, and the mechanism is PROVEN
    # rather than argued: with /l2neglife/ still in `main`, injecting one
    # memo-skipped /l2negmu/ request into the assertion window of
    # test_l2_negative_ttl_expires moves its delta 0 -> 1; the identical
    # injection against an already-isolated location leaves it at 0. Same
    # binary, same timing, only the zone differs. The harness bounded the
    # window by error.log byte offsets, so an in-window URI provably landed
    # between the two admin reads (unlike _recent_memo_skips(), which tails the
    # WHOLE log and can show a URI that predates the test -- that is most
    # likely what made the discarded ~40-location story look confirmed).
    #
    # !! Still NOT established: that this was the cause of the ORIGINAL SUITE-1
    # intermittency. No foreign write has been observed landing naturally in
    # that window -- only an injected one. A recurrence is therefore possible
    # and would NOT be a regression from this change.
    # NOTE Isolating the zone is only HALF the fix: /_cache is `cache_turbo_admin
    # main`, so a helper reading it after this move would read a counter this
    # location no longer writes and `delta == 0` would be trivially true forever.
    # The paired admin endpoint /_cache_l2neg below is the other half; the two
    # must be changed together or the test goes quiet instead of going correct.
    #
    # 1m, not 16m: these locations run min_uses 4 over a handful of unique keys
    # and store essentially nothing, so the zone only ever holds counter nodes.
    # Sizing them at 16m each cost 32m of shared memory for no coverage, which
    # matters under ASan where the redzone overhead per allocation is large.
    cache_turbo_zone name=l2negz 1m;
    # SUITE-1: private zone for the long-memo outage location (/l2negout/), kept
    # separate from l2negz so the 60s memo cannot bleed into the short-window
    # repeat-GET test's counter, and vice versa.
    cache_turbo_zone name=l2negoutz 1m;
    # SUITE-1 (s128): private zones for the last two memo locations. These were
    # left in `main` by the first split, which kept the defect alive at
    # test_l2_negative_ttl_expires' `delta == 0` -- /l2neglife/ and /l2negmu/ are
    # BOTH l2_neg_skips writers, so a request to one failed an assertion about
    # the other. PROVEN, not argued: same binary, same timing, inject a
    # memo-skipped request mid-window and the delta moves 0 -> 1 when the
    # injected location shares `main`, and stays 0 when it sits in a private
    # zone (see issues.md / HANDOFF for the log-offset-bounded harness).
    #
    # /l2negmu/ also sets min_uses, so this move additionally takes it out of the
    # min_uses_skips contention set that /minuses/ and /pmu/ still share in
    # `main` -- those two keep `== N` equality asserts and are now the only
    # remaining writers of that counter there.
    #
    # 1m for the same reason as l2negz: counter nodes only, and ASan redzones
    # make an oversized zone expensive.
    cache_turbo_zone name=l2neglifez 1m;
    cache_turbo_zone name=l2negmuz 1m;

    # BRK-RA1: private zones for the breaker_retry_after auto-track
    # regression pin. TWO zones, not one shared by /ra1/ and /ra1exp/ --
    # breaker STATE is per-zone (same O4.4-d reasoning as the policy-warn
    # block), so tripping /ra1/'s breaker OPEN would leave /ra1exp/'s own
    # prime fetch answered straight from breaker_unavailable() too, before
    # its own dead-origin trip ever runs. Own zones (not sr72z/s71z/brkiz/
    # etc.) so neither test's own CLOSED-breaker prime is polluted by
    # another test's already-tripped breaker by the time run_all() gets
    # here, same "own zone" reasoning as s71z/h73z/sr72z above.
    cache_turbo_zone name=raz 16m;
    cache_turbo_zone name=raexpz 16m;
    # AUD-STORE-ERR-STUB: private zone for /storefail/'s lock_waits oracle.
    # NOT `main` -- `main` is shared by 166 other test locations, including
    # test_cold_single_flight's 40 deliberately-parking concurrent readers,
    # whose stragglers can land between this test's w0/w1 samples and move
    # the exact-equality assert on an unrelated build (see
    # test_store_failure_cleans_up_cold_stub). Own zone + own admin endpoint
    # (/_cache_storefail) makes the assert observe only /storefail/ traffic.
    cache_turbo_zone name=storefailz 16m;
    # S231-EVICT-BLIND: private tiny zone (64k == enforced minimum, same
    # reasoning as srz/ksevz above -- a handful of unique keys genuinely
    # overflow it and force real eviction) with its own breaker, so tripping
    # it OPEN and filling the zone cannot perturb any other zone's breaker
    # state or LRU contents.
    cache_turbo_zone name=evblindz 64k;
    # S231-PERF-MISSLOCKS: private zone for /mmulock/'s concurrent min_uses +
    # cache_turbo_lock race (a second worker claiming the key between what
    # used to be count_miss()'s and claim()'s separate mutex acquisitions).
    # NOT `main` -- min_uses_skips and lock_waits are zone-global counters and
    # `main` already carries traffic from 166+ other locations by the time
    # this runs, so a delta-based assert here needs its own zone + admin
    # endpoint for the same reason storefailz does.
    cache_turbo_zone name=mmulockz 16m;

    # Q1 end-to-end: stacked native proxy_cache, one zone per suppress mode, so
    # a test can prove cache_turbo_suppress_native actually keeps the native
    # cache empty (vs the inert default where proxy_cache stores normally).
    proxy_cache_path {root}/pcache_on  keys_zone=ctpcon:1m  levels=1:2
                     inactive=10m max_size=64m;
    proxy_cache_path {root}/pcache_off keys_zone=ctpcoff:1m levels=1:2
                     inactive=10m max_size=64m;
    # O4.2-f: dedicated proxy_cache zone for /o45natpc/'s native-HIT-records-
    # nothing check. NOT ctpcon -- test_suppress_native_e2e_proxy_cache
    # asserts ctpcon stays EMPTY (proof cache_turbo_suppress_native
    # suppressed it), and /o45natpc/ deliberately stores through its own
    # proxy_cache normally, which would pollute that assertion.
    proxy_cache_path {root}/pcache_o45 keys_zone=ctpo45:1m levels=1:2
                     inactive=10m max_size=64m;

    server {{
        listen 127.0.0.1:{port};
{sk_loc}
{redis_loc}
{mc_loc}
{dsn_loc}
{fault_loc}

        # SERVER-level preset: inherited by every location that does not name a
        # backend of its own. /nonepreset/ overrides it with `none` -- that is
        # the whole point of `none`, and without an inherited preset here that
        # test would pass vacuously.
        cache_turbo_backend wordpress;

        # standard 30s-fresh cache
        location /c/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_max_size 1m;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # compressed-edge regression (2026-06-13 incident): a real nginx gzip
        # filter sits in front of cache_turbo. gzip_proxied any + gzip_min_length
        # 1 force compression even on the tiny origin body. With the dh_nginx
        # prio-80 load-order fix cache_turbo's body filter runs ABOVE gzip, so it
        # captures the IDENTITY body (no Content-Encoding) and gzip re-encodes per
        # client on MISS and HIT alike. Drives test_compressed_edge_identity_capture.
        location /gz/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            gzip                 on;
            gzip_types           application/json;
            gzip_min_length      1;
            gzip_proxied         any;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # cold-miss single-flight (v10), per-box: cache_turbo_lock is ON by
        # default, so a burst of first-hits on one cold key collapses to a
        # single origin fetch; the rest wait then serve the filled entry.
        location /cold/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_lock_ttl 5s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # cold-miss single-flight DISABLED: the gate-off control. The same burst
        # stampedes the origin (one hit per reader).
        location /coldoff/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_lock     off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # min_uses (v15): only cache after the key has cold-missed 3 times, so a
        # one-hit-wonder URL never occupies the cache. The first two misses go to
        # the origin without storing; the third stores; the fourth is a HIT.
        location /minuses/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_min_uses 3;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # cacheability floor (RFC 9111): origin emits Set-Cookie / Cache-Control
        # based on the path marker; such responses must never be stored. key=$uri
        # so repeated requests share a slot (proving the refusal, not just a key
        # split).
        location /cc/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ignore_cc: with cache_turbo_cache_control ignore, the response
        # Cache-Control floor (here max-age=0 via the ccmaxage0 path marker) is
        # ignored and the entry is stored at cache_turbo_valid. Mirrors nginx
        # proxy_ignore_headers Cache-Control. key=$uri to share a slot.
        location /ccign/ {{
            cache_turbo               main;
            cache_turbo_key           $uri;
            cache_turbo_valid         30s;
            cache_turbo_cache_control ignore;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # default cache key (no cache_turbo_key) = $host$request_uri, so two
        # Host headers on the same path must NOT collide.
        location /dk/ {{
            cache_turbo          main;
            cache_turbo_valid    30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # conditional requests (v11): origin emits ETag + Last-Modified; a HIT
        # whose stored validators satisfy If-None-Match / If-Modified-Since is
        # answered 304 (no body) straight from cache.
        location /cond/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUD-RANGE1: origin honours Range (rngsrc path marker); a HIT must
        # answer Range: identically to a MISS instead of always replaying 200.
        location /range/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Range over a STALE-IF-ERROR serve. r->allow_ranges is set in
        # restore_response(), which sie_rewrite() shares with the live HIT path,
        # so the SIE serve must range identically to a HIT. Same short-fresh
        # shape as /sieserve/ (1s fresh, stale_mult 1 -> 1s stale window, fully
        # expired by ~1.3s) but with the rngsrc+rngsie markers so the stored
        # blob is Range-capable AND carries stale-if-error=30. Drives
        # test_range_on_sie_serve.
        location /rangesie/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 1s;
            cache_turbo_stale_mult 1;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # RFC-6: short fresh TTL + ETag (the origin emits validators for any
        # path containing "cond") so a conditional request can be made against a
        # STALE entry. beta 1 ~ never rolls a refresh, so the read is a
        # deterministic STALE serve - and a 304 must NOT be answered from it.
        location /condst/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 1s;
            cache_turbo_beta  1;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # RFC-2: fresh 1s; default stale window would be 3s (stale_mult 4 ->
        # expire at 4s), but the origin's stale-while-revalidate=10 extends it,
        # so the entry is still STALE-serveable at 5s. beta 1 ~ no refresh.
        location /swrdur/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 1s;
            cache_turbo_beta  1;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # per-status caching (v6): cache redirects + negative responses too
        location /st/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            cache_turbo_valid 301 302 308 30s;
            cache_turbo_valid 404 410 30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # honor upstream Cache-Control (v7): origin says max-age=1, so the entry
        # goes stale at ~1s even though cache_turbo_valid is 60s. beta 1 ~ never
        # refresh, so a read inside the stale window is deterministically STALE.
        location /cc7/ {{
            cache_turbo                    main;
            cache_turbo_key                $uri;
            cache_turbo_valid              60s;
            cache_turbo_beta               1;
            cache_turbo_cache_control       honor;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # must-revalidate (RFC 9111): honor_cc reads max-age=1 (fresh 1s); the
        # must-revalidate token collapses the stale window, so at ~2s the entry
        # is NOT stale-served (as /cc7/ would be) but re-fetched. beta 1 ~ never
        # rolls a refresh, isolating the must-revalidate behaviour.
        location /mrev/ {{
            cache_turbo                    main;
            cache_turbo_key                $uri;
            cache_turbo_valid              60s;
            cache_turbo_beta               1;
            cache_turbo_cache_control       honor;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUD-CC-FIRST-LINE: same must-revalidate collapse as /mrev/, but the
        # origin (splitmrev marker) sends max-age and must-revalidate on TWO
        # separate Cache-Control field-lines instead of one. Proves the fix
        # walks every Cache-Control line rather than only the first.
        location /ccsplit/ {{
            cache_turbo                    main;
            cache_turbo_key                $uri;
            cache_turbo_valid              60s;
            cache_turbo_beta               1;
            cache_turbo_cache_control       honor;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ignore_cc vs must-revalidate: cache_turbo_cache_control ignore must
        # make the ENTIRE response Cache-Control inert, not just the cacheability
        # floor. The origin emits "max-age=1, must-revalidate"; without ignore
        # the must-revalidate token collapses the stale window (like /mrev/), but
        # with ignore the window stays valid*stale_mult (2s*4 = 8s), so at ~4s
        # the entry is still STALE-served, not a hard miss. fresh = valid 2s
        # (ignore forces honor off). beta 1 ~never rolls a refresh, so the
        # stale read is a clean STALE serve (no dice regen polluting origin).
        #
        # !! valid is 2s, NOT the 1s the origin declares, and the test's sleep
        # is sized from it. At valid 1s the prime->HIT assert raced the 1s fresh
        # edge: a loaded runner (ASan, busy CI box) taking >1s between the two
        # fetches makes STALE the CORRECT answer and the test fails on box speed,
        # not on module behaviour (SUITE-4). Both edges scale together -- widening
        # valid alone would move the stale read back inside the FRESH window and
        # break the STALE assert instead.
        #
        # Total serve life is valid*stale_mult ABSOLUTE, not fresh + stale on top:
        # shm_store() sets stale_until = now + stale_ttl(valid, stale_mult), so
        # 2s*4 = 8s total == 2s fresh + 6s stale. When retuning, the sleep must
        # satisfy valid < sleep < valid*(stale_mult-1) -- the lower slack absorbs
        # the prime, and the upper one the elapsed time before the sleep starts.
        # Here that is 2 < 4 < 6.
        location /ccignmr/ {{
            cache_turbo               main;
            cache_turbo_key           $uri;
            cache_turbo_valid         2s;
            cache_turbo_beta          1;
            cache_turbo_cache_control ignore;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # PURGE method (v14): `PURGE /pg/x` drops that entry from L1 (+L2)
        location /pg/ {{
            cache_turbo       main;
            cache_turbo_key   $uri;
            cache_turbo_valid 30s;
            cache_turbo_purge on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Access-phase regression: both locations use the same cache key, but
        # the denied location must reject a cached GET and PURGE before cache
        # lookup/side effects run.
        location /acl-seed/ {{
            cache_turbo       main;
            cache_turbo_key   $arg_k;
            cache_turbo_valid 30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /acl-denied/ {{
            cache_turbo       main;
            cache_turbo_key   $arg_k;
            cache_turbo_valid 30s;
            cache_turbo_purge on;
            deny all;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # bypass (v9): ?nocache=1 skips the cache lookup but still refreshes it
        location /bp/ {{
            cache_turbo        main;
            cache_turbo_key    $uri;
            cache_turbo_valid  30s;
            cache_turbo_bypass $arg_nocache;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # DIY manual URI bypass (cache_turbo_bypass_uri, v15): the preset
        # segment-boundary matcher exposed as a directive, for an app we ship no
        # preset for. "/bu/panel" bypasses on a segment boundary; "/bu/panel-x"
        # (letters continue past the needle) must NOT -- that boundary check is
        # exactly what a plain nginx location prefix cannot express. Mounted at a
        # subdir to prove the matcher is subdirectory-safe. X-CT-Status makes
        # BYPASS a POSITIVE signal (a plain MISS also lacks x-cache).
        location /bu/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_bypass_uri /bu/panel /bu/admin/;
            add_header           X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Subdirectory install (cache_turbo_backend_prefix, item 18): preset
        # uris[] are literals anchored at byte 0 ("/wp-admin/"), so a WordPress
        # mounted at /shop/ matches NO URI rule and its admin surface caches.
        # The directive rebases r->uri onto the mount before the preset URI tier
        # runs. /shop/ has it; /noshop/ is the SAME app WITHOUT it and exists to
        # pin that the bug is real -- if /noshop/wp-admin/ ever stops caching,
        # the /shop/ assertions below are passing for the wrong reason.
        location /shop/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_backend  wordpress;
            cache_turbo_backend_prefix /shop/;
            add_header           X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Directive value deliberately does NOT match this location's own path:
        # requests here reach the module with backend_prefix set to /shop/ while
        # r->uri starts with /elsewhere/, which is the ONLY way to exercise the
        # no-rebase branch (a request routed to /shop/ always starts with it).
        # A misconfigured mount must leave the URI alone, not force a match.
        location /elsewhere/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_backend  wordpress;
            cache_turbo_backend_prefix /shop/;
            add_header           X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location /noshop/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_backend  wordpress;
            add_header           X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # DIY cookie value-keying (cache_turbo_key_cookie, v15): the tier-3
        # magento engine exposed as a directive. "seg" is value-keyed into the
        # cache key -- different values get different entries, the SAME value
        # shares one, and an absent cookie is its own anonymous bucket. Same
        # unforgeable length-prefixed fold, EXACT-name match, all Cookie headers
        # scanned -- but with NO preset.
        location /kc/ {{
            cache_turbo            main;
            cache_turbo_key        $uri;
            cache_turbo_valid      30s;
            cache_turbo_key_cookie seg;
            add_header             X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # $cache_turbo_status access-log variable: echoed into a header so the
        # test can read MISS -> HIT, and BYPASS when ?nocache=1 trips bypass.
        location /ctstatus/ {{
            cache_turbo        main;
            cache_turbo_key    $uri;
            cache_turbo_valid  30s;
            cache_turbo_bypass $arg_nocache;
            add_header         X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # $cache_turbo_status STALE + EXPIRED: short fresh TTL (1s) so the
        # default stale_mult 4 gives a 4s serveable window; beta 1 keeps the
        # refresh dice at ~0 so a stale read is a clean STALE serve (not a
        # refresh-to-HIT), and sleeping past 4s makes the entry EXPIRED.
        location /ctstale/ {{
            cache_turbo        main;
            cache_turbo_key    $uri;
            cache_turbo_valid  1s;
            cache_turbo_beta   1;
            add_header         X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # RFC-1 request Cache-Control serve verdict (req_serve_verdict): a
        # client's own max-age/min-fresh/max-stale bound the entry it will
        # accept. Long fresh window (30s) so the entry is unambiguously FRESH
        # for the max-age/min-fresh cases; a separate 1s+beta1 sibling (/reqccst/)
        # lets an entry go STALE so max-stale tolerance can be exercised.
        location /reqcc/ {{
            cache_turbo        main;
            cache_turbo_key    $uri;
            cache_turbo_valid  30s;
            add_header         X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /reqccst/ {{
            cache_turbo        main;
            cache_turbo_key    $uri;
            cache_turbo_valid  1s;
            cache_turbo_beta   1;
            add_header         X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # cc_mode (cache_turbo_cache_control) merge precedence: a child location
        # with a CMS backend preset (cc_mode defaults to honor) under a parent
        # that set `ignore` must resolve to HONOR, NOT inherit the parent ignore
        # (the merged tri-state cannot represent "both" the way the old two-flag
        # model accidentally did). honor respects the cacheability floor, so the
        # origin's `private` response is NOT cached at the child; the parent
        # (ignore) DOES cache it. Origin emits "private, max-age=60" for ccprivate.
        location /ccinh/ {{
            cache_turbo               main;
            cache_turbo_key           $uri;
            cache_turbo_valid         30s;
            cache_turbo_cache_control ignore;
            proxy_pass http://127.0.0.1:{origin_port}/;

            location /ccinh/wp/ {{
                cache_turbo         main;
                cache_turbo_backend wordpress;
                cache_turbo_key     $uri;
                cache_turbo_valid   30s;
                proxy_pass http://127.0.0.1:{origin_port}/;
            }}
        }}

        # no_store (v9): ?private=1 means the response is never stored
        location /nost/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_no_store $arg_private;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # short fresh TTL so the stale window is reachable in-test
        location /swr/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;     # stale window = 3s, expires at 4s
            cache_turbo_beta     5000;   # aggressive: refresh likely while stale
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # stale-if-error (v8): background_update is ON by default, so a stale
        # dice-winner serves stale + refreshes in the background. A failing
        # origin never overwrites the entry -> the stale copy persists.
        location /sie/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    2s;     # fresh 2s, stale window x4 -> 8s
            cache_turbo_beta     5000;   # aggressive: a stale read fires a refresh
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # RFC-2 stale-if-error serve-on-error (CTB4). Short fresh (1s, stale_mult
        # 1 -> 1s stale window, fully expired by ~1.3s). The origin emits
        # stale-if-error=30 ONLY when the request suffix carries the "sieserve"
        # marker (proxy_pass strips the /sieserve/ prefix), so a /sieserve/sieserve-*
        # key gets a serve-on-error window and a /sieserve/plain-* key does NOT.
        # The plain-* key is the negative control: an expired entry with no SIE
        # window must surface the origin error. Drives test_sie_serve_on_error.
        location /sieserve/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_stale_mult 1;
            # S231-DEFAULTS: pinned off. The no-SIE negative controls here
            # (test_sie_serve_on_error, test_sie_serves_counter) rely on a
            # PLAIN expired entry surfacing the origin's 503 directly -- left
            # at the new 24h default, cache_turbo_keep_stale would serve it
            # stale via S2.2 instead and make those negative controls vacuous.
            cache_turbo_keep_stale off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUD-SIE-BODY regression: same fixture shape as /sieserve/ (the
        # "sieserve" request-suffix marker still reaches the origin, since
        # proxy_pass only strips the /siebuf/ prefix) but with proxy_buffering
        # off. The body filter's sie_serving block discards the incoming
        # upstream error chain without marking it consumed; under a buffered
        # upstream there is slack so the bug never reproduces, but with
        # buffering off the discarded buffers stay on the upstream's
        # busy_bufs forever and the request hangs. Drives
        # test_sie_serve_on_error_unbuffered.
        location /siebuf/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_stale_mult 1;
            proxy_buffering       off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # P1-8: cold-miss LOSER serves the armed stale-if-error snapshot
        # instead of stampeding the origin when lock_timeout expires.
        # Same expiry shape as /sieserve/ (valid 1s, stale_mult 1 -> fully
        # expired ~1.3s after priming, "sieserve" request-suffix marker gets
        # the origin's stale-if-error=30). lock_ttl 5s / lock_timeout 1s:
        # long enough that the CLAIM_WINNER (made slow via origin.delay)
        # never finishes inside the loser's wait window, short enough that
        # the loser's park+giveup completes well under fetch()'s 5s client
        # timeout. cache_turbo_lock stays ON (default) so a second request
        # against the same key while the first is in flight becomes a real
        # CLAIM_LOSER, not an independent cold miss. Drives
        # test_cold_wait_loser_serves_stale_on_lock_timeout.
        location /coldwaitsie/ {{
            cache_turbo              main;
            cache_turbo_key          $uri;
            cache_turbo_valid        1s;
            cache_turbo_stale_mult   1;
            cache_turbo_lock_ttl     5s;
            cache_turbo_lock_timeout 1s;
            # S231-DEFAULTS: pinned off, same reasoning as /sieserve/ above --
            # the negative control here (a "plain" key with no response
            # stale-if-error) relies on sie_ttl staying 0 so the timed-out
            # loser's fall-through-to-origin behaviour is genuinely
            # unexercised by SIE. Left at the 24h default, keep_stale would
            # arm a snapshot for EVERY key regardless of the origin's
            # headers and the negative control would be vacuous.
            cache_turbo_keep_stale off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # UNBUF: proxy_buffering off with an ordinary (non-error) streamed
        # multi-chunk origin body. /siebuf/ above only drives the SIE
        # serve-on-error body-filter consume path; this location covers the
        # ordinary capture/store + HIT-serve path under the SAME
        # multi-invocation body filter, exercising ctx->body_last append and
        # last_buf/last_in_chain accumulation across calls. Drives
        # test_unbuf_streamed_store_and_hit.
        location /unbuf/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            proxy_buffering       off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # UNBUF oversize: same proxy_buffering off + streamed multi-chunk
        # origin body as /unbuf/, but with a small cache_turbo_max_size so the
        # limit is crossed MID-STREAM on a later body-filter invocation
        # rather than on the first buffer. Drives
        # test_unbuf_oversize_abort_mid_stream.
        location /unbufbig/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_max_size 8k;
            proxy_buffering       off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S2.2: cache_turbo_keep_stale feeds sie_window when the response
        # carries NO stale-if-error of its own (D-1 precedence table). Origin
        # for this location sends no Cache-Control at all -> keep_stale is the
        # only thing standing between an expired entry and a surfaced error.
        # Short fresh (1s) / stale (stale_mult 1 -> 1s) window like /sieserve/ so
        # the entry is fully expired quickly. Drives test_keep_stale_serves_dead_origin.
        location /keepstale/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_stale_mult 1;
            cache_turbo_keep_stale 1h;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-DEFAULTS: NO cache_turbo_keep_stale directive at all -- proves
        # the compiled-in merge default is 24h, not just that `24h;` works
        # when written out explicitly (every /keepstale*/ location above opts
        # in explicitly). Same short fresh/stale shape as /keepstale/ (1s
        # fresh, stale_mult 1 -> 1s stale window) so a dead-origin fetch
        # against a fully expired entry isolates the shipped default rather
        # than the explicit 1h window. Drives
        # test_keep_stale_shipped_default_serves_dead_origin.
        location /ksdefault/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_stale_mult 1;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S4.2: cache_turbo_use_stale decides WHICH upstream statuses fall back
        # to a stale copy. keep_stale 1h supplies the serve-on-error window (the
        # origin for these locations sends no Cache-Control), so the only
        # variable between the three locations below is the use_stale mask.
        #
        # http_404 alone: a 404 must serve stale, and a 503 must NOT (the mask
        # names 404 and nothing else). That second half is what makes this test
        # discriminating -- a broken mask read that just triggers on everything
        # passes the 404 arm on its own. Drives test_use_stale_http_404.
        location /usestale404/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_stale_mult 1;
            cache_turbo_keep_stale 1h;
            cache_turbo_use_stale http_404;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Negative control for /usestale404/: identical apart from the missing
        # use_stale directive, i.e. the merge default (every 5xx, no 404). A 404
        # here must surface as a 404. If this location ever serves stale on a
        # 404, the default mask has been widened or the merge is broken.
        location /usestaledefault/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_stale_mult 1;
            cache_turbo_keep_stale 1h;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S4.2 / S4.1-b: pins ANY_5XX down. The mask names http_500 only, so a
        # 500 serves stale while a 507 -- a 5xx no explicit bit covers -- must
        # surface. Dropping ANY_5XX from USE_STALE_DEFAULT is invisible to the
        # parse tests and to the two locations above; this one catches it via
        # /usestaledefault/ (default mask, 507 -> stale) versus here.
        location /usestale500/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_stale_mult 1;
            cache_turbo_keep_stale 1h;
            cache_turbo_use_stale http_500;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S4.2: `off` is not "no directive" -- it is an EMPTY mask, so nothing
        # triggers a stale serve, not even the 5xx the default covers. Same
        # keep_stale 1h window as its siblings, so the window is not what
        # differs. Drives test_use_stale_off.
        location /usestaleoff/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_stale_mult 1;
            cache_turbo_keep_stale 1h;
            cache_turbo_use_stale off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S4.2: the two non-5xx tokens that are not 404. Covers the remaining
        # explicit bits so no status token ships on parse-test evidence alone.
        # Drives test_use_stale_403_429.
        location /usestale403429/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_stale_mult 1;
            cache_turbo_keep_stale 1h;
            cache_turbo_use_stale http_403 http_429;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # P5-5: error/timeout now mean "transport failure only", NOT "any
        # 502/504 regardless of origin provenance". This location names error
        # and timeout ALONE (no http_502/http_504), so a stale serve here can
        # only come from the transport-failure discrimination -- a real
        # origin-emitted 502/504 must surface unchanged. Drives
        # test_use_stale_error_transport_only.
        location /usestaleerroronly/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_stale_mult 1;
            cache_turbo_keep_stale 1h;
            cache_turbo_use_stale error timeout;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # O4.4: the circuit breaker's own on/off switch (cache_turbo_breaker),
        # independent of the threshold/window off-switches the config-parse
        # tests already cover. NO keep_stale/use_stale window here on purpose:
        # once the entry is past its stale window (1s fresh, stale_mult 1 -> 1s
        # stale) the ONLY thing that can still answer a dead origin with a cached body is
        # the breaker's own any-age fallback (call site 1 in
        # ngx_http_cache_turbo_access_handler) -- so this isolates that call
        # site's routing through breaker_should_consult() rather than
        # overlapping RFC-2/keep_stale, which have their own coverage above.
        # Drives test_breaker_arming_gated_on_breaker_enable. Own zone
        # (brkonoffz), not `main`: S231-DEFAULTS made breaker_enable/
        # threshold/window shipped-on by default, so `main`'s ~120+ other
        # locations (which set no breaker directives at all) now pick up the
        # compiled-in defaults (5/10s) -- sharing `main` here would make this
        # location's deliberately-fast explicit tuple (threshold=1/window=60s,
        # chosen to trip on a single request) diverge from that ambient
        # default and trip the O4.4-d policy-divergence warning on every
        # config load. /breakeroff/ shares brkonoffz with this location (they
        # need to compare against each other, not against `main`).
        location /breakeron/ {{
            cache_turbo                    brkonoffz;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_stale_mult          1;
            # keep_stale is ALSO on by default now (S231-DEFAULTS, 24h) and
            # would mask the dead origin behind S2.2's serve-on-error
            # fallback before the tripping request ever reached it -- off
            # here so this isolates the breaker call site alone.
            cache_turbo_keep_stale          off;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Negative control for /breakeron/: identical apart from
        # `cache_turbo_breaker off`. threshold/window/open are still set (an
        # operator who left the breaker off but configured the tuning knobs)
        # -- if breaker_enable were not an independent gate at the arming call
        # site, this location would ALSO fall back to the stale snapshot on a
        # dead origin, exactly like /breakeron/. It must instead surface the
        # origin failure, because with the breaker off nothing may EVER be
        # armed or consulted. keep_stale off for the same reason as
        # /breakeron/ above (S231-DEFAULTS): it would otherwise mask the
        # dead origin via S2.2 regardless of the breaker flag, making this
        # negative control vacuous.
        location /breakeroff/ {{
            cache_turbo                    brkonoffz;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_stale_mult          1;
            cache_turbo_keep_stale          off;
            cache_turbo_breaker             off;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-DEFAULTS: NO cache_turbo_breaker/threshold/window directives at
        # all -- proves the compiled-in merge defaults are breaker_enable=1,
        # breaker_threshold=5, breaker_window=10s, not just that `on;
        # threshold 1; window 60s;` works when written out explicitly (every
        # /breaker*/ location above opts in explicitly). Own zone so tripping
        # it here cannot perturb /breakeron/'s counters on `main`. threshold=5
        # means five failing responses are needed to trip CLOSED -> OPEN (vs.
        # threshold=1 on /breakeron/), so the test below drives five tripping
        # fetches before the sixth observes the tripped state. Drives
        # test_breaker_shipped_default_trips_and_serves_stale.
        location /brkdefault/ {{
            cache_turbo             brkdefz;
            cache_turbo_key         $uri;
            cache_turbo_valid       1s;
            cache_turbo_stale_mult  1;
            cache_turbo_lock_timeout 2s;
            # keep_stale is now ALSO on by default (S231-DEFAULTS, 24h) and
            # would mask a dead origin behind S2.2's serve-on-error fallback
            # before the breaker ever gets a chance to trip -- explicitly off
            # here so this location isolates the breaker default alone.
            cache_turbo_keep_stale  off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S232-BYPASS-STALE. /bstale/api/ is opted in to breaker-only storage;
        # /bstale/plain/ is NOT, and is the negative control proving the
        # directive is scoped rather than blanket. threshold=1 so a single dead
        # -origin request trips CLOSED -> OPEN. keep_stale off for the same
        # reason as /brkdefault/: it would answer from the stale entry before
        # the breaker could trip, masking what these tests measure.
        location /bstale/ {{
            cache_turbo             bstalez;
            cache_turbo_key         $uri;
            cache_turbo_valid       1s;
            cache_turbo_stale_mult  1;
            cache_turbo_keep_stale  off;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            cache_turbo_bypass_stale_uri  /bstale/api;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S232-BYPASS-STALE, safety control. Own zone + own breaker to trip,
        # for the same 30s-open-window reason as /bstalen/ below.
        location /bstales/ {{
            cache_turbo             bstalesz;
            cache_turbo_key         $uri;
            cache_turbo_valid       1s;
            cache_turbo_stale_mult  1;
            cache_turbo_keep_stale  off;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            cache_turbo_bypass_stale_uri  /bstales/api;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S232-BYPASS-STALE, never-primed control. Its own zone + its own
        # breaker to trip, so it never races the feature test's 30s open window.
        location /bstalen/ {{
            cache_turbo             bstalenz;
            cache_turbo_key         $uri;
            cache_turbo_valid       1s;
            cache_turbo_stale_mult  1;
            cache_turbo_keep_stale  off;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            cache_turbo_bypass_stale_uri  /bstalen/api;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S232-BYPASS-STALE, CLOSED-breaker half. Same directives as /bstale/
        # but on its own zone and with the breaker left at its default (never
        # tripped here), so the normal-path and scope controls measure their
        # own subject rather than a breaker some earlier test opened.
        location /bstalec/ {{
            cache_turbo             bstalecz;
            cache_turbo_key         $uri;
            cache_turbo_valid       1s;
            cache_turbo_stale_mult  1;
            cache_turbo_keep_stale  off;
            cache_turbo_bypass_stale_uri  /bstalec/api;
            add_header              X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # O4.4-i white-box arming control. Mirrors /breakeron/ and /breakeroff/
        # exactly, but on the dedicated `brkiz` zone so tripping the breaker here
        # cannot perturb the black-box test that shares `main`. Drives
        # test_breaker_arming_sites_gated_white_box, which reads the
        # TEST_FAULTS-only arming counter off these responses.
        location /brkion/ {{
            cache_turbo                    brkiz;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_keep_stale         off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default
            cache_turbo_stale_mult          1;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location /brkioff/ {{
            cache_turbo                    brkiz;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_keep_stale         off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default
            cache_turbo_stale_mult          1;
            cache_turbo_breaker            off;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S7.2: $cache_turbo_serve_reason coverage, FRESH/STALE arms. Same
        # shape as /ctstale/ (1s fresh -> x4=4s stale, beta 1 so the refresh
        # dice never fires) but on the private sr72z zone. Drives
        # test_serve_reason_variable.
        location /sr72/ {{
            cache_turbo        sr72z;
            cache_turbo_key    $uri;
            cache_turbo_valid  1s;
            cache_turbo_beta   1;
            # S231-DEFAULTS: pinned off explicitly. This location does not
            # exercise the breaker; left at the (now shipped-on) default it
            # would diverge from /sr72brk/'s deliberately fast explicit tuple
            # (threshold=1/window=60s) on this shared zone and trip the
            # O4.4-d policy-divergence warning on every config load.
            cache_turbo_breaker off;
            add_header         X-CT-Reason $cache_turbo_serve_reason always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S7.2: $cache_turbo_serve_reason coverage, STALE-IF-ERROR arm. Same
        # shape as /sieserve/ (the "sieserve" request-suffix marker makes the
        # origin emit stale-if-error=30) but on sr72z so the breaker arm below
        # can trip that zone's breaker without disturbing this location's own
        # fully-expired-entry setup. Drives test_serve_reason_variable.
        location /sr72sie/ {{
            cache_turbo        sr72z;
            cache_turbo_key    $uri;
            cache_turbo_valid  1s;
            cache_turbo_stale_mult 1;
            # S231-DEFAULTS: see /sr72/ above -- same reason, pinned off.
            cache_turbo_breaker off;
            add_header         X-CT-Reason $cache_turbo_serve_reason always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S7.2: $cache_turbo_serve_reason coverage, STALE-BREAKER + BREAKER-503
        # arms. Same shape as /s71brk/ (1s fresh, stale_mult 1 -> 1s stale,
        # threshold=1) but on sr72z: the /dead key gets primed then trips the breaker OPEN, the
        # /never key is NEVER primed so once the breaker is OPEN it has no
        # armed copy at all and falls into breaker_unavailable() (BREAKER-503).
        # Drives test_serve_reason_variable.
        location /sr72brk/ {{
            cache_turbo                    sr72z;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_keep_stale         off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default
            cache_turbo_stale_mult          1;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            add_header         X-CT-Reason $cache_turbo_serve_reason always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-NOCACHE-OUTAGE: private zone for the "honour cache instead of a
        # client's Cache-Control: no-cache while the origin is known down" gate
        # (:4749 in ngx_http_cache_turbo_module.c). Own zone (s231ncz), not
        # sr72z/brkiz/s71z/etc: this location primes then trips ITS OWN breaker
        # OPEN, which must not perturb any other test's CLOSED-breaker
        # expectations on a shared zone. threshold=1/stale_mult=1/keep_stale off
        # mirror /sr72brk/'s fast-trip shape. Drives
        # test_nocache_breaker_open_honours_cache and
        # test_nocache_breaker_closed_still_revalidates (negative control).
        location /s231nc/ {{
            cache_turbo                    s231ncz;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_keep_stale         off;  # isolate from the 24h keep_stale default
            cache_turbo_stale_mult          1;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            add_header         X-CT-Reason $cache_turbo_serve_reason always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-NOCACHE-OUTAGE negative control: identical shape to /s231nc/ but
        # on its OWN zone (s231nccz) that is NEVER tripped -- proves the fix
        # only kicks in while the breaker is actually OPEN, not unconditionally.
        # Drives test_nocache_breaker_closed_still_revalidates. Also carries
        # the only-if-cached-out-of-scope regression pin
        # (test_nocache_only_if_cached_still_504), since that arm is unaffected
        # by breaker state either way and needs no tripping.
        location /s231ncc/ {{
            cache_turbo                    s231nccz;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_keep_stale         off;
            cache_turbo_stale_mult          1;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            add_header         X-CT-Reason $cache_turbo_serve_reason always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-NOCACHE-OUTAGE ordering-hazard regression: same breaker shape as
        # /s231nc/ but with auto-Vary on, on its OWN zone (s231ncvz) so tripping
        # this breaker cannot perturb /s231nc/'s. The gate at :4749 runs BEFORE
        # ngx_http_cache_turbo_vary_resolve() (:4762) -- falling through on a
        # breaker-OPEN no-cache request must still resolve the variant key
        # before the cache lookup below it runs, or a varying URL would probe
        # the BASE key and silently serve the wrong (or no) variant. Drives
        # test_nocache_breaker_open_varying_url_serves_correct_variant.
        location /s231ncv/ {{
            cache_turbo                    s231ncvz;
            cache_turbo_key                $request_uri;
            cache_turbo_valid               30s;
            cache_turbo_auto_vary           on;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            add_header         X-CT-Reason $cache_turbo_serve_reason always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-NOCACHE-OUTAGE ordering-hazard breaker trigger: SAME zone
        # (s231ncvz) as /s231ncv/ above -- the breaker STATE is per-zone, so
        # tripping it here also flips /s231ncv/'s view of the breaker -- but a
        # SHORT cache_turbo_valid (1s) of its own, distinct from /s231ncv/'s
        # 30s. This lets the tripping key (/dead) expire and trip fast while
        # the gzip/br variants primed on /s231ncv/ stay comfortably fresh for
        # the whole sequence. Drives
        # test_nocache_breaker_open_varying_url_serves_correct_variant.
        location /s231ncvbrk/ {{
            cache_turbo                    s231ncvz;
            cache_turbo_key                $request_uri;
            cache_turbo_valid               1s;
            cache_turbo_keep_stale         off;
            cache_turbo_stale_mult          1;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # BRK-RA1 regression pin: cache_turbo_breaker_open set to a small,
        # non-30 value (2s) and NO explicit cache_turbo_breaker_retry_after
        # -- the auto-track path. Own zone (raz) so the CLOSED-breaker prime
        # is not polluted by any other test's already-tripped breaker.
        # /ra1/never is deliberately never primed so, once the breaker is
        # OPEN, it has no cached copy at all and falls straight into
        # ngx_http_cache_turbo_breaker_unavailable() -- same COLD-url shape as
        # /sr72brk/never above. Drives test_breaker_retry_after_auto_tracks_
        # breaker_open.
        location /ra1/ {{
            cache_turbo                    raz;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_keep_stale         off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default
            cache_turbo_stale_mult          1;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open        2s;
            cache_turbo_lock_timeout        2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # BRK-RA1 positive control: identical shape to /ra1/ but with an
        # EXPLICIT cache_turbo_breaker_retry_after that must still win over
        # the derived default -- proves the fix does not break the explicit
        # path while fixing the auto-track one.
        location /ra1exp/ {{
            cache_turbo                    raexpz;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_keep_stale         off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default
            cache_turbo_stale_mult          1;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open        2s;
            cache_turbo_breaker_retry_after 7s;
            cache_turbo_lock_timeout        2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S7.1: breaker_serves / origin_failures counter coverage. Same shape
        # as /breakeron/ (1s fresh, stale_mult 1 -> 1s stale, threshold=1) but on its own
        # zone (s71z) so the admin JSON delta is not polluted by /breakeron/'s
        # or /brkion/'s already-tripped breaker. Drives test_breaker_counters.
        location /s71brk/ {{
            cache_turbo                    s71z;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_keep_stale         off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default
            cache_turbo_stale_mult          1;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S7.1: admin endpoint for /s71brk/'s private zone (s71z). This must NOT
        # sit in the redis-gated block because it carries no cache_turbo_redis
        # directive -- placing it here alongside /s71brk/ ensures it exists even
        # when Redis is unavailable, so test_breaker_counters can query the counters.
        location = /_cache_s71 {{
            cache_turbo_admin    s71z;
            allow 127.0.0.1;
            deny all;
        }}

        # O4.5: breaker LIFECYCLE end-to-end. /o45/o45cache is primed then
        # tripped (same 1s-fresh/stale_mult-1-1s-stale/threshold=1 shape as /s71brk/) so
        # a re-fetch while OPEN proves zero origin contact (origin.hits_for
        # unchanged) by serving the armed any-age snapshot. /o45/o45cold shares
        # the zone but is NEVER primed, so once OPEN it has no snapshot to
        # arm and falls into breaker_unavailable() (503 + Retry-After) --
        # same "second, never-primed uri on the same zone" shape as
        # /sr72brk/'s BREAKER-503 arm. breaker_open is 2s (vs. the 30s other
        # fixtures use) so the CLOSE-via-probe assertion does not idle the
        # suite for 30+ seconds.
        # cache_turbo_breaker_retry_after is set EXPLICITLY here (not left to
        # track cache_turbo_breaker_open automatically) -- an unset
        # breaker_retry_after inherits the ENCLOSING server block's
        # already-resolved default (30s, from breaker_open's OWN 30s default
        # at that level) rather than being derived from THIS location's
        # breaker_open, so leaving it unset with breaker_open 2s here would
        # read 30 instead of 2 (a pre-existing inheritance gap, reported
        # separately -- not what this fixture is testing). An explicit
        # directive is unaffected by that gap and is what this test verifies.
        location /o45/ {{
            cache_turbo                    o45z;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_keep_stale         off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default
            cache_turbo_stale_mult           1;
            cache_turbo_breaker              on;
            cache_turbo_breaker_threshold    1;
            cache_turbo_breaker_window      60s;
            cache_turbo_breaker_open         2s;
            cache_turbo_breaker_retry_after  2s;
            cache_turbo_lock_timeout         2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location = /_cache_o45 {{
            cache_turbo_admin    o45z;
            allow 127.0.0.1;
            deny all;
        }}

        # O4.5 negative control: identical shape to /o45/ (SAME threshold/
        # window/open, so only the breaker on|off flag itself differs -- a
        # mutation that ignores breaker_enable in breaker_should_consult()
        # would otherwise still be blocked by threshold/window and this
        # control would pass for the wrong reason). With the breaker off a
        # dead origin gets no fallback at all -- the origin hit count keeps
        # climbing (every request reaches it) rather than flatlining behind
        # an OPEN breaker.
        location /o45off/ {{
            cache_turbo                    o45offz;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_keep_stale         off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default
            cache_turbo_stale_mult           1;
            cache_turbo_breaker              off;
            cache_turbo_breaker_threshold    1;
            cache_turbo_breaker_window      60s;
            cache_turbo_breaker_open         2s;
            cache_turbo_lock_timeout         2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # O4.5 / O4.2-f: header-filter recording-block pins (claims 1+2: a
        # 5xx records a failure, a cache-turbo HIT records nothing). Own
        # zone (o45hitz) so origin_failures here is never moved by /o45/'s
        # own trip. threshold=1/window=60s/open=30s -- same shape as the
        # other breaker fixtures; claim 1's drop DOES trip this zone's
        # breaker, which is why it runs after claim 2's HIT check.
        #
        # valid is 30s, NOT the 1s the sibling breaker fixtures use: claim 2
        # puts an _admin_stat round trip between the prime and the HIT fetch,
        # so a 1s window can expire on a loaded or ASan runner and the HIT
        # becomes a re-fetch -- failing on box speed rather than on module
        # behaviour, the same SUITE-4 trap the /ccignmr/ comment records.
        # Neither claim here needs a short TTL: /o45hit/dropme is never primed,
        # and the staleness step runs on /o45hitpos/, a different zone.
        location /o45hit/ {{
            cache_turbo                    o45hitz;
            cache_turbo_key                $uri;
            cache_turbo_valid              30s;
            cache_turbo_keep_stale         off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default
            cache_turbo_breaker              on;
            cache_turbo_breaker_threshold    1;
            cache_turbo_breaker_window      60s;
            cache_turbo_breaker_open        30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location = /_cache_o45hit {{
            cache_turbo_admin    o45hitz;
            allow 127.0.0.1;
            deny all;
        }}

        # O4.5 / O4.2-f: POSITION-claim-only location (see the o45hitposz
        # zone comment above for why this is not on o45hitz). keep_stale
        # forever so the same key's expired entry can be pushed through the
        # SIE rewrite, masking a real origin 502 with a 200/stale body while
        # still needing to have recorded the 502 as a breaker failure.
        location /o45hitpos/ {{
            cache_turbo                    o45hitposz;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_stale_mult          1;
            cache_turbo_keep_stale     forever;
            cache_turbo_breaker              on;
            cache_turbo_breaker_threshold    1;
            cache_turbo_breaker_window      60s;
            cache_turbo_breaker_open        30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location = /_cache_o45hitpos {{
            cache_turbo_admin    o45hitposz;
            allow 127.0.0.1;
            deny all;
        }}

        # O4.2-f: a native proxy_cache HIT must not touch the breaker's
        # recording block at all (ctx is NULL/ctx->served on a HIT --
        # never a cache-turbo location, so the header filter never reaches
        # the record() call). Own proxy_cache zone (ctpo45, not ctpcon --
        # see the proxy_cache_path comment above); no cache_turbo directive
        # here at all, so no ctx and no breaker.
        location /o45natpc/ {{
            proxy_cache          ctpo45;
            proxy_cache_valid    200 5m;
            proxy_cache_key      $uri;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Negative control for /keepstale/: identical location, keep_stale off
        # (explicit -- S231-DEFAULTS made 24h the default, so this is no
        # longer "the default", it is an opt-out) -> an expired entry with a
        # dead origin must surface the error (502), not serve stale. Proves
        # the positive result above is actually caused by keep_stale, not
        # some other widening.
        location /keepstaleoff/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_stale_mult 1;
            cache_turbo_keep_stale off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Precedence test: both a response stale-if-error AND cache_turbo_keep_stale
        # are in play here. keep_stale is a generous 1h baseline; the response's
        # own stale-if-error=5 (via the "sieshort" request-suffix marker -- a
        # short-window sibling of the "sieserve" convention used by /sieserve/)
        # must WIN -- sie_window = ttl + 5, not ttl + 3600 and not max() of the
        # two. Drives test_keep_stale_loses_to_response_sie.
        location /keepstalewins/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_keep_stale 1h;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S3.1: a negative-cached 5xx must never overwrite a still-serveable
        # body (cache_turbo_valid 503 1m legitimately negative-caches errors,
        # but that must not let an error blob clobber a good 200 -- the
        # inverse of outage resilience). Short fresh/stale window (1s / x4=4s,
        # default stale_mult) so the entry goes stale quickly; the 503 negative
        # cache rule is what a "cache negative responses too" config looks
        # like. Drives test_5xx_never_overwrites_cached_body.
        location /noclobber/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    1s;
            cache_turbo_valid    503 1m;
            cache_turbo_background_update off;
            cache_turbo_beta     100000;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUD-5XX-CTA: cache_turbo_bypass skips the LOOKUP *and* single-flight
        # but still permits storing, so it is the one path that can reach the
        # 5xx guard with NO earlier serialization point at all -- exactly the
        # reachability the check-then-act race needed. Negative-cache 503 so a
        # bypassed 5xx is actually eligible to be stored (a non-cacheable
        # status never reaches the guard). Drives test_5xx_cta_bypass_never_
        # overwrites_cached_body.
        location /cta5xx/ {{
            cache_turbo         main;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            cache_turbo_valid   503 1m;
            cache_turbo_bypass  $arg_nocache;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S2.3: no-reaper contract. keep_stale is a generous 1h -- an entry
        # here is way inside its keep-stale window at every point this test
        # checks it, so if the entry ever disappears on its own that proves a
        # time-based reaper exists (contract violation). The zone (ksevz,
        # 64k, the enforced minimum) is what actually reclaims memory: it only
        # holds a couple of these bodies, so flooding it with distinct keys
        # forces genuine LRU eviction and gives the test a second location to
        # observe the SAME key vanish for the CORRECT reason (max_size
        # pressure, not time).
        location /ksev/ {{
            cache_turbo             ksevz;
            cache_turbo_key         $uri;
            cache_turbo_valid       1s;
            cache_turbo_keep_stale  1h;
            add_header X-CT-Status  $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # P1-4: background_update ON (default) with a huge beta so the FIRST
        # stale read deterministically wins the refresh dice. The origin's
        # "vldecho" marker echoes back whatever If-None-Match /
        # If-Modified-Since it received AND stamps a stable ETag/Last-Modified
        # on every response, so a primed entry always has a validator for the
        # next background refresh to inject.
        location /swrval/ {{
            cache_turbo                   main;
            cache_turbo_key               $uri;
            cache_turbo_valid             1s;
            cache_turbo_beta              5000;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # P1-4 safety probe: same shape as /swrval/, but the origin ANSWERS
        # 304 to the injected If-None-Match (the "vld304" marker). Proves the
        # stored entry survives a 304-answered background refresh intact --
        # the case that decides whether injection alone is safe.
        location /swr304/ {{
            cache_turbo                   main;
            cache_turbo_key               $uri;
            cache_turbo_valid             1s;
            cache_turbo_beta              5000;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # P1-4 negative control: same shape as /swrval/ but the origin path
        # never carries "vldecho"/"cond" so the stored entry has NEITHER
        # validator -- the background refresh must stay an unconditional GET,
        # exactly like today.
        location /swrvalnone/ {{
            cache_turbo                   main;
            cache_turbo_key               $uri;
            cache_turbo_valid             1s;
            cache_turbo_beta              5000;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # background_update OFF (v8): the stale dice-winner regenerates INLINE
        # and serves the fresh body on that request (pre-v8 behaviour).
        location /noswr/ {{
            cache_turbo                   main;
            cache_turbo_key               $uri;
            cache_turbo_valid             2s;
            cache_turbo_beta              5000;
            cache_turbo_background_update off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # max_size = 4 bytes: origin body "gen-N\\n" is >4, so never cached
        location /big/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_max_size 4;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Q1 suppress-native: $cache_turbo_active reads 1 when engaged AND
        # cache_turbo_suppress_native is on. Echo it into a header so a test can
        # observe the value an operator would wire into proxy_no_cache.
        location /sup/ {{
            cache_turbo                 main;
            cache_turbo_key             $uri;
            cache_turbo_valid           30s;
            cache_turbo_suppress_native on;
            add_header X-CT-Active      $cache_turbo_active always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # suppress off (default): the variable is always 0, so the wiring is a
        # safe no-op until opted in.
        location /nosup/ {{
            cache_turbo            main;
            cache_turbo_key        $uri;
            cache_turbo_valid      30s;
            add_header X-CT-Active $cache_turbo_active always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # auto-classify: anon pages cache, dynamic surfaces skip. This used to
        # be `cache_turbo main auto;` (the generic union); `auto`/`generic` are
        # gone, so the backends are named explicitly -- which is the point.
        location /auto/ {{
            cache_turbo         main;
            cache_turbo_backend wordpress woocommerce joomla;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # auto-classify + suppress_native: an anon page engages cache-turbo
        # ($cache_turbo_active=1, native defers), but a request the preset
        # classifies as dynamic (login cookie / backend URI) is skipped -> NOT
        # engaged -> $cache_turbo_active=0 so a stacked native cache is free to
        # own that URL. Proves auto-skip forces the variable to 0 even with
        # suppress_native on.
        location /autosup/ {{
            cache_turbo                 main;
            cache_turbo_backend         wordpress;
            cache_turbo_key             $uri;
            cache_turbo_valid           30s;
            cache_turbo_suppress_native on;
            add_header X-CT-Active      $cache_turbo_active always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # auto-classify URI-prefix rule: r->uri starts with /wp-admin/ -> skip
        location /wp-admin/ {{
            cache_turbo         main;
            cache_turbo_backend wordpress;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # cache_turbo_backend woocommerce only: composes just that preset.
        # NOTE the key includes the query string: ?wc-ajax= rides on an ORDINARY
        # page URL, so this location is exactly the "cacheable page that an AJAX
        # call is layered onto" shape the wc-ajax arg rule has to catch.
        #
        # `woocommerce` alone here ALSO implies `wordpress` (resolved at parse):
        # the woo-cookie/arg rules are woo's own; the WP login-cookie skip and the
        # /wp-admin/ URI skip come from the implied wordpress preset. Composition
        # itself is now pinned in ci/t/preset-engine/composition.t; this fixture
        # location remains for test_woocommerce_wc_ajax below.
        location /woo/ {{
            cache_turbo         main;
            cache_turbo_backend woocommerce;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # woo-only location mounted at /wooshop/: proves the IMPLIED wordpress
        # /wp-admin/ URI rule fires without `wordpress` being named. The prefix
        # rebases /wooshop/wp-admin/* onto /wp-admin/* for the preset matcher, so
        # a hit here would be the exact leak (cacheable wp-admin under woo-only).
        location /wooshop/ {{
            cache_turbo         main;
            cache_turbo_backend woocommerce;
            cache_turbo_backend_prefix /wooshop/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # wordpress preset with the QUERY STRING in the key -- needed to tell
        # /wpq/x?s=foo apart from /wpq/x. This is where the ?s= (site search)
        # and ?preview= arg rules are exercised.
        location /wpq/ {{
            cache_turbo         main;
            cache_turbo_backend wordpress;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # two backends stacked: both WP and Woo dynamic surfaces skip
        location /multi/ {{
            cache_turbo         main;
            cache_turbo_backend wordpress woocommerce;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # joomla URI-prefix rule: r->uri starts with /administrator/ -> skip
        location /administrator/ {{
            cache_turbo         main;
            cache_turbo_backend joomla;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # xenforo preset (opt-in; deliberately NOT part of generic/auto).
        # The preset's URI prefixes anchor at position 0 of r->uri, so /login
        # and /misc must be real ROOT locations to be exercised at all: a
        # /xf/login path would (correctly) never match. See docs/xenforo.md.
        location /login {{
            cache_turbo         main;
            cache_turbo_backend xenforo;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /misc {{
            cache_turbo         main;
            cache_turbo_backend xenforo;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # /api/ is the REST API: it authenticates on the XF-Api-Key HEADER, which
        # no cookie rule can see, so the preset bypasses it on the URI. Root
        # location for the same anchor-at-0 reason as /login and /misc above.
        location /api/ {{
            cache_turbo         main;
            cache_turbo_backend xenforo;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # xenforo cookie/arg rules are path-independent, so a prefixed location
        # exercises them: xf_user / xf_session_admin / xf_session bypass and the
        # _xfToken query arg bypasses, while the xf_style_* / xf_language_id
        # variant cookies must KEY (value-folded), not bypass and not collide.
        location /xf/ {{
            cache_turbo         main;
            cache_turbo_backend xenforo;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # smf routes every page through index.php?action=<route>, so its
        # dynamic surface is expressed as query-arg VALUES, not URI prefixes.
        # Arg rules are path-independent, so a prefixed location exercises them.
        location /smf/ {{
            cache_turbo         main;
            cache_turbo_backend smf;
            cache_turbo_key     $request_uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /mybb/ {{
            cache_turbo         main;
            cache_turbo_backend mybb;
            cache_turbo_key     $request_uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # redmine / opencart (2026-07-26 research pass). Both exist to prove a
        # guest-issued session cookie is NOT treated as a login signal -- the
        # trap that makes a preset bypass 100% of traffic and silently
        # disable the cache. The key must include $is_args$args so the
        # opencart arg-tier rows are reachable: with a bare $uri key every
        # ?route= variant collapses onto one entry and the test would pass for
        # the wrong reason.
        location /redmine/ {{
            cache_turbo         main;
            cache_turbo_backend redmine;
            cache_turbo_backend_prefix /redmine/;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # opencart needs no prefix: it ships NO uris[] row at all (everything is
        # /index.php?route=), so the arg tier is what fires and it is
        # path-independent.
        location /opencart/ {{
            cache_turbo         main;
            cache_turbo_backend opencart;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-PERF-AUTOCLASSIFY negative control: the presets below had no
        # dedicated runtime-test location at all before this change, so their
        # cookie needles were exercised only by the fuzz corpus (crash safety)
        # and never asserted classified-dynamic here. Added to prove the
        # first-byte prefilter cannot make a needle unreachable -- see
        # test_cookie_prefilter_negative_control().
        location /ct-drupal/ {{
            cache_turbo         main;
            cache_turbo_backend drupal;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-mediawiki/ {{
            cache_turbo         main;
            cache_turbo_backend mediawiki;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-ghost/ {{
            cache_turbo         main;
            cache_turbo_backend ghost;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-wagtail/ {{
            cache_turbo         main;
            cache_turbo_backend wagtail;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-kirby/ {{
            cache_turbo         main;
            cache_turbo_backend kirby;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-typo3/ {{
            cache_turbo         main;
            cache_turbo_backend typo3;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-vanilla/ {{
            cache_turbo         main;
            cache_turbo_backend vanilla;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-punbb/ {{
            cache_turbo         main;
            cache_turbo_backend punbb;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-phorum/ {{
            cache_turbo         main;
            cache_turbo_backend phorum;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-yabb/ {{
            cache_turbo         main;
            cache_turbo_backend yabb;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-flarum/ {{
            cache_turbo         main;
            cache_turbo_backend flarum;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # A NAMED preset must pull in ONLY its own rules. `wordpress` here must
        # not react to /login, /user, /session, /index.php or another preset's
        # cookies -- those are other backends' surfaces and are perfectly
        # cacheable pages on a WordPress site. (This location used to be
        # `cache_turbo_backend generic;` and proved the same thing about the
        # union; the union is gone, the invariant is not.)
        location /gen/ {{
            cache_turbo         main;
            cache_turbo_backend wordpress;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- magento -------------------------------------------------------
        # URI prefixes anchor at position 0 -> ROOT locations.
        location /checkout {{
            cache_turbo         main;
            cache_turbo_backend magento;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /customer {{
            cache_turbo         main;
            cache_turbo_backend magento;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # Web API front names (app/code/Magento/Webapi/etc/di.xml). Header-
        # authenticated -> invisible to the cookie tier, so they need URI rules.
        # Root locations, or the fetch falls through to nginx's implicit 404 and
        # a "must bypass" assertion passes without the preset ever running.
        location /rest {{
            cache_turbo         main;
            cache_turbo_backend magento;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /soap {{
            cache_turbo         main;
            cache_turbo_backend magento;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # A catalog URL that merely SHARES the letters must still cache: the
        # prefix needs a '/' or '.' boundary after it, so /restaurant-supplies
        # is not /rest.
        location /restaurant-supplies {{
            cache_turbo         main;
            cache_turbo_backend magento;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # Cookie rules are path-independent. The catalog is the surface that MUST
        # stay cacheable -- including for guests carrying PHPSESSID / form_key /
        # private_content_version, every one of which Magento sets for anons.
        location /mg/ {{
            cache_turbo         main;
            cache_turbo_backend magento;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}


        # ---- require_header (explicit upstream store opt-in) ----------------
        # The gate INVERTS the store default here: nothing is captured unless the
        # origin affirms it. X-CT-Status is mandatory to test this at all -- every
        # refusal case (header absent / "no" / duplicated / empty) produces a
        # plain MISS, and a MISS has no x-cache, so "x-cache not in headers"
        # cannot tell a working gate from a gate that never runs.
        location /gql/ {{
            cache_turbo              main;
            cache_turbo_key          $uri;
            cache_turbo_valid        30s;
            cache_turbo_require_header X-GraphQL-Cacheable;
            add_header               X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # Same origin, NO gate: proves the refusals above come from the directive
        # and not from something else in the response (an unset gate must leave
        # the module's normal "cacheable unless vetoed" path untouched).
        location /nogql/ {{
            cache_turbo         main;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            add_header          X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # `none` overrides an inherited preset. The server-level directive below
        # arms wordpress for every location that does not say otherwise; this one
        # says otherwise, so /wp-admin/-style rules must NOT fire here.
        location /nonepreset/ {{
            cache_turbo         main;
            cache_turbo_backend none;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- discourse (ported to ci/t/preset-engine/arg-scanner.t and
        # ci/t/presets/discourse.t; kept here only as long as another Python
        # test in this file still references /dc/)
        # Cookie/arg rules are path-independent, so a prefixed location is fine:
        # _t bypasses, but the guest _forum_session and the theme_ids /
        # forced_color_mode variant cookies must NOT.
        location /dc/ {{
            cache_turbo         main;
            cache_turbo_backend discourse;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- phpbb --------------------------------------------------------
        # Every visitor gets phpBB's cookies; the preset therefore uses the
        # `_u != 1` value predicate rather than a name-presence rule.
        location /ucp.php {{
            cache_turbo         main;
            cache_turbo_backend phpbb;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /phpbb/ {{
            cache_turbo         main;
            cache_turbo_backend phpbb;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- vbulletin ----------------------------------------------------
        # The only preset wired to the NONEMPTY and EQ predicate ops (userid /
        # password non-empty, imloggedin == "yes"), and the only one whose key
        # cookie list is exercised here. $uri key so a key-cookie split is
        # attributable to the cookie and not to the path.
        location /vbull/ {{
            cache_turbo         main;
            cache_turbo_backend vbulletin;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- 2026 preset expansion --------------------------------------
        # Each app is mounted below a unique prefix. backend_prefix rebases
        # the preset's root-relative URI rules, so the same location exercises
        # cookie, query-arg and URI tiers without colliding with older tests'
        # /admin, /login and other root locations.
        location /ct-textpattern/ {{
            cache_turbo         main;
            cache_turbo_backend textpattern;
            cache_turbo_backend_prefix /ct-textpattern/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-bludit/ {{
            cache_turbo         main;
            cache_turbo_backend bludit;
            cache_turbo_backend_prefix /ct-bludit/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-spip/ {{
            cache_turbo         main;
            cache_turbo_backend spip;
            cache_turbo_backend_prefix /ct-spip/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-PERF-AUTOCLASSIFY (args half) negative control: ghost/mediawiki/
        # yabb have non-empty args[] rows but no dedicated arg-classification
        # location elsewhere in this config. $uri$is_args$args in the key so
        # distinct query strings do not collapse onto one cache entry.
        location /ct-ghost-args/ {{
            cache_turbo         main;
            cache_turbo_backend ghost;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-mediawiki-args/ {{
            cache_turbo         main;
            cache_turbo_backend mediawiki;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-yabb-args/ {{
            cache_turbo         main;
            cache_turbo_backend yabb;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-bugzilla/ {{
            cache_turbo         main;
            cache_turbo_backend bugzilla;
            cache_turbo_backend_prefix /ct-bugzilla/;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-mantis/ {{
            cache_turbo         main;
            cache_turbo_backend mantis;
            cache_turbo_backend_prefix /ct-mantis/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-plone/ {{
            cache_turbo         main;
            cache_turbo_backend plone;
            cache_turbo_backend_prefix /ct-plone/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-umbraco/ {{
            cache_turbo         main;
            cache_turbo_backend umbraco;
            cache_turbo_backend_prefix /ct-umbraco/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-dotclear/ {{
            cache_turbo         main;
            cache_turbo_backend dotclear;
            cache_turbo_backend_prefix /ct-dotclear/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-wikijs/ {{
            cache_turbo         main;
            cache_turbo_backend wikijs;
            cache_turbo_backend_prefix /ct-wikijs/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-classicpress/ {{
            cache_turbo         main;
            cache_turbo_backend classicpress;
            cache_turbo_backend_prefix /ct-classicpress/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ct-backdrop/ {{
            cache_turbo         main;
            cache_turbo_backend backdrop;
            cache_turbo_backend_prefix /ct-backdrop/;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- invision -----------------------------------------------------
        # Cookie/arg rules are path-independent, so a prefixed location
        # exercises them. $uri key for the same attribution reason as /vbull/.
        location /ips/ {{
            cache_turbo         main;
            cache_turbo_backend invision;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- header-auth REST surfaces (drupal /jsonapi, /oauth) -----------
        # Used by test_header_auth_rest_surfaces() -- both surfaces are
        # header-authenticated (bearer token) and structurally invisible to
        # the cookie tier; only the URI rule catches them. See
        # ci/t/presets/drupal.t for the drupal preset's own cookie/URI tests.
        location /jsonapi {{
            cache_turbo         main;
            cache_turbo_backend drupal;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /oauth {{
            cache_turbo         main;
            cache_turbo_backend drupal;
            cache_turbo_key     $uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- internal-redirect regression (DOC-A1 / DOC-A2) ---------------
        # A PHP front controller: try_files sends every clean URL to
        # /ctir/index.php. After that internal redirect nginx has REPLACED
        # r->uri with /ctir/index.php, so both the default $uri-based key and
        # the preset URI rules see the front controller, never the original
        # route. /ctir/ reproduces the shape the published docs used to show.
        location /ctir/ {{
            try_files $uri /ctir/index.php;
        }}
        location = /ctir/index.php {{
            cache_turbo         main;
            cache_turbo_backend xenforo;
            cache_turbo_key     $host$uri$cache_turbo_normalized_args;
            cache_turbo_valid   30s;
            add_header          X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # AUD-DOC1. Third copy of the same front controller, guarded ONLY by
        # cache_turbo_bypass_uri. The directive matches r->uri, which the
        # internal redirect has already rewritten to the front controller, so
        # the prefix never matches and the private route is cached like any
        # other. Pinning it here keeps the documented blind spot honest.
        location /ctir-bu/ {{
            try_files $uri /ctir-bu/index.php;
        }}
        location = /ctir-bu/index.php {{
            cache_turbo            main;
            cache_turbo_key        $host$request_uri;
            cache_turbo_bypass_uri /ctir-bu/api/;
            cache_turbo_valid      30s;
            add_header             X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Same front controller, keyed the way the fixed docs now prescribe:
        # $request_uri survives the internal redirect, so distinct clean URLs
        # stay distinct and the map-driven private-route veto still fires.
        location /ctir-fixed/ {{
            try_files $uri /ctir-fixed/index.php;
        }}
        location = /ctir-fixed/index.php {{
            cache_turbo           main;
            cache_turbo_backend   xenforo;
            cache_turbo_key       $host$request_uri;
            cache_turbo_bypass    $ctir_private_route;
            cache_turbo_no_store  $ctir_private_route;
            cache_turbo_valid     30s;
            add_header            X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # ---- CTXRDR: error_page internal redirect AFTER ctx exists --------
        # The /ctir* fixtures above redirect via try_files, which runs in the
        # REWRITE phase -- before the PRECONTENT access handler, so the module
        # only ever sees the post-redirect URI and ctx is built once. This pair
        # covers the other order: cache-turbo is enabled on BOTH the route that
        # 404s and the error_page target, so the access handler builds a ctx,
        # the origin 404s, error_page fires ngx_http_internal_redirect(), and
        # r->ctx is memzeroed mid-request while the first ctx's pool cleanups
        # (cold-winner unstub, blob release) and its embedded cold_wait_ev timer
        # remain registered on the still-live r->pool.
        #
        # Both locations emit the status/reason variables so the SECOND pass's
        # ctx is observable: the variable getters read r->ctx directly, so a
        # module that cached a ctx pointer across the redirect -- or that failed
        # to rebuild one -- shows up here rather than as a silent corruption.
        location /ctxrdr/ {{
            cache_turbo           main;
            cache_turbo_key       $host$request_uri;
            cache_turbo_valid     30s;
            error_page            404 = /ctxrdr-fallback/page;
            # Required: without it nginx passes the origin's 404 straight to the
            # client and error_page never fires, so the redirect under test
            # never happens at all.
            proxy_intercept_errors on;
            add_header            X-CT-Status $cache_turbo_status always;
            add_header            X-CT-Reason $cache_turbo_serve_reason always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ctxrdr-fallback/ {{
            cache_turbo           main;
            cache_turbo_key       $host$request_uri;
            cache_turbo_valid     30s;
            add_header            X-CT-Status $cache_turbo_status always;
            add_header            X-CT-Reason $cache_turbo_serve_reason always;
            # NOTE: the upstream path carries a marker UNIQUE to the fallback
            # leg. (Config is written encoding="ascii" -- keep this block
            # ASCII-only; a non-ASCII char here fails the whole suite at
            # config-write time, before a single test runs.)
            # Both ctxrdr locations strip their own prefix, so a bare
            # `proxy_pass .../` made the fallback fetch plain `/page` -- and
            # hits_for("ctxrdr-missing") then counted only the FIRST pass's 404,
            # never the fallback's origin contact. The "exactly one origin
            # contact" assertion was true for the wrong reason and would have
            # stayed 1 however many times the fallback hit the origin. Keep this
            # marker distinct from every other fixture's path.
            proxy_pass http://127.0.0.1:{origin_port}/ctxrdr-fb-;
        }}
        # Negative control for the CTXRDR test: same variables, but cache_turbo
        # is NOT enabled, so no ctx is ever created. Both variables must report
        # "-" here. Without this arm the CTXRDR assertions would pass equally
        # well against getters that answered from anything but r->ctx.
        location /ctxrdr-off/ {{
            add_header            X-CT-Status $cache_turbo_status always;
            add_header            X-CT-Reason $cache_turbo_serve_reason always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Q2 multi-buffer oversize: ~200 KB body, 1k cap -> mid-stream abort
        location /qbig/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            cache_turbo_max_size 1k;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Q1: a location WITHOUT cache_turbo -> $cache_turbo_active must be "0"
        # (no ctx / disabled), proving the variable's defensive default.
        location /plain/ {{
            add_header X-CT-Active $cache_turbo_active always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Q1 E2E: cache_turbo_suppress_native on + the documented wiring ->
        # proxy_cache (ctpcon) must stay empty (cache-turbo owns caching).
        location /supcache/ {{
            cache_turbo                 main;
            cache_turbo_suppress_native on;
            cache_turbo_key             $uri;
            cache_turbo_valid           30s;
            proxy_cache                 ctpcon;
            proxy_cache_valid           200 5m;
            proxy_cache_key             $uri;
            proxy_no_cache              $cache_turbo_active;
            proxy_cache_bypass          $cache_turbo_active;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Q1 E2E control: suppress OFF -> $cache_turbo_active=0 -> the SAME
        # wiring is inert and proxy_cache (ctpcoff) stores normally.
        location /nosupcache/ {{
            cache_turbo                 main;
            cache_turbo_key             $uri;
            cache_turbo_valid           30s;
            proxy_cache                 ctpcoff;
            proxy_cache_valid           200 5m;
            proxy_cache_key             $uri;
            proxy_no_cache              $cache_turbo_active;
            proxy_cache_bypass          $cache_turbo_active;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # tiny zone to force LRU eviction (R6)
        location /e/ {{
            cache_turbo          tiny;
            cache_turbo_key      $uri;
            cache_turbo_valid    30s;
            add_header           X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-EVICT-BLIND: private tiny zone (evblindz, 64k) + own breaker
        # (threshold=1, same trip shape as /s71brk/). proxy_pass is the bare
        # origin root (not /sieserve/) so callers choose per-key whether the
        # upstream response carries a stale-if-error window: /evblind/sieserve/*
        # gets one (fresh=1s + stale-if-error=30 -> sie_ttl=31s from creation,
        # SIE-live for the whole test), /evblind/_trip_plain does not, which is
        # what lets the trip fetch surface the origin's raw failure instead of
        # a 200 STALE-IF-ERROR replay. Drives test_evict_blind_second_chance:
        # fills the zone while the breaker is OPEN (must still store, never
        # ENOMEM/store failure) and pins that a live-SIE entry survives
        # exactly one eviction pass, not every pass.
        location /evblind/ {{
            cache_turbo                     evblindz;
            cache_turbo_key                 $uri;
            cache_turbo_valid               1s;
            cache_turbo_keep_stale          off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default, same as /s71brk/
            cache_turbo_stale_mult          1;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window      10s;
            cache_turbo_breaker_open        30s;
            add_header                      X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location = /_cache_evblind {{
            cache_turbo_admin    evblindz;
            allow 127.0.0.1;
            deny all;
        }}

        # S231-PERF-MISSLOCKS: min_uses > 1 AND cache_turbo_lock on (the
        # default) TOGETHER -- the exact combination the merged resolve_miss()
        # path covers. lock_ttl left short so a losing waiter does not have to
        # wait long, and lock_timeout is generous so a slow CI runner cannot
        # make a genuine waiter give up and stampede the origin, which would
        # look like a correctness failure but would only be scheduling noise.
        location /mmulock/ {{
            cache_turbo               mmulockz;
            cache_turbo_key           $uri;
            cache_turbo_valid         30s;
            cache_turbo_min_uses      3;
            cache_turbo_lock          on;
            cache_turbo_lock_ttl      2s;
            cache_turbo_lock_timeout  5s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location = /_cache_mmulock {{
            cache_turbo_admin    mmulockz;
            allow 127.0.0.1;
            deny all;
        }}

        # S8: scan-resistant segmented LRU, ON. Own tiny zone so the scan below
        # cannot be perturbed by other tests sharing /e/.
        location /sr/ {{
            cache_turbo               srz;
            cache_turbo_key           $uri;
            cache_turbo_valid         300s;
            {sr_directive}
            add_header                X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S8/P3-1: the SAME shape with the directive ABSENT -- the
        # default-on control (P3-1 flipped the compiled-in default from off
        # to on). Any behavioural difference between /sr/ and /sroff/ would
        # be attributable to the directive; since P3-1 there should be NONE,
        # because absent now means the same effective config as `on`.
        location /sroff/ {{
            cache_turbo          sroffz;
            cache_turbo_key      $uri;
            cache_turbo_valid    300s;
            add_header           X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S8/P3-1: explicit `off` must restore the pre-P3-1 flat LRU -- the
        # migration path for a deployment that relies on the old default.
        # Separate zone again so it is independently measurable.
        location /srexpoff/ {{
            cache_turbo               srexpz;
            cache_turbo_key           $uri;
            cache_turbo_valid         300s;
            cache_turbo_scan_resistant off;
            add_header                X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # R6b: refresh-under-pressure. A tiny zone (so eviction churns) with a
        # short fresh window + aggressive beta + background_update, so a working
        # set larger than the zone is CONTINUOUSLY going stale and refreshing
        # (SWR store back into shm) at the same time other entries are being
        # evicted to make room. This overlaps the shm slab alloc/free/evict path
        # with the refresh-store path under concurrency -- the combination the
        # eviction-only (/e/, valid 30s never stale) and serve-under-eviction
        # (PERF-7) tests do not exercise. The value is under the sanitizer CI run
        # (asan job runs the full suite): a shm UAF / double-free / overflow in
        # store-under-eviction surfaces there. beta 5000 = refresh fires early in
        # the stale window; valid 1s keeps entries turning over fast.
        location /shmref/ {{
            cache_turbo               shmref;
            cache_turbo_key           $uri;
            cache_turbo_valid         2s;     # stale window opens at t+2s
            cache_turbo_beta          5000;   # aggressive: refresh fires early in stale
            cache_turbo_background_update on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # key normalize (v3-1): key is built from $cache_turbo_normalized_args
        # so reordered / tracking-laden query strings collapse to one slot
        location /n/ {{
            cache_turbo          main;
            cache_turbo_key      $uri$cache_turbo_normalized_args;
            cache_turbo_valid    30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # extra denylist patterns: exact "sid" + prefix "tmp_*", on top of the
        # built-in defaults (utm_*, fbclid, ...)
        location /ns/ {{
            cache_turbo          main;
            cache_turbo_key      $uri$cache_turbo_normalized_args;
            cache_turbo_valid    30s;
            cache_turbo_normalize_strip sid "tmp_*";
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # strip "*": every arg dropped, so all query strings share one slot
        location /na/ {{
            cache_turbo          main;
            cache_turbo_key      $uri$cache_turbo_normalized_args;
            cache_turbo_valid    30s;
            cache_turbo_normalize_strip "*";
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Vary-aware suffix (v3-4): a request that differs only by Accept-Encoding
        # class (br/gzip/identity) gets its own cache slot.
        location /ve/ {{
            cache_turbo          main;
            cache_turbo_key      $uri$cache_turbo_normalized_args;
            cache_turbo_valid    30s;
            cache_turbo_normalize_vary encoding;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # device class (mobile/desktop from User-Agent) gets its own slot
        location /vd/ {{
            cache_turbo          main;
            cache_turbo_key      $uri$cache_turbo_normalized_args;
            cache_turbo_valid    30s;
            cache_turbo_normalize_vary device;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # both buckets compose: encoding x device = distinct slots
        location /vb/ {{
            cache_turbo          main;
            cache_turbo_key      $uri$cache_turbo_normalized_args;
            cache_turbo_valid    30s;
            cache_turbo_normalize_vary encoding device;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # auto-Vary (v11 other half): the module reads the response Vary header
        # itself and splits on the named request header (safe whitelist only).
        # cache_turbo_key includes the query so each test's marker isolates.
        location /av/ {{
            cache_turbo          main;
            cache_turbo_key      $request_uri;
            cache_turbo_valid    30s;
            cache_turbo_auto_vary on;
            # X-CT-Status is the canary the primary-subtag share test asserts
            # on: "b1 == b2" alone is equally satisfied by two independent
            # origin misses that happen to return byte-identical bodies, so
            # the HIT status is what distinguishes a real shared slot.
            add_header           X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # cache_turbo_key_encoded_origin (P3-2): an origin that ALWAYS sends a
        # non-identity Content-Encoding (no Vary: Accept-Encoding at all --
        # the /precompressed marker) is otherwise 100% uncacheable, silently
        # (see /av/'s test_auto_vary_encoding_precompressed_still_never_cached,
        # which pins that OLD default-off behaviour and must stay green). ON
        # here, so this location stores the origin's own pre-compressed bytes
        # keyed by ae-class instead of refusing outright.
        location /avenc/ {{
            cache_turbo          main;
            cache_turbo_key      $request_uri;
            cache_turbo_valid    30s;
            cache_turbo_auto_vary on;
            cache_turbo_key_encoded_origin on;
            add_header            X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # cache_turbo_serve_authorized (P3-4): the LOOKUP-side Authorization
        # refusal is lifted here, so a credentialed request may READ an
        # anonymously-stored entry. The STORE floor is untouched and ungated,
        # so nothing stored here was ever written by a credentialed request.
        # Serving is additionally gated on the stored response carrying an
        # RFC 9111 SS3.5 reuse authorisation (public / s-maxage /
        # must-revalidate), enforced at the serve chokepoint via
        # BLOBF_AUTH_SHAREABLE.
        #
        # /c/ and /cc/ deliberately do NOT set this -- test_no_cache_
        # authorization and test_refuse_authorization_counter pin the
        # DEFAULT-OFF behaviour there and must stay meaningful.
        location /sauth/ {{
            cache_turbo          main;
            cache_turbo_key      $request_uri;
            cache_turbo_valid    30s;
            cache_turbo_serve_authorized on;
            add_header            X-CT-Status $cache_turbo_status always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # cache_turbo_vary_ignore (P3-3): Accept is dropped from the response
        # Vary header BEFORE the whitelist/unknown-axis check, so a response
        # varying only on Accept (a very common API/image-CDN axis the
        # built-in whitelist has no bit for) stays cacheable instead of being
        # permanently refused like /av/ would refuse it.
        location /avi/ {{
            cache_turbo          main;
            cache_turbo_key      $request_uri;
            cache_turbo_valid    30s;
            cache_turbo_auto_vary on;
            cache_turbo_vary_ignore Accept;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # auto-Vary with a SHORT fresh TTL so the variant (and its L1 vary marker)
        # go stale fast: a request after the fresh deadline but inside the stale
        # window must still resolve to the variant via the now-stale marker
        # (codex follow-up) and serve it stale, instead of falling back to the
        # base key and missing to origin.
        location /avs/ {{
            cache_turbo          main;
            cache_turbo_key      $request_uri;
            cache_turbo_valid    2s;
            cache_turbo_auto_vary on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # cache_turbo_valid 0 == "cache forever" (resolved to a long finite TTL):
        # the entry stays FRESH (a HIT, not instantly STALE) and survives the L2
        # round-trip, reconciling the documented "forever" contract.
        location /forever/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_valid    0;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # Raw-key migration (was cache_turbo_safe_key): an explicit
        # $scheme$host$request_uri key keeps the full raw query (no strip/sort),
        # so two distinct sessionid values get distinct entries instead of
        # aliasing onto one normalized key.
        location /safekey/ {{
            cache_turbo          main;
            cache_turbo_key      $scheme$host$request_uri;
            cache_turbo_valid    30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # COR-5 (L1-only): auto-Vary + PURGE with NO L2 backend. A PURGE of the
        # base URI must invalidate EVERY variant; with no enumerable L2 index the
        # module bumps the marker generation so old-generation variants are
        # orphaned and the next request for each axis value misses to origin.
        location /cor5l1/ {{
            cache_turbo          main;
            cache_turbo_key      $request_uri;
            cache_turbo_valid    30s;
            cache_turbo_auto_vary on;
            cache_turbo_purge    on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # auto-Vary explicitly OFF (S231-VARY: no longer the shipped default --
        # see /avdefault/ below for that): the same response Vary header is
        # ignored, so two encodings collapse onto one slot (back-compat proof
        # for an operator who opts back out).
        location /avoff/ {{
            cache_turbo          main;
            cache_turbo_key      $request_uri;
            cache_turbo_valid    30s;
            cache_turbo_auto_vary off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # S231-VARY: NO cache_turbo_auto_vary directive at all -- this is the
        # only location that proves the *compiled-in* default rather than an
        # explicit `on;` (every /av/ location above opts in explicitly). Must
        # behave exactly like /av/: safe axes split, Vary: Cookie is refused.
        location /avdefault/ {{
            cache_turbo          main;
            cache_turbo_key      $request_uri;
            cache_turbo_valid    30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # presets (v3-2): one location per preset. Each overrides cache_turbo_valid
        # to 1s so the test runs fast; the only behavioural difference left is the
        # preset-supplied stale multiplier (conservative x2 -> serveable 2s,
        # balanced x4 -> 4s, aggressive x8 -> 8s). The explicit valid also proves
        # an explicit knob beats the preset's band value.
        location /pc/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_preset   conservative;
            cache_turbo_valid    1s;     # stale_mult=2 -> expires at 2s
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /pb/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_preset   balanced;
            cache_turbo_valid    1s;     # stale_mult=4 -> expires at 4s
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # H5: the aggressive band is stale_mult=8, but an explicit directive
        # must beat it -> 1 = no stale window at all, hard-expires at 1s.
        location /psm/ {{
            cache_turbo             main;
            cache_turbo_key         $uri;
            cache_turbo_preset      aggressive;
            cache_turbo_valid       1s;
            cache_turbo_stale_mult  1;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /pa/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_preset   aggressive;
            cache_turbo_valid    1s;     # stale_mult=8 -> expires at 8s
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # H3c band-column fixtures. Deliberately NOT reusing /pa/ and /pb/: those
        # carry `cache_turbo_valid 1s` for the stale_mult tests, and the min_uses
        # tests need several sequential requests to stay inside the fresh window.
        # 30s TTL keeps the gate the only variable.
        #
        # /pab/: aggressive band, NO directive -> band min_uses=2 is the only
        # thing that can arm the gate, so req1 skips and req2 stores.
        location /pab/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_preset   aggressive;
            cache_turbo_valid    30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # /pbb/: balanced (the DEFAULT band) -> min_uses=1, stores on req1.
        location /pbb/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_preset   balanced;
            cache_turbo_valid    30s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # /pmu/: aggressive band (min_uses=2) + an explicit directive -> 1 wins,
        # so req2 is already a HIT.
        location /pmu/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_preset   aggressive;
            cache_turbo_valid    30s;
            cache_turbo_min_uses 1;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        # micro preset: NO explicit cache_turbo_valid, so the band's own 1s fresh
        # TTL (stale_mult=2 -> serveable 2s) is what drives expiry. Distinguishes
        # micro (default valid 1s) from every other preset (default valid >= 30s).
        location /pm/ {{
            cache_turbo          main;
            cache_turbo_key      $uri;
            cache_turbo_preset   micro;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # live autotune (v4-3). /at/ + /atc/ share zone "at": a window of slow
        # misses drives the zone's beta verdict up; /at/ is balanced (band
        # [500,2000]) so it shows the verdict, /atc/ is conservative (band
        # [500,1000]) so it shows the SAME verdict re-clamped -- proving the
        # per-location band clamp. X-CT-Beta exposes the effective beta. /ato/ has
        # autotune OFF so it always shows the static preset beta regardless of the
        # zone verdict (off-by-default). The recompute cadence is a fixed 30s;
        # the tests force a recompute via the admin ?autotune=1 endpoint.
        location /at/ {{
            cache_turbo          at;
            cache_turbo_key      $uri;
            cache_turbo_autotune on;
            cache_turbo_background_update off;   # autotune test: inline regen (see /atch/)
            add_header           X-CT-Beta $cache_turbo_beta always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /atc/ {{
            cache_turbo          at;
            cache_turbo_key      $uri;
            cache_turbo_preset   conservative;
            cache_turbo_autotune on;
            cache_turbo_background_update off;   # autotune test: inline regen (see /atch/)
            add_header           X-CT-Beta $cache_turbo_beta always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location /ato/ {{
            cache_turbo          at;
            cache_turbo_key      $uri;
            cache_turbo_preset   balanced;
            add_header           X-CT-Beta $cache_turbo_beta always;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # v4-4 load-adaptive stale widen. conservative (stale_mult 2) + valid 1s =
        # static serveable window 2s. A slow-miss window pumps the zone load factor
        # to the cap (4x); the probe entry, hard-expired by its STATIC 2s window, is
        # still STALE-serveable at t=3s because the load factor widened the
        # serveable stale span. bg-update ON (default) so losers serve stale.
        location /atl/ {{
            cache_turbo          atl;
            cache_turbo_key      $uri;
            cache_turbo_preset   conservative;
            cache_turbo_valid    1s;
            cache_turbo_autotune on;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # autotune insufficient-data: a fresh zone with < MISSES_FLOOR traffic in
        # the window must NOT publish a verdict (autotuned_beta stays 0).
        location /ati/ {{
            cache_turbo          ati;
            cache_turbo_key      $uri;
            cache_turbo_autotune on;
            cache_turbo_background_update off;   # autotune test: inline regen (see /atch/)
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # autotune churn-disqualify: short TTL + short lock + aggressive beta so a
        # stale read reliably refreshes; the test drives refreshes >> misses so the
        # churn gate (refreshes/misses > 2) vetoes the otherwise-qualifying verdict.
        location /atch/ {{
            cache_turbo          atch;
            cache_turbo_key      $uri;
            cache_turbo_preset   aggressive;  # stale_mult 8 -> entry lives 8s, so a
                                              # skipped refresh cycle never expires
                                              # to a MISS (keeps churn ratio stable)
            cache_turbo_min_uses 1;           # H3c: the aggressive band is 2, but
                                              # this test measures the refresh/miss
                                              # churn ratio over 110 cold keys --
                                              # gating each key's first store would
                                              # double the miss count and change the
                                              # very ratio under test. Pin the
                                              # pre-H3c behaviour explicitly.
            cache_turbo_valid    1s;
            cache_turbo_beta     5000;        # static dice beta: refresh is certain
            cache_turbo_lock_ttl 1s;
            cache_turbo_autotune on;
            # bg-update OFF: this test drives a *flood* of stale re-reads (110 keys
            # x 4 cycles) purely to exercise the autotune churn gate; with SWR on
            # each would fire an async background-refresh subrequest, swamping a
            # single-process worker and leaking late origin hits into later tests'
            # exact-count assertions. Inline regen records cost/refreshes identically
            # for autotune, so this changes nothing the test measures.
            cache_turbo_background_update off;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        location = /_cache_at {{
            cache_turbo_admin at;
            allow 127.0.0.1;
            deny all;
        }}
        location = /_cache_atl {{
            cache_turbo_admin atl;
            allow 127.0.0.1;
            deny all;
        }}
        location = /_cache_ati {{
            cache_turbo_admin ati;
            allow 127.0.0.1;
            deny all;
        }}
        location = /_cache_atch {{
            cache_turbo_admin atch;
            allow 127.0.0.1;
            deny all;
        }}
        location = /_cache_shmref {{
            cache_turbo_admin shmref;
            allow 127.0.0.1;
            deny all;
        }}

        # H7.3a: Prometheus breaker_opens_total/breaker_state coverage. Own
        # zone (h73z, not s71z -- see the zone declaration comment) and own
        # admin endpoint for the same reason /_cache_s71 exists: /_cache
        # reports `main`, which never sees this zone's breaker_opens.
        location /h73brk/ {{
            cache_turbo                    h73z;
            cache_turbo_key                $uri;
            cache_turbo_valid               1s;
            cache_turbo_keep_stale         off;  # S231-DEFAULTS: isolate dead-origin arming from the 24h keep_stale default
            cache_turbo_stale_mult          1;
            cache_turbo_breaker             on;
            cache_turbo_breaker_threshold   1;
            cache_turbo_breaker_window     60s;
            cache_turbo_breaker_open       30s;
            cache_turbo_lock_timeout        2s;
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}
        location = /_cache_h73 {{
            cache_turbo_admin    h73z;
            allow 127.0.0.1;
            deny all;
        }}

        # uncached passthrough, lets us read the raw origin
        location /raw/ {{
            proxy_pass http://127.0.0.1:{origin_port}/;
        }}

        # admin endpoint for the "main" zone, localhost-only
        location = /_cache {{
            cache_turbo_admin main;
            allow 127.0.0.1;
            deny all;
        }}
        # same endpoint but reachable only from a (non-loopback) address we
        # can't be, to prove the deny path returns 403
        location = /_cache_denied {{
            cache_turbo_admin main;
            deny all;
        }}
    }}
}}
"""
