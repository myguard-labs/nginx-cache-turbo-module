#!/usr/bin/env python3
"""cache-turbo runtime suite — façade.

MAINT-T1 split the 19k-line suite into per-area modules under ci/tools/areas/.
This module stays the entry point and the importable name every tool already
uses:

* ``run_all()`` below remains the single reachability root walked by
  ci/tools/lint-orphan-tests.py, and it keeps BARE-NAME calls -- the lint only
  collects ``ast.Call`` whose func is an ``ast.Name``, so ``mod.test_foo(ng)``
  would be invisible to it.
* Every test stays reachable as ``test_runtime.<name>`` for
  ci/tools/run_named.py, which does ``getattr(T, name)``.

Both properties come from the star-imports below; keep them.
"""

from __future__ import annotations

from areas.admin import *
from areas.breaker import *
from areas.core import *
from areas.http import *
from areas.l2 import *
from areas.policy import *
from areas.tune import *

# Underscore-prefixed names are NOT re-exported by `import *`, so the
# private helpers this module actually calls are imported explicitly.
from test_runtime_base import *
from test_runtime_base import (
    MemcachedServer,
    Nginx,
    Origin,
    RedisServer,
    _check_port_registry,
    _instrument,
    _start_tls_fixtures,
)


def run_all(ng: Nginx, origin: Origin,
            redis: RedisServer | None = None,
            redis_auth: RedisServer | None = None,
            redis_tls: RedisServer | None = None,
            mc: MemcachedServer | None = None,
            redis_tls_untrusted: RedisServer | None = None,
            redis_tls_expired: RedisServer | None = None) -> None:
    test_sanitizer_time_scale()  # FLAKE-ASAN-TIMING-BAND: pure, no fixtures
    test_miss_then_hit(ng)
    test_surrogate_key_emit_on_miss_and_hit(ng)
    if redis is not None:
        # /skoff/ carries a cache_turbo_redis (its tag needs the L2 consumer to
        # keep the COR-0 warning quiet), so it only exists in a Redis run.
        test_surrogate_key_off_by_default(ng)
    test_surrogate_key_origin_header_survives_hit(ng)
    test_surrogate_key_empty_tag_no_header(ng)
    test_surrogate_key_dedup_from_arg(ng)
    test_post_passthrough_uncached(ng, origin)
    test_compressed_edge_identity_capture(ng)
    test_header_fidelity(ng)
    test_downstream_charset_conversion_repeats_on_hit(ng)
    if ng.fault_injection:
        test_restore_allocation_failure_fails_closed(ng, origin)
        test_file_backed_delegate_never_stores(ng, origin)
        test_store_failure_cleans_up_cold_stub(ng, origin)
    test_max_size_not_cached(ng)
    test_suppress_native_variable(ng)
    test_auto_classify(ng, origin)
    test_auto_classify_suppress_native_interaction(ng, origin)
    test_woocommerce_wc_ajax(ng, origin)
    test_header_auth_rest_surfaces(ng, origin)
    test_phpbb_preset(ng, origin)
    test_redmine_key_arg_bypasses_without_cookie(ng, origin)
    test_redmine_public_content_stays_cacheable(ng, origin)
    test_cookie_pred_multiple_matching_cookies(ng, origin)
    test_cookie_prefilter_negative_control(ng, origin)  # S231-PERF-AUTOCLASSIFY
    test_cookie_prefilter_counter_oracle(ng, origin)     # S231-PERF-AUTOCLASSIFY
    test_2026_preset_expansion(ng, origin)
    test_internal_redirect_key_and_veto(ng, origin)
    test_auto_classify_more(ng, origin)
    test_arg_prefilter_negative_control(ng, origin)
    test_arg_prefilter_mangling_regression(ng, origin)
    test_arg_prefilter_counter_oracle(ng, origin)
    test_arg_span_overflow_boundary(ng, origin)  # AUD4-PERF-ARG64
    test_q2_multibuffer_oversize(ng, origin)
    test_suppress_native_inert_on_plain_location(ng)
    test_suppress_native_e2e_proxy_cache(ng)
    test_invalid_backend_name(ng)
    test_invalid_cache_turbo_mode(ng)
    test_auto_and_generic_are_removed(ng)
    test_breaker_directives_accepted(ng)                     # O4.4
    test_breaker_policy_divergence_warns(ng)                 # O4.4-d
    test_breaker_policy_identical_no_warning(ng)              # O4.4-d
    test_breaker_open_zero_rejected(ng)                      # O4.4 / O4.3-a
    test_breaker_arming_gated_on_breaker_enable(ng, origin)  # O4.4
    test_breaker_shipped_default_trips_and_serves_stale(ng, origin)  # S231-DEFAULTS
    test_breaker_counters(ng, origin)                        # S7.1 breaker_serves/origin_failures
    test_breaker_retry_after_auto_tracks_breaker_open(ng, origin)  # BRK-RA1
    test_prometheus_breaker_metrics(ng, origin)               # H7.3a breaker_opens_total/breaker_state on prometheus
    test_double_partition_encoding_warns(ng)                  # P1-7
    test_double_partition_device_warns(ng)                    # P1-7
    test_double_partition_both_warns(ng)                      # P1-7
    test_p4_5_chained_serve_bytes_identical(ng, origin)       # P4-5 multi-buf zero-copy serve
    test_p4_5_chained_serve_terminates_on_keepalive(ng, origin)  # P4-5 last_buf termination
    test_p4_5_chained_serve_head_and_empty_body(ng, origin)   # P4-5 non-chained arms
    test_p4_5_chained_serve_slow_client_drain(ng, origin)     # P4-5 blob refcount across a slow drain
    test_breaker_arming_sites_gated_white_box(ng, origin)    # O4.4-i (L1)
    test_bypass_stale_serves_fallback_when_breaker_open(ng, origin)  # S232-BYPASS-STALE
    test_bypass_stale_never_serves_on_normal_path(ng, origin)        # S232 safety control
    test_bypass_stale_scoped_not_blanket(ng, origin)                 # S232 scope control
    test_bypass_stale_absent_directive_has_no_fallback(ng, origin)   # S232 default-unchanged control
    if redis is not None:
        # O4.4-i (L2). Needs a real Redis: without an L2 backend the L2 arming
        # path never executes and every delta reads 0, so the test would pass
        # while proving nothing. Guarded rather than unconditional for that
        # reason -- a no-Redis run must SKIP it, not fake it.
        test_breaker_l2_arming_site_gated_white_box(ng, origin, redis)
    test_breaker_lifecycle_open_zero_contact_close(ng, origin)  # O4.5
    test_breaker_off_negative_control_origin_climbs(ng, origin)  # O4.5
    test_breaker_record_position_and_sense(ng, origin)          # O4.5 / O4.2-f
    test_breaker_record_native_proxy_cache_hit_no_record(ng)    # O4.2-f
    test_backend_separators(ng)
    test_backend_malformed_pipes(ng)
    test_backend_none_is_exclusive(ng)
    test_backend_none_overrides_inherited(ng, origin)
    test_valid_status_rejects_304(ng)
    test_empty_l2_prefix_rejected(ng)
    test_duplicate_l2_directive_rejected(ng)
    test_backend_prefix_rejected(ng)
    test_keepalive_cap_rejected(ng)
    test_s8_scan_resistant_config_rejects(ng)
    test_lock_ttl_zero_rejected(ng)                          # O4.4-b
    test_lock_ttl_oversized_clamped_not_rejected(ng)          # O4.4-b
    test_admin_lock_ttl_oversized_reads_back_clamped(ng)      # O4.4-b read-back
    test_min_uses_window_range_rejected(ng)                   # P3-6
    test_redis_tls_empty_ca_and_name_rejected(ng)
    test_keep_stale_config_parse(ng)                        # S2.1
    test_use_stale_config_parse(ng)                         # S4.1
    test_memcached_keepalive_invalid_rejected(ng)
    test_memcached_keepalive_cap_rejected(ng)
    test_memcached_keepalive_timeout_invalid_rejected(ng)
    test_redis_timeout_zero_rejected(ng)                     # S231-L2-TIMEOUT0
    test_redis_param_reject_keeps_own_diagnostic(ng)         # MAINT-C1b
    test_memcached_timeout_zero_rejected(ng)                 # S231-L2-TIMEOUT0
    test_redis_connect_backoff_config_parse(ng)               # S231-L2-BACKOFF
    test_redis_connect_backoff_fails_fast(ng, origin)          # S231-L2-BACKOFF
    test_redis_connect_backoff_disabled_never_arms(ng, origin) # S231-L2-BACKOFF
    test_cold_wait_poll_timer_no_uaf(ng, origin)                # S231-COLDWAIT-UAF
    test_memcached_connect_backoff_fails_fast(ng, origin)       # S231-L2-BACKOFF
    test_memcached_replyless_peer_arms_backoff(ng)              # release audit
    test_valid_dup_status_warns(ng)
    test_tag_without_l2_warns(ng)
    test_tag_without_l2_but_surrogate_key_no_warn(ng)
    test_cache_control_invalid_mode_rejected(ng)
    test_cache_control_duplicate_rejected(ng)
    test_valid_status_rejects_out_of_range_code(ng)
    test_valid_rejects_bad_time(ng)
    test_require_header_rejects_invalid_name(ng)
    test_require_header_duplicate_rejected(ng)
    test_redis_bad_db_rejected(ng)
    test_redis_db_cap_rejected(ng)
    test_l2_prefix_charset_rejected(ng)
    test_no_cache_set_cookie(ng)
    test_p58_default_off_set_cookie_still_refused(ng)
    test_p58_listed_cookie_is_stored(ng)
    test_p58_stored_blob_carries_no_set_cookie(ng)
    test_p58_all_listed_multi_is_stored(ng)
    test_p58_one_unlisted_refuses(ng)
    test_p58_key_cookie_vetoes_the_relax(ng)
    test_p58_backend_preset_vetoes_the_relax(ng)
    test_p58_malformed_set_cookie_fails_closed(ng)
    test_no_cache_cc_private(ng)
    test_no_cache_cc_nostore(ng)
    test_no_cache_authorization(ng)
    test_refuse_set_cookie_counter(ng, origin)                # P0-1
    test_refuse_cache_control_counter(ng, origin)              # P0-1
    test_refuse_authorization_counter(ng, origin)               # P0-1
    test_serve_authorized_reads_public_anonymous_entry(ng, origin)     # P3-4
    test_serve_authorized_refuses_non_shareable_entry(ng, origin)      # P3-4
    test_serve_authorized_never_stores_under_credentials(ng, origin)   # P3-4
    test_serve_authorized_off_by_default_still_refuses_lookup(ng, origin)
    test_default_key_varies_by_host(ng)
    test_default_key_normalizes(ng)
    test_r31_normalize_max_args_over_cap_serves_and_keys_consistently(ng)
    test_r31_normalize_max_args_config_bounds(ng)
    test_cache_redirect(ng)
    test_cache_negative_404(ng)
    test_head_not_stored(ng)
    test_origin_method_hits_falsifiable(ng, origin)  # P5-6-r1a
    test_store_head_populates_head_only_url(ng, origin)          # P5-6-r2
    test_store_head_fixture_no_method_collapse(ng, origin)       # P5-6-r1
    test_head_derived_entry_never_served_to_get(ng, origin)      # P5-6-r1
    test_honor_cache_control(ng)
    test_honor_expires_absolute_ttl(ng)                    # upstream_ttl Expires arm
    test_cdn_cache_control_ttl_outranks_cache_control(ng)   # RFC 9213
    test_surrogate_control_ttl_outranks_cdn_and_cache_control(ng)  # RFC 9213
    test_surrogate_control_split_header_ttl(ng)             # AUD2-CC-TARGETED
    test_cdn_cache_control_split_header_ttl(ng)             # AUD2-CC-TARGETED
    test_cdn_cache_control_no_store_refuses(ng)             # RFC 9213
    test_targeted_cache_control_stripped_from_serve(ng)     # RFC 9213
    test_age_header(ng)
    test_request_no_cache(ng, origin)
    test_must_revalidate(ng)
    test_must_revalidate_split_header(ng)
    test_proxy_revalidate(ng)
    test_precise_maxage_token_parse(ng)
    test_ignore_cache_control_overrides_floor(ng, origin)
    test_ignore_cc_must_revalidate_keeps_stale_window(ng, origin)
    test_hits_for_exact_beyond_ring_size(ng, origin)        # A1: hits_for() Counter
    test_valid_zero_is_forever(ng, origin)
    test_honor_ttl_clamped_to_max(ng, origin)              # STAB-5 TTL clamp
    test_vary_encoding_qvalue(ng, origin)
    test_auto_vary_unknown_axis_uncacheable(ng, origin)
    test_vary_ignore_makes_named_axis_cacheable(ng, origin)           # P3-3
    test_vary_ignore_negative_control_without_directive(ng, origin)   # P3-3
    test_vary_ignore_axis_excluded_from_variant_key(ng, origin)       # P3-3
    test_vary_ignore_does_not_disable_other_unknown_axes(ng, origin)  # P3-3
    test_refuse_vary_unsafe_counter(ng, origin)                        # P0-1
    test_refuse_vary_unsafe_excludes_named_vetoes(ng, origin)          # P0-1
    test_auto_vary_stale_marker_reachable(ng, origin)
    test_206_never_cached(ng, origin)
    test_refuse_partial_counter(ng, origin)                    # P0-1
    test_refuse_head_counter(ng, origin)                       # P0-1
    test_refuse_require_header_counter(ng, origin)             # P0-1
    test_refuse_encoded_counter(ng, origin)                    # P0-1
    test_range_hit_matches_miss(ng, origin)
    test_range_suffix_hit_matches_miss(ng, origin)
    test_range_unsatisfiable_hit_matches_miss(ng, origin)
    test_range_not_offered_on_304(ng, origin)
    test_range_on_sie_serve(ng, origin)
    test_safe_key_distinct_sessionids(ng, origin)
    test_conditional_inm_304(ng, origin)
    test_conditional_inm_list_short_first(ng, origin)
    test_conditional_inm_star(ng)
    test_conditional_inm_mismatch_full(ng)
    test_conditional_ims_304(ng)
    test_conditional_ims_old_full(ng)
    test_conditional_inm_beats_ims(ng)
    test_rfc6_stale_conditional_full(ng, origin)
    test_rfc3_date_stable_across_hits(ng)
    test_rfc1_only_if_cached_miss_504(ng, origin)
    test_rfc1_only_if_cached_hit(ng, origin)
    test_rfc1_request_no_store(ng, origin)
    test_request_cache_control_multifield_restrictive(ng, origin)
    test_cache_control_delta_grammar(ng, origin)
    test_rfc1_request_max_age_zero_revalidates(ng, origin)
    test_rfc1_request_max_age_n(ng, origin)
    test_rfc1_request_min_fresh(ng, origin)
    test_rfc1_request_max_stale(ng, origin)
    test_p4_multi_directive_single_resolve(ng, origin)
    test_rfc2_swr_duration_extends_stale(ng, origin)
    test_purge_method(ng)
    test_cor5_l1only_variant_purge(ng, origin)
    test_cor5_l1only_variant_purge_gen_wrap(ng, origin)
    test_cache_and_purge_respect_access_control(ng)
    test_bypass(ng)
    test_bypass_uri(ng)
    test_bypass_uri_inert_after_internal_redirect(ng, origin)
    test_ctx_survives_error_page_internal_redirect(ng, origin)
    test_require_header(ng)
    test_key_cookie(ng)
    test_dynamic_response_header_not_cached(ng)
    test_status_variable(ng)
    test_status_stale(ng, origin)
    test_status_expired(ng, origin)
    test_serve_reason_variable(ng, origin)                   # S7.2 unfolded serve reason
    test_nocache_breaker_open_honours_cache(ng, origin)              # S231-NOCACHE-OUTAGE
    test_nocache_breaker_closed_still_revalidates(ng, origin)        # S231-NOCACHE-OUTAGE negctrl
    test_nocache_only_if_cached_still_504(ng, origin)                # S231-NOCACHE-OUTAGE regression pin
    test_nocache_breaker_open_varying_url_serves_correct_variant(ng, origin)  # S231-NOCACHE-OUTAGE ordering
    test_request_cc_serve_verdict_fresh(ng, origin)
    test_request_cc_serve_verdict_stale(ng, origin)
    test_request_cache_control_same_line_and_quotes(ng, origin)
    test_cc_mode_inheritance_child_preset_overrides_parent_ignore(ng, origin)
    test_no_store(ng)
    test_native_cache_headers_stripped(ng)
    test_many_headers_survive_list_part_spill(ng)
    test_admin_purge_post_with_body(ng)
    test_concurrent_hits_no_deadlock(ng)
    test_lru_eviction(ng)
    test_evict_blind_negative_control_closed_breaker_evicts_normally(ng)  # S231-EVICT-BLIND, must run BEFORE the breaker trips
    test_evict_blind_second_chance(ng, origin)                    # S231-EVICT-BLIND
    test_p1_coarse_lru_splice_keeps_hot_key_resident(ng)
    test_s8_scan_resistant_keeps_hot_key(ng)
    test_s8_default_on_is_scan_resistant(ng)
    test_s8_explicit_off_restores_flat_lru(ng)
    test_s8_reload_on_to_off_drains_protected(ng)
    test_s8_scan_still_stores_and_evicts(ng)
    test_admin_stats(ng)
    test_admin_prometheus(ng)
    test_admin_unsupported_method_405(ng)
    test_admin_purge_key(ng)
    test_admin_gating(ng)
    test_warm_populates(ng, origin)
    test_warm_root_and_trailing_slash_still_warm(ng, origin)
    test_warm_admin_no_uri_proxy_pass_no_ubsan_abort(ng, origin)
    test_warm_multi(ng, origin)
    test_warm_no_url(ng)
    test_warm_max_bound_enforced(ng, origin)
    test_warm_url_file_populates(ng, origin)
    test_warm_url_file_no_trailing_newline(ng, origin)
    test_warm_url_file_bound_enforced(ng, origin)
    test_warm_url_file_missing(ng)
    test_warm_url_file_fifo_does_not_block_worker(ng)
    if ng.fault_injection:
        test_warm_url_file_io_stages_run_off_event_loop(ng)
    test_warm_url_file_empty(ng, origin)
    test_warm_url_file_oversize_rejected(ng)
    test_warm_url_file_overlong_line_rejected(ng)
    test_warm_url_file_binary_no_crash(ng, origin)
    test_warm_strips_key_cookie(ng, origin)
    test_admin_warm_rebuilds_headers_from_allowlist(ng, origin)
    test_warm_rejects_traversal(ng, origin)
    test_warm_rejects_embedded_nul(ng, origin)
    test_warm_normal_url_still_warms(ng, origin)
    test_stale_serves_stale(ng, origin)
    test_swr_parent_disconnect_refresh_drop_lifecycle(ng, origin)
    test_single_flight(ng, origin)
    test_cold_single_flight(ng, origin)
    test_cold_lock_off_stampedes(ng, origin)
    test_min_uses_lock_merged_concurrent_claim(ng, origin)
    test_min_uses(ng, origin)
    test_min_uses_off_by_default(ng)
    test_min_uses_band_aggressive(ng, origin)
    test_min_uses_band_balanced_is_1(ng, origin)
    test_min_uses_directive_beats_band(ng, origin)
    test_min_uses_rejects_out_of_range(ng)
    test_stale_if_error(ng, origin)
    test_stale_serves_stale_origin_hard_dead(ng, origin)
    test_sie_serve_on_error(ng, origin)                     # RFC-2 CTB4 serve-on-error
    test_cold_wait_loser_serves_stale_on_lock_timeout(ng, origin)  # P1-8 timed-out loser serves SIE snapshot
    test_cold_wait_loser_no_snapshot_goes_to_origin(ng, origin)    # P1-8 control: no snapshot -> origin unchanged
    test_sie_serve_on_error_unbuffered(ng, origin)          # AUD-SIE-BODY proxy_buffering off
    if ng.fault_injection:
        test_sie_midbody_rescue(ng, origin)                 # S231-SIE-MIDBODY pre-flush rescue
        test_sie_midbody_rescue_declines_on_length_mismatch(ng, origin)  # S231-SIE-MIDBODY framing guard
    test_unbuf_streamed_store_and_hit(ng)                   # UNBUF streamed store + HIT round-trip
    test_unbuf_oversize_abort_mid_stream(ng, origin)        # UNBUF oversize mid-stream abort
    test_sie_serves_counter(ng, origin)                     # S7.1 sie_serves counter
    test_sie_origin_recovers_serves_fresh(ng, origin)       # RFC-2 success not hijacked
    test_keep_stale_serves_dead_origin(ng, origin)          # S2.2 keep_stale fallback
    test_keep_stale_shipped_default_serves_dead_origin(ng, origin)  # S231-DEFAULTS
    test_keep_stale_loses_to_response_sie(ng, origin)       # S2.2 / D-1 precedence
    test_use_stale_http_404(ng, origin)                     # S4.2 mask selects trigger
    test_use_stale_any_5xx_bit(ng, origin)                  # S4.2 ANY_5XX bit
    test_use_stale_off(ng, origin)                          # S4.2 off = empty mask
    test_use_stale_403_429(ng, origin)                      # S4.2 non-5xx tokens
    test_use_stale_error_transport_only(ng, origin)         # P5-5 transport-vs-origin 5xx
    test_hostile_origin_framing_matrix(ng, origin)          # HOSTILE-ORIGIN-MATRIX
    test_keep_stale_no_reaper_lru_only_reclaim(ng, origin)  # S2.3 no-reaper contract
    test_5xx_never_overwrites_cached_body(ng, origin)       # O6/S3.1 5xx-never-clobbers
    test_5xx_cta_bypass_never_overwrites_cached_body(ng, origin)  # AUD-5XX-CTA
    test_background_update_off_regenerates_inline(ng, origin)
    test_swr_refresh_injects_stored_validators(ng, origin)  # P1-4
    test_swr_refresh_no_validator_stays_unconditional(ng, origin)  # P1-4
    test_swr_refresh_304_keeps_entry_and_serves_it(ng, origin)  # P1-4 safety
    test_normalize_arg_order(ng, origin)
    test_normalize_arg_order_many_permutations(ng, origin)
    test_normalize_strips_tracking(ng, origin)
    test_normalize_strip_custom(ng, origin)
    test_normalize_strip_all(ng, origin)
    test_normalize_distinct_args_differ(ng, origin)
    test_normalize_vary_encoding(ng, origin)
    test_normalize_vary_device(ng, origin)
    test_normalize_vary_both(ng, origin)
    test_normalize_vary_off_by_default(ng, origin)
    test_normalize_vary_encoding_zstd(ng, origin)
    test_invalid_normalize_vary_token(ng)
    test_auto_vary_encoding(ng, origin)
    test_auto_vary_encoding_collapses_when_body_unencoded(ng, origin)      # P1-1
    test_auto_vary_encoding_precompressed_still_never_cached(ng, origin)  # P1-1
    test_key_encoded_origin_caches_and_keys_by_ae_class(ng, origin)        # P3-2
    test_key_encoded_origin_serve_guard_refuses_wrong_ae_class(ng, origin)  # P3-2
    test_key_encoded_origin_requires_auto_vary(ng)                         # P3-2
    test_auto_vary_marker_probe_selects_correct_variant(ng, origin)
    test_c3_marker_counter_tracks_store_and_purge(ng, origin)
    test_c3_auto_vary_resolves_variants_with_marker_gate_active(ng, origin)
    test_auto_vary_encoding_same_class_shares(ng, origin)
    test_auto_vary_device(ng, origin)
    test_auto_vary_language(ng, origin)
    test_swr_preserves_auto_vary_language(ng, origin)
    test_auto_vary_language_primary_subtag_shares(ng, origin)
    test_auto_vary_language_different_primary_splits(ng, origin)
    test_auto_vary_language_absent_splits_from_class(ng, origin)
    test_auto_vary_origin(ng, origin)
    test_auto_vary_origin_not_class_folded(ng, origin)
    test_auto_vary_star_uncacheable(ng, origin)
    test_auto_vary_cookie_uncacheable(ng, origin)
    test_auto_vary_mixed_refused_wins(ng, origin)
    test_auto_vary_off_ignores_vary(ng, origin)
    test_auto_vary_shipped_default_splits_encoding(ng, origin)
    test_auto_vary_shipped_default_cookie_refused(ng, origin)
    test_preset_window_differs(ng, origin)
    test_stale_mult_directive_beats_preset(ng, origin)
    test_stale_mult_rejects_out_of_range(ng)
    test_preset_micro_default_ttl(ng, origin)
    test_invalid_preset_name(ng)
    test_autotune_force_requires_post_action(ng, origin)
    test_autotune_raises_beta_within_band(ng, origin)
    test_autotune_load_factor_under_load(ng, origin)
    test_autotune_load_widens_stale_window(ng, origin)
    test_autotune_off_by_default(ng)
    test_autotune_insufficient_data(ng, origin)
    test_autotune_churn_disqualifies(ng, origin)
    if redis is not None:
        test_l2_write_through(ng, origin, redis)
        test_l2_negative_ttl_skips_repeat_get(ng, origin, redis)   # L13
        test_l2_negative_ttl_expires(ng, origin, redis)            # L13
        test_l2_negative_ttl_with_min_uses(ng, origin, redis)      # L13
        test_l2_negative_ttl_not_armed_by_outage(ng, origin, redis)  # L13-fix #5
        test_min_uses_counter_survives_uncacheable(ng, origin, redis)  # L13-fix CR-B
        # config-reject arm: no redis fixture needed, but its config anchor only
        # exists when the redis locations are emitted, so it lives in here too
        test_l2_negative_ttl_rejects_out_of_range(ng)              # L13
        test_l2_keepalive_reuse(ng, origin, redis)
        test_l2_keepalive_db_isolation(ng, origin, redis)
        test_redis_dirty_reply_not_pooled(ng)                 # exact RESP gate
        test_l2_cross_instance_fill(ng, origin, redis)
        test_l2_purge_key_drops_l2(ng, origin, redis)
        test_l2_expired_consults_l2(ng, origin, redis)
        test_request_cc_serve_verdict_l2(ng, origin, redis)  # C-S5-a L2 verdict arm
        test_l2_promote_race_never_overwrites_newer_l1_entry(
            ng, origin, redis)                          # AUD-L2-PROMOTE-RACE
        test_l2_preserves_original_freshness(ng, origin, redis)
        test_l2_malformed_blob_rejected(ng, origin, redis)  # STAB-4 validate
        test_ctb5_date_replayed_from_blob(ng, origin, redis)   # PERF-AUD2-02
        test_ctb5_role_tag_restores_typed_headers(ng, origin, redis)  # AUD2-03
        # P4-3 positive control: the store path really does stamp the bit,
        # so the fast path is not silently a no-op.
        test_l2_store_stamps_hdrs_vetted_bit(ng, origin, redis)        # P4-3
        test_l2_forged_blob_cannot_inject_headers(ng, origin, redis)   # AUD-BLOBE2E1
        # P4-3: same primitives, but with BLOBF_HDRS_VETTED forged on -- the
        # bit must be stripped at L2 ingress, not honoured off the wire.
        test_l2_forged_vetted_bit_does_not_bypass_header_gate(
            ng, origin, redis)                                         # P4-3
        test_l2_restore_href_array_alignment_ubsan(ng, origin, redis)  # S231-HDRWALK-VALIDATE-STRICTER
        test_sie_forged_blob_cannot_inject_headers(ng, origin, redis)  # AUD-SIEBLOB1
        test_sie_ttl_stored_in_blob(ng, origin, redis)      # RFC-2 CTB4 sie_ttl
        test_l2_retain_ttl_covers_sie(ng, origin, redis)    # S1.2 retain_ttl
        test_l2_sie_serve_survives_l1_purge(ng, origin, redis)  # S1.2 e2e serve
        test_l2_stale_refetch_does_not_stall_on_lock(ng, origin, redis)  # V-HANG-2
        test_l2_unserveable_giveup_still_single_flights(ng, origin, redis)
        test_l2_tag_add_on_store(ng, origin, redis)
        test_l2_tag_truncation_warns(ng, origin, redis)
        test_l2_tag_overlong_warns(ng, origin, redis)  # CR297-TAGLEN
        test_l2_tag_purge(ng, origin, redis)
        test_l2_tag_purge_large(ng, origin, redis)  # STAB-3 + PERF-1/2 pipeline
        test_l2_tag_purge_arg_validation(ng, origin, redis)  # AUD-TAG1
        test_l2_tag_cap_and_dedup(ng, origin, redis)  # PERF-2 tag cap/dedup
        test_l2_tag_cap_purge_reports_degraded(ng, origin, redis)  # TAG-CAP-SILENT-DROP
        test_l2_tag_add_batched_one_op(ng, origin, redis)  # L9 one op for N tags
        test_cor5_redis_variant_purge(ng, origin, redis)  # COR-5 variant index
        # COR-5(b): a variant-index write dropped before the wire self-heals
        # on a later hit. Runs AFTER the plain COR-5 test, which is the
        # symptom detector for the same defect and must keep its own fixture.
        test_cor5_varidx_selfheal_after_dropped_index_write(ng, origin, redis)
        # c-1: the PURGE reply must distinguish a complete enumeration from a
        # degraded one when a drop is still outstanding at purge time.
        test_cor5_purge_reports_degraded_enumeration(ng, origin, redis)
        # COR5-PURGE-VARIDX-RACE: a purge racing an UNACKNOWLEDGED index write
        # (handed to the transport, never acked -- not a drop) must likewise
        # report complete:false instead of a silent short count.
        #
        # ⚠ ORDER IS LOAD-BEARING: runs AFTER the degraded test above. Its hold
        # fault models a write that is never acknowledged, so the zone-scoped
        # varidx_inflight gap it opens is permanent -- any later test in this
        # zone asserting an unqualified "complete" would fail against it.
        test_cor5_purge_reports_inflight_index_write(ng, origin, redis)
        # SILENT-INDEX-DROP option (c): a purge-by-tag must REPORT a degraded
        # enumeration once a tag-index drop is outstanding, rather than
        # claiming success while an unindexed object keeps serving stale.
        #
        # ⚠ ORDER IS LOAD-BEARING: this runs BEFORE the option (a) test below.
        # tag_index_drops is zone-scoped and only ever increases (tags have no
        # re-issue, by design -- see the test docstring), so its clean
        # "complete absent" leg is only satisfiable while the zone has taken
        # no drop yet. Moving it after option (a) makes it a permanent red,
        # not a flake.
        test_tagidx_purge_reports_degraded_after_dropped_index_write(
            ng, origin, redis)
        # SILENT-INDEX-DROP option (a): the L9 tag-index write's own drop
        # must be observable via the admin tag_index_drops counter.
        test_l9_tag_index_drop_is_observable(ng, origin, redis)
        test_l2_vary_marker_cold_node_finds_peer_variant(ng, origin, redis)  # P3-5
        # c-2: a peer's PURGE must stop a warm-marker node from serving the
        # old variant within cache_turbo_vary_marker_revalidate's window; the
        # negative control (knob at 0) must reproduce today's unbounded
        # staleness, proving the positive test actually discriminates.
        test_c2_vary_marker_revalidate_closes_cross_node_staleness(
            ng, origin, redis)
        test_c2_vary_marker_revalidate_negative_control_knob_zero(
            ng, origin, redis)
        test_multinode_lock(ng, origin, redis)
        test_cross_node_won_stale_body(ng, origin, redis)  # S231-PERF-BGSNAP
        test_lock_self_heal(ng, origin, redis)
        test_cold_single_flight_cross_node(ng, origin, redis)
        test_cross_node_winner_owner_token_preserved(ng, origin, redis)  # AUD-NXLOCK-OWNER
        test_l2_miss_counted_once_on_cold_park(ng, origin)  # double-count guard
        test_l2_db_select(ng, origin, redis)         # SELECT-only preamble
        # AUD-SCAN1: multi-page SCAN walks. Own ctscan: prefix, and they clean up
        # after themselves, so they must stay AHEAD of the two all-purge tests
        # below (the last of which deliberately empties L2).
        test_scan_walk_pool_is_o1_in_pages(ng, redis)
        test_scan_walk_page_cap_reports_incomplete(ng, redis)
        test_scan_walk_deadline_reports_incomplete(ng, redis)  # S231-L2-SCANTIME
        # AUD-PURGE-HONESTY1: shares the ctscan: prefix for its control leg, so
        # it belongs in this group and ahead of the all-purge tests below.
        test_all_purge_reports_l2_unavailable_when_backend_is_down(ng, redis)
        test_purge_all_escapes_redis_prefix_glob(ng, redis)
        test_purge_all_clears_l2(ng, origin, redis)  # last L2: empties L2
        test_lock_redis_outage_fallback(ng, origin, redis)  # NGX_ERROR lock fallback (stops/restarts redis)
    if redis_auth is not None:
        test_l2_dsn_auth_db(ng, origin, redis_auth)  # AUTH+SELECT preamble
        test_l2_keepalive_no_auth_replay(ng, origin, redis_auth)  # no replay on reuse
    if redis_tls is not None:
        test_l2_tls(ng, origin, redis_tls)           # rediss:// + verify
        test_l2_tls_keepalive_reuse(ng, origin, redis_tls)  # v15-2 TLS pool
        if redis is not None:
            # v16: plain + TLS profiles each keep their own keepalive bucket
            test_l2_keepalive_per_profile_no_starvation(
                ng, origin, redis, redis_tls)
    if redis_tls_untrusted is not None:
        test_redis_tls_untrusted_ca_rejected(ng, origin, redis_tls_untrusted)
        test_redis_tls_handshake_failure_arms_backoff(
            ng, origin, redis_tls_untrusted)  # S231-L2-BACKOFF TLS follow-up
    if redis_tls_expired is not None:
        test_redis_tls_expired_cert_rejected(ng, origin, redis_tls_expired)
    if mc is not None:
        test_l2_memcached_write_through(ng, origin, mc)        # v13
        test_l2_memcached_cross_instance_fill(ng, origin, mc)  # v13
        # P4-3: the memcached ingress point is a SEPARATE call site from
        # redis.c; without this the redis test alone would stay green while
        # memcached deployments kept the bypass.
        test_l2_memcached_forged_vetted_bit_does_not_bypass_header_gate(
            ng, origin, mc)                                    # P4-3
        test_l2_memcached_purge_key_drops_l2(ng, origin, mc)   # v13
        if redis is not None:
            # child redis over parent memcached — precedence regression lock
            test_l2_backend_inheritance_child_redis_over_parent_memcached(
                ng, origin, redis, mc)
        test_mc_keepalive_reuse(ng, origin, mc)            # D-O1 reuse+re-pool
        test_mc_keepalive_zero_does_not_drain_pool(ng, origin, mc)  # MC-A2
        test_mc_keepalive_idle_timeout_drops(ng, origin, mc)  # D-O1 timedout br
        test_mc_dirty_reply_not_pooled(ng, origin)         # D-O2 clean-gate
        test_mc_set_ack_is_recognized_and_pools(ng, origin)  # R4-3 ack match
        # D-O1 idle-pool close: MUST be last mc test — it stops the mc server.
        test_mc_keepalive_server_close_survives(ng, origin, mc)
    # PERF-7 zero-copy serve stress: run LAST among L1 tests — its 48-thread /
    # 4000-request eviction churn keeps the workers busy, so placing it before a
    # timing-sensitive test (e.g. stale-if-error's ~0.8s bg-refresh window) can
    # starve that window under the slow ASan build. Here it can't perturb others.
    test_perf7_zero_copy_serve_under_eviction(ng)
    test_shm_refresh_under_pressure(ng)
    test_admin_all_zero_does_not_purge(ng)
    test_admin_purge_all(ng)   # last: it empties the zone


def main() -> int:
    args = parse_args()
    binary = pathlib.Path(args.nginx_binary).resolve()
    module = pathlib.Path(args.module).resolve() if args.module else None
    if not binary.exists():
        raise FileNotFoundError(binary)
    if module is not None and not module.exists():
        raise FileNotFoundError(module)

    _check_port_registry(PORT_OFFSETS)

    origin_port = args.port + PORT_OFFSETS["origin"]
    redis_port = args.port + PORT_OFFSETS["redis"] if args.redis_server else None
    redis_auth_port = (
        args.port + PORT_OFFSETS["redis_auth"] if args.redis_server else None)
    redis_tls_port = (
        args.port + PORT_OFFSETS["redis_tls"] if args.redis_server else None)
    memcached_port = (
        args.port + PORT_OFFSETS["memcached"] if args.memcached_server else None)
    # mc_dirty_reply (+25) is claimed here too: test_mc_dirty_reply_not_pooled()
    # stands up its DirtyMemcached on `ng.port + PORT_OFFSETS["mc_dirty_reply"]`,
    # a call site nowhere near this block. See PORT_OFFSETS above -- that is
    # the registry a new fixture must check before picking an offset.
    redis_tls_untrusted_port = (
        args.port + PORT_OFFSETS["redis_tls_untrusted"] if args.redis_server else None)
    redis_tls_expired_port = (
        args.port + PORT_OFFSETS["redis_tls_expired"] if args.redis_server else None)
    redis_password = "ctsecret"
    # AUD-TESTFIX1: a fixture whose CLI flag was passed (--redis-server,
    # --memcached-server) must fail the run if it cannot start -- redis.start()
    # and mc.start() already raise uncaught, which is correct, leave them
    # alone. TLS is the one sub-fixture allowed to stay best-effort (needs a
    # TLS-capable redis-server build + working openssl), but "best-effort"
    # must never mean *silent*: every skip prints a loud, grep-able line and
    # is counted here so CI can assert the fixture set it asked for actually
    # came up instead of quietly losing ~80 L2/TLS tests off the running total.
    fixture_skips: list[str] = []

    def _skip(name: str, reason: str) -> None:
        line = f"FIXTURE SKIPPED: {name} ({reason})"
        print(line, flush=True)
        fixture_skips.append(name)

    with tempfile.TemporaryDirectory(prefix="cache-turbo-ci-") as tmp:
        root = pathlib.Path(tmp)
        origin = Origin(origin_port, delay=0.05)
        redis = redis_auth = redis_tls = mc = None
        redis_tls_untrusted = redis_tls_expired = None
        tls_certs = None
        if args.memcached_server:
            mc = MemcachedServer(pathlib.Path(args.memcached_server),
                                 memcached_port)
        if args.redis_server:
            rbin = pathlib.Path(args.redis_server)
            redis = RedisServer(rbin, root / "redis", redis_port)
            redis_auth = RedisServer(rbin, root / "redis-auth", redis_auth_port,
                                     password=redis_password)
            # TLS is best-effort: needs a TLS-capable redis + openssl. If either
            # is missing, skip the rediss:// tests rather than failing the
            # suite -- but loudly (see fixture_skips above).
            try:
                tls_certs = gen_tls_certs(root / "redis-tls-certs")
                redis_tls = RedisServer(rbin, root / "redis-tls", redis_tls_port,
                                        tls_certs=tls_certs)
                # AUD-TLS1 negative fixtures: a second, untrusted CA + an
                # expired-but-chain-trusted cert. Best-effort alongside the
                # base TLS fixture -- same openssl/redis-server dependency.
                untrusted_certs = gen_tls_certs(root / "redis-tls-untrusted-certs")
                redis_tls_untrusted = RedisServer(
                    rbin, root / "redis-tls-untrusted", redis_tls_untrusted_port,
                    tls_certs=untrusted_certs)
                expired_certs = gen_tls_expired_cert(
                    root / "redis-tls-expired-certs",
                    tls_certs["ca_key"], tls_certs["ca"])
                redis_tls_expired = RedisServer(
                    rbin, root / "redis-tls-expired", redis_tls_expired_port,
                    tls_certs=expired_certs)
            except (OSError, subprocess.SubprocessError) as e:
                _skip("redis_tls", f"cert/build generation failed: {e}")
                redis_tls = redis_tls_untrusted = redis_tls_expired = None
                tls_certs = None

        ng = Nginx(binary, module, root / "server", args.port, origin_port,
                   args.runner, args.single_process, redis_port,
                   redis_auth_port=redis_auth_port if redis_auth else None,
                   redis_password=redis_password,
                   redis_tls_port=redis_tls_port if redis_tls else None,
                   redis_tls_ca=(tls_certs or {}).get("ca"),
                   memcached_port=memcached_port if mc else None,
                   fault_injection=args.fault_injection,
                   redis_tls_untrusted_port=(
                       redis_tls_untrusted_port if redis_tls_untrusted else None),
                   redis_tls_expired_port=(
                       redis_tls_expired_port if redis_tls_expired else None))
        ng.sanitizer = args.sanitizer

        try:
            origin.start()
            if redis is not None:
                redis.start()
            if redis_auth is not None:
                redis_auth.start()
            if redis_tls is not None:
                redis_tls, redis_tls_untrusted, redis_tls_expired = (
                    _start_tls_fixtures(
                        redis_tls, redis_tls_untrusted, redis_tls_expired,
                        _skip))
            if mc is not None:
                mc.start()
            ng.write_config()
            ng.config_test()
            ng.start()
            _instrument(origin)   # DIAG: socket-flake attribution
            run_all(ng, origin, redis, redis_auth, redis_tls, mc,
                    redis_tls_untrusted, redis_tls_expired)
            time.sleep(0.2)
            ng.stop()
            ng.assert_clean_logs()
        finally:
            ng.stop()
            if redis is not None:
                redis.stop()
            if redis_auth is not None:
                redis_auth.stop()
            if redis_tls is not None:
                redis_tls.stop()
            if redis_tls_untrusted is not None:
                redis_tls_untrusted.stop()
            if redis_tls_expired is not None:
                redis_tls_expired.stop()
            if mc is not None:
                mc.stop()
            origin.stop()

        if fixture_skips:
            print(f"FIXTURE SUMMARY: {len(fixture_skips)} skipped: "
                  f"{', '.join(fixture_skips)}", flush=True)

    print("OK: miss/hit, POST passthrough uncached (origin do_POST harness), "
          "header fidelity, max_size, "
          "cacheability floor (Set-Cookie/CC-private/CC-no-store/Authorization "
          "not cached), default-key Host split, "
          "per-status caching (301/404 cached, HEAD not stored), "
          "honor upstream Cache-Control, "
          "Expires-only absolute TTL (upstream_ttl step 4), "
          "RFC 9213 targeted cache-control (CDN-CC/Surrogate-Control TTL "
          "precedence + no-store veto + stripped from serve), "
          "valid 0 = forever (fresh HIT, not instant-stale), "
          "TTL clamp to TTL_MAX (huge upstream max-age stays fresh, no overflow), "
          "Accept-Encoding q-value (gzip;q=0 != gzip bucket), "
          "auto-Vary unknown-axis uncacheable, "
          "auto-Vary stale-marker still reachable, 206 never cached, "
          "raw-key distinct sessionids (explicit request_uri key), "
          "conditional 304 (v11: If-None-Match/*/mismatch, "
          "If-Modified-Since fresh/stale, INM-beats-IMS precedence), "
          "PURGE method, COR-5 auto-Vary variant purge (L1-only gen-bump), "
          "bypass + no_store, DIY bypass_uri (v15: segment-boundary + subdir + "
          "non-boundary caches), backend_prefix malformed value rejected "
          "(item 18), DIY key_cookie (v15: value-keyed entries + anon "
          "bucket + exact-name + split-header + oversize values collapse to one "
          "bucket distinct from anon and from in-range, 256 still verbatim), "
          "$cache_turbo_status (MISS/HIT/BYPASS + bypasses counter, "
          "STALE serve, EXPIRED refetch), "
          "RFC-1 request Cache-Control serve verdict (fresh: max-age=0/min-fresh "
          "refuse fresh HIT + revalidate, bare max-stale still serves fresh; "
          "stale: default and bare serve STALE, max-stale=N applies its bound, "
          "invalid valued max-stale refuses; same-line repeated bounds merge "
          "restrictively and quoted extension fragments stay inert), "
          "cc_mode inheritance (child preset honor "
          "overrides parent ignore), "
          "native-cache headers stripped, "
          "admin purge w/ body, "
          "concurrency (R1), prometheus metrics (incl L2 hit/miss), "
          "default-key normalization, "
          "LRU eviction (R6), S8 scan-resistant segmented LRU (protected hot key survives a scan; default-off and explicit-off both still evict it; churn stores+evicts without wedging; config rejects; on->off across a REAL reload drains inherited PROTECTED nodes), refresh-under-pressure (R6b), "
          "stale serve (R3), single-flight (R4), "
          "cold-miss single-flight (v10: per-box collapse + lock-off stampede), "
          "min_uses (v15: cache after N misses + off-by-default; "
          "H3c: aggressive band=2, balanced band stays 1, directive beats band, "
          "range-checked), "
          "stale-if-error (v8), "
          "keep_stale (S2.2: serves a dead origin with no response "
          "stale-if-error, off surfaces the error; response stale-if-error "
          "wins over keep_stale, not max(); S2.3: no time-based reaper, "
          "LRU/max_size is the only reclaim), "
          "background_update off (v8 inline regen), "
          "admin stats/purge/gating, warm (v3-3: populates/multi/no-url), "
          "key normalize (v3-1: order/tracking/"
          "custom-strip/strip-all/distinct), "
          "vary suffix (v3-4: encoding/device/both/off-by-default, "
          "zstd>br bucket (V6), invalid-token rejected), "
          "auto-Vary (v11: encoding/same-class/device/language/origin split, "
          "Vary:*/Cookie/mixed-refused uncacheable, on-by-default splits+"
          "refuses with no directive, explicit off still ignores Vary, "
          "P1-1: encoding axis collapses when the body is unencoded, still "
          "splits when genuinely pre-encoded), "
          "presets (v3-2: conservative/aggressive stale-window differ, "
          "explicit cache_turbo_stale_mult beats the band + range-rejects, "
          "invalid-name rejected), "
          "cookie predicate multi-match (guest cookie must not mask a member "
          "in the same header, both orders, two-guests still cacheable), "
          "2026 preset expansion (textpattern/bludit/spip/bugzilla/mantisbt/"
          "plone/umbraco/dotclear/wikijs: public HIT + state-cookie/URI/arg "
          "BYPASS, custom "
          "cookie-prefix predicates, backend_prefix rebasing; mantis/"
          "classicpress/backdrop aliases), "
          "header-auth REST surfaces (magento /rest+/soap, drupal /jsonapi+"
          "/oauth, wp ?rest_route=, /restaurant-supplies still cached), "
          "config maxima/warns (STAB-5 keepalive cap rejected, COR-9 dup-status "
          "warn, COR-0 tag-without-L2 warn), "
          "config-time rejects (cache_control bad-mode/duplicate, valid "
          "out-of-range code/bad time, require_header non-token/duplicate, "
          "redis DSN bad db, redis db out-of-range cap both arms), "
          "autotune (v4-3: raises beta within band/off-by-default/"
          "insufficient-data/churn-disqualify)"
          + (", L2 write-through (P4), "
             "L2 negative memo (L13: skips the repeat GET, expires, "
             "coexists with min_uses, range-checked incl. 0=off, "
             "survives its full window, NOT armed by an L2 outage, "
             "min_uses counter survives uncacheable teardown), "
             "keepalive pool reuse (v15), "
             "malformed L2 blob rejected pre-L1 (STAB-4), "
             "L2 cross-instance fill (P2), "
             "L2-aware key purge (P6), expired-L1 consults L2 (P6), "
             "tag index add (v2c), tag purge both tiers (P4), "
             "COR-5 Redis variant-index purge (both tiers), "
             "multi-node dogpile lock (v4-2 SET NX PX), lock self-heal (v4-2), "
             "cold-miss cross-node single-flight (v10), "
             "?all=1 clears L2 (v4-2 SCAN+DEL), "
             "DSN SELECT-db preamble (v5)"
             if redis_port else "")
          + (", DSN AUTH+SELECT preamble (v5)" if redis_auth else "")
          + (", rediss:// TLS + verify (v5), TLS keepalive reuse (v15-2)"
             + (", per-profile keepalive no-starvation (v16)" if redis_port else "")
             if redis_tls else "")
          + (", memcached L2 (v13: write-through, cross-instance fill, "
             "key purge)" if memcached_port else "")
          + (", backend-inheritance (child redis over parent memcached)"
             if (memcached_port and redis_port) else "")
          + (", alloc-fault fails-closed, file-backed sendfile delegate "
             "never stores" if ng.fault_injection else ""))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
