#define _POSIX_C_SOURCE 200809L

/* A failed marker write may roll back A, but must never delete replacement B. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ngx_shim_marker_rollback.h"
#include "generated_marker_rollback.inc"

static int         failures;
unsigned           ngx_test_release_calls;
u_char            *ngx_test_released_data;
unsigned           ngx_test_warning_calls;
ngx_int_t          ngx_test_warning_level;
const char        *ngx_test_warning_format;
static u_char       blob_a[1];
static u_char       blob_b[1];
static u_char       variant_key[32];
static pthread_barrier_t marker_failed;
static pthread_barrier_t replacement_done;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);   \
            failures++;                                                      \
        }                                                                    \
    } while (0)

typedef struct {
    ngx_http_request_t              *request;
    ngx_http_cache_turbo_loc_conf_t *clcf;
    ngx_http_cache_turbo_zone_t     *zone;
} race_ctx_t;

static void
hang_watchdog(int signo)
{
    static const char message[] =
        "HANG: marker rollback barrier or zone mutex did not complete\n";

    (void) signo;
    (void) write(STDERR_FILENO, message, sizeof(message) - 1);
    _Exit(2);
}

static void
require_zero(int rc, const char *message)
{
    if (rc != 0) {
        fprintf(stderr, "FAIL: %s (rc=%d)\n", message, rc);
        exit(2);
    }
}

static void
wait_barrier(pthread_barrier_t *barrier)
{
    int rc = pthread_barrier_wait(barrier);

    if (rc != 0 && rc != PTHREAD_BARRIER_SERIAL_THREAD) {
        fprintf(stderr, "barrier wait failed: %d\n", rc);
        abort();
    }
}

static void *
request_a_rollback(void *data)
{
    race_ctx_t *ctx = data;

    /* A has observed its marker failure.  Hold it before rollback until B has
     * installed a replacement under the same variant key. */
    wait_barrier(&marker_failed);
    wait_barrier(&replacement_done);
    ngx_http_cache_turbo_body_filter_rollback_store(ctx->request, ctx->clcf,
        ctx->zone, variant_key, 0x12345678, blob_a);
    return NULL;
}

static void *
request_b_replace(void *data)
{
    race_ctx_t *ctx = data;

    wait_barrier(&marker_failed);
    ngx_shmtx_lock(ngx_http_cache_turbo_zone_mutex(ctx->zone));
    ctx->zone->node.data = blob_b;
    ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(ctx->zone));
    wait_barrier(&replacement_done);
    return NULL;
}

static void
reset_zone(ngx_http_cache_turbo_zone_t *zone, u_char *data)
{
    zone->present = 1;
    zone->drops = 0;
    memcpy(zone->node.key, variant_key, sizeof(variant_key));
    zone->node.data = data;
    ngx_test_release_calls = 0;
    ngx_test_released_data = NULL;
    ngx_test_warning_calls = 0;
    ngx_test_warning_level = 0;
    ngx_test_warning_format = NULL;
}

int
main(void)
{
    ngx_cache_turbo_l1_backend_t       l1;
    ngx_http_cache_turbo_loc_conf_t    clcf;
    ngx_http_cache_turbo_zone_t        zone;
    ngx_http_request_t                 request;
    ngx_connection_t                   connection;
    race_ctx_t                         race;
    pthread_t                          thread_a;
    pthread_t                          thread_b;
    unsigned                           i;

    for (i = 0; i < sizeof(variant_key); i++) {
        variant_key[i] = (u_char) (0x40 + i);
    }

    require_zero(pthread_mutex_init(&zone.mutex, NULL),
                 "zone mutex must initialise");
    l1.purge_if_blob = ngx_http_cache_turbo_shm_purge_if_blob;
    clcf.l1 = &l1;
    memset(&request, 0, sizeof(request));
    memset(&connection, 0, sizeof(connection));
    request.connection = &connection;
    request.uri.data = (u_char *) "/asset.css";
    request.uri.len = sizeof("/asset.css") - 1;
    race.request = &request;
    race.clcf = &clcf;
    race.zone = &zone;

    reset_zone(&zone, blob_a);
    require_zero(pthread_barrier_init(&marker_failed, NULL, 2),
                 "marker-failed barrier must initialise");
    require_zero(pthread_barrier_init(&replacement_done, NULL, 2),
                 "replacement-done barrier must initialise");
    (void) signal(SIGALRM, hang_watchdog);
    (void) alarm(5);
    require_zero(pthread_create(&thread_a, NULL, request_a_rollback, &race),
                 "request A thread must start");
    require_zero(pthread_create(&thread_b, NULL, request_b_replace, &race),
                 "request B thread must start");
    require_zero(pthread_join(thread_a, NULL),
                 "request A thread must complete");
    require_zero(pthread_join(thread_b, NULL),
                 "request B thread must complete");
    (void) alarm(0);

    CHECK(zone.present && zone.node.data == blob_b,
          "concurrent replacement B must survive A's rollback");
    CHECK(zone.drops == 0,
          "A's stale token must not delete B's replacement node");
    CHECK(ngx_test_release_calls == 1 && ngx_test_released_data == blob_a,
          "A's pinned blob token must be released exactly once");
    CHECK(ngx_test_warning_calls == 0,
          "replacement-preserving rollback must not claim it deleted A");

    (void) pthread_barrier_destroy(&marker_failed);
    (void) pthread_barrier_destroy(&replacement_done);

    reset_zone(&zone, blob_a);
    ngx_http_cache_turbo_body_filter_rollback_store(&request, &clcf, &zone,
                                                     variant_key, 0x12345678,
                                                     blob_a);
    CHECK(!zone.present && zone.drops == 1,
          "isolated failed marker store must remove A's unsafe variant");
    CHECK(ngx_test_release_calls == 1 && ngx_test_released_data == blob_a,
          "isolated rollback must release A's pinned token exactly once");
    CHECK(ngx_test_warning_calls == 1
              && ngx_test_warning_level == NGX_LOG_WARN,
          "successful unsafe-variant rollback must emit exactly one warning");
    CHECK(ngx_test_warning_format != NULL
              && strstr(ngx_test_warning_format,
                        "removed unsafe auto-vary variant") != NULL,
          "rollback warning must identify removal of the unsafe variant");

    reset_zone(&zone, blob_b);
    ngx_http_cache_turbo_body_filter_rollback_store(&request, &clcf, &zone,
                                                     variant_key, 0x12345678,
                                                     NULL);
    CHECK(zone.present && zone.node.data == blob_b && zone.drops == 0,
          "a failed L1 store with no token must not purge an existing entry");
    CHECK(ngx_test_release_calls == 0,
          "a missing store token must not be released");
    CHECK(ngx_test_warning_calls == 0,
          "a rollback that deletes nothing must not emit a removal warning");

    (void) pthread_mutex_destroy(&zone.mutex);
    fprintf(stderr, "marker rollback race: %d failures\n", failures);
    return failures ? 1 : 0;
}
