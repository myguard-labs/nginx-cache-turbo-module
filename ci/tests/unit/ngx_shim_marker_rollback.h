/* Minimal shared-memory/backend surface for the extracted rollback helpers. */
#ifndef NGX_CACHE_TURBO_UNIT_SHIM_MARKER_ROLLBACK_H
#define NGX_CACHE_TURBO_UNIT_SHIM_MARKER_ROLLBACK_H

#include <pthread.h>
#include <stdint.h>
#include <string.h>

typedef intptr_t       ngx_int_t;
typedef unsigned char  u_char;

#define NGX_OK  0

typedef struct ngx_http_cache_turbo_node_s {
    u_char  key[32];
    u_char *data;
} ngx_http_cache_turbo_node_t;

typedef struct ngx_http_cache_turbo_zone_s {
    pthread_mutex_t                 mutex;
    ngx_http_cache_turbo_node_t     node;
    unsigned                        present;
    unsigned                        drops;
} ngx_http_cache_turbo_zone_t;

typedef struct ngx_cache_turbo_l1_backend_s {
    ngx_int_t (*purge_if_blob)(ngx_http_cache_turbo_zone_t *z,
        u_char *key_hash, uint32_t hash, u_char *stored_data);
} ngx_cache_turbo_l1_backend_t;

typedef struct ngx_http_cache_turbo_loc_conf_s {
    ngx_cache_turbo_l1_backend_t *l1;
} ngx_http_cache_turbo_loc_conf_t;

extern unsigned  ngx_test_release_calls;
extern u_char   *ngx_test_released_data;

#define ngx_http_cache_turbo_zone_mutex(z) (&(z)->mutex)

static void
ngx_shmtx_lock(pthread_mutex_t *mutex)
{
    (void) pthread_mutex_lock(mutex);
}

static void
ngx_shmtx_unlock(pthread_mutex_t *mutex)
{
    (void) pthread_mutex_unlock(mutex);
}

static ngx_http_cache_turbo_node_t *
ngx_http_cache_turbo_shm_lookup(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash)
{
    (void) hash;

    if (!z->present || memcmp(z->node.key, key_hash, 32) != 0) {
        return NULL;
    }

    return &z->node;
}

static void
ngx_http_cache_turbo_shm_drop_locked(ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_node_t *ctn)
{
    (void) ctn;
    z->present = 0;
    z->drops++;
}

static void
ngx_http_cache_turbo_blob_release(ngx_http_cache_turbo_zone_t *z,
    u_char *data)
{
    (void) z;
    ngx_test_release_calls++;
    ngx_test_released_data = data;
}

#endif
