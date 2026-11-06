/* Minimal nginx declarations for the lifetime query tests. Copyright (C) 2026 Thijs Eilander, BSD-2-Clause. */
#ifndef NGX_STUB_H
#define NGX_STUB_H
typedef unsigned long size_t;
#define NULL ((void *) 0)
typedef long ngx_int_t;
typedef struct ngx_log_s { int level; } ngx_log_t;
typedef struct ngx_pool_s { size_t size; } ngx_pool_t;
typedef struct ngx_event_s ngx_event_t;
typedef void (*ngx_event_handler_pt)(ngx_event_t *ev);
struct ngx_event_s { void *data; ngx_event_handler_pt handler; };
typedef struct ngx_connection_s {
    void *data; ngx_event_t *read; ngx_event_t *write; ngx_log_t *log; unsigned destroyed:1;
} ngx_connection_t;
typedef struct ngx_http_request_s ngx_http_request_t;
struct ngx_http_request_s {
    ngx_connection_t *connection; ngx_pool_t *pool; ngx_http_request_t *main;
    unsigned count:16; int uri;
};
#define NGX_DONE -4
#define NGX_ERROR -1
void ngx_http_finalize_request(ngx_http_request_t *r, ngx_int_t rc);
void ngx_http_terminate_request(ngx_http_request_t *r, ngx_int_t rc);
void ngx_http_free_request(ngx_http_request_t *r, ngx_int_t rc);
void ngx_http_run_posted_requests(ngx_connection_t *c);
void ngx_http_core_run_phases(ngx_http_request_t *r);
void ngx_log_it(ngx_log_t *log, int v);
void *ngx_palloc(ngx_pool_t *pool, size_t n);
void ngx_destroy_pool(ngx_pool_t *pool);
#endif
