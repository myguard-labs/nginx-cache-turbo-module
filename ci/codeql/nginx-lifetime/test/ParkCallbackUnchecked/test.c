/* Copyright (C) 2026 Thijs Eilander. SPDX-License-Identifier: BSD-2-Clause */
#include "../ngx_stub.h"

typedef struct {
    ngx_http_request_t *request;
    ngx_connection_t *peer;
    void (*read_handler)(ngx_event_t *);
    unsigned park_gen;
} demo_redis_op_t;

struct demo_mc_op_s {
    ngx_http_request_t *request;
    unsigned park_gen;
};

/* Not a backend op: its request field is out of scope. */
typedef struct {
    ngx_http_request_t *request;
} demo_ctx_t;

int demo_park_stale(void *op);

/* The BP-B2 guard: drop the reply when the park is no longer current. */
#define CT_PARK_CHECK(op)                                                     \
    do {                                                                      \
        if (demo_park_stale(op)) {                                            \
            return;                                                           \
        }                                                                     \
    } while (0)

void demo_install(void (*read_handler)(ngx_event_t *));

/* ---- completion helpers, reached from the read handlers ---- */

/* BAD: a completion helper that never checks the park */
static void demo_get_finish(demo_redis_op_t *op)
{
    ngx_http_request_t *r = op->request;             // $ Alert
    ngx_http_core_run_phases(r);
}

/* GOOD: helper with its own CT_PARK_CHECK first */
static void demo_lock_finish(demo_redis_op_t *op)
{
    ngx_http_request_t *r;

    CT_PARK_CHECK(op);
    r = op->request;
    ngx_http_core_run_phases(r);
}

/* BAD: the check sits on one branch only, so it does not dominate */
static void demo_scan_finish(demo_redis_op_t *op, int more)
{
    if (more) {
        CT_PARK_CHECK(op);
    }
    ngx_http_finalize_request(op->request, NGX_DONE); // $ Alert
}

/* GOOD: a NULL test and a clear read no request memory */
static void demo_detach(demo_redis_op_t *op)
{
    if (op->request == NULL) {
        return;
    }
    op->request = NULL;
}

/* ---- read handlers, installed three ways ---- */

/* installed as c->read->handler */
static void demo_read_get(ngx_event_t *rev)
{
    ngx_connection_t *c = rev->data;
    demo_redis_op_t *op = c->data;

    demo_get_finish(op);
    demo_detach(op);
}

/* installed as op->read_handler */
static void demo_read_lock(ngx_event_t *rev)
{
    ngx_connection_t *c = rev->data;
    demo_redis_op_t *op = c->data;

    demo_lock_finish(op);
    ngx_log_it(op->request->connection->log, 0);    // $ Alert
}

/* passed for a parameter named read_handler */
static void demo_read_scan(ngx_event_t *rev)
{
    ngx_connection_t *c = rev->data;
    demo_redis_op_t *op = c->data;

    demo_scan_finish(op, 1);
}

/* memcached-style op (struct tag *_op_s), handler chosen by a ternary */
static void demo_mc_read(ngx_event_t *rev)
{
    ngx_connection_t *c = rev->data;
    struct demo_mc_op_s *op = c->data;

    ngx_http_core_run_phases(op->request);           // $ Alert
}

/* GOOD: guarded directly in the handler */
static void demo_mc_read_checked(ngx_event_t *rev)
{
    ngx_connection_t *c = rev->data;
    struct demo_mc_op_s *op = c->data;

    CT_PARK_CHECK(op);
    ngx_http_core_run_phases(op->request);
}

/* GOOD: not reached from any read handler (a write-side callback) */
static void demo_write_side(demo_redis_op_t *op)
{
    ngx_http_core_run_phases(op->request);
}

/* GOOD: a read handler touching a non-op struct's request field */
static void demo_read_ctx(ngx_event_t *rev)
{
    demo_ctx_t *ctx = rev->data;

    ngx_http_core_run_phases(ctx->request);
}

void demo_wire(ngx_connection_t *c, demo_redis_op_t *op, int mc, int checked)
{
    c->read->handler = demo_read_get;
    op->read_handler = demo_read_lock;
    demo_install(demo_read_scan);
    c->read->handler = mc ? (checked ? demo_mc_read_checked : demo_mc_read) : demo_read_ctx;
    c->write->handler = (ngx_event_handler_pt) 0;
    demo_write_side(op);
}
