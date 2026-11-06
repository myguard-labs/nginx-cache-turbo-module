/* Copyright (C) 2026 Thijs Eilander. SPDX-License-Identifier: BSD-2-Clause */
#include "../ngx_stub.h"

/* ---- positive: the 9c32123 shape (CT-RESUME-FINALIZE-UAF) ---- */

/* BAD: run_posted_requests(r->connection) then finalize(r) (redis get_finish) */
void bad_get_finish(ngx_http_request_t *r)
{
    ngx_http_core_run_phases(r);
    ngx_http_run_posted_requests(r->connection);
    ngx_http_finalize_request(r, NGX_DONE);          // $ Alert
}

/* BAD: connection from the timer, posted requests before finalize (cold_wait) */
void bad_cold_wait_timeout(ngx_event_t *ev)
{
    ngx_http_request_t *r = ev->data;
    ngx_connection_t *c = ev->data;

    ngx_http_core_run_phases(r);
    ngx_http_run_posted_requests(c);
    ngx_http_finalize_request(r, NGX_DONE);          // $ Alert
}

/* BAD: an alias of r, which the name-based lint-resume-order.sh misses */
void bad_alias(ngx_http_request_t *r)
{
    ngx_http_request_t *req = r;
    ngx_connection_t *c = r->connection;

    ngx_http_finalize_request(r, NGX_DONE);
    ngx_log_it(req->connection->log, 1);             // $ Alert
    ngx_http_run_posted_requests(c);
}

/* BAD: late capture of the connection after the finalize */
void bad_late_capture(ngx_http_request_t *r)
{
    ngx_connection_t *c;

    ngx_http_finalize_request(r, NGX_DONE);
    c = r->connection;                               // $ Alert
    ngx_http_run_posted_requests(c);
}

/* BAD: a pool captured before the free is destroyed with the request */
void bad_pool_after_free(ngx_http_request_t *r)
{
    ngx_pool_t *pool = r->pool;

    ngx_http_free_request(r, 0);
    (void) ngx_palloc(pool, 16);                     // $ Alert
}

/* BAD: the connection captured up front, used for more than the posted run */
void bad_conn_log_after_terminate(ngx_http_request_t *r)
{
    ngx_connection_t *c = r->connection;

    ngx_http_terminate_request(r, NGX_ERROR);
    ngx_log_it(c->log, 2);                           // $ Alert
}

/* BAD: only one branch returns; the other falls through to the use */
void bad_one_branch(ngx_http_request_t *r, int rc)
{
    if (rc) {
        ngx_http_finalize_request(r, rc);
    }
    ngx_http_core_run_phases(r);                     // $ Alert
}

/* BAD: double finalize */
void bad_double_finalize(ngx_http_request_t *r)
{
    ngx_http_finalize_request(r, NGX_ERROR);
    ngx_http_finalize_request(r, NGX_DONE);          // $ Alert
}

/* ---- negative: the #503 fixed shape and other safe code ---- */

/* GOOD: finalize first, run_posted_requests last on c captured up front */
void good_get_finish(ngx_http_request_t *r)
{
    ngx_connection_t *c = r->connection;

    ngx_http_core_run_phases(r);
    ngx_http_finalize_request(r, NGX_DONE);
    ngx_http_run_posted_requests(c);
}

/* GOOD: walk_finish shape: c read just before the finalize */
void good_walk_finish(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_connection_t *c;

    ngx_log_it(r->connection->log, 0);
    c = r->connection;
    ngx_http_finalize_request(r, rc);
    ngx_http_run_posted_requests(c);
}

/* GOOD: the finalizing branch returns */
ngx_int_t good_return_after(ngx_http_request_t *r, int rc)
{
    if (rc) {
        ngx_http_finalize_request(r, rc);
        return NGX_DONE;
    }
    ngx_http_core_run_phases(r);
    return 0;
}

/* GOOD: r is rebound before the next use (a loop over parked waiters) */
void good_rebind(ngx_http_request_t **reqs, int n)
{
    ngx_http_request_t *r;
    int i;

    for (i = 0; i < n; i++) {
        r = reqs[i];
        ngx_http_core_run_phases(r);
        ngx_http_finalize_request(r, NGX_DONE);
    }
}

/* GOOD: clearing the variable is a write, not a use */
void good_clear(ngx_http_request_t *r)
{
    ngx_http_finalize_request(r, NGX_DONE);
    r = NULL;
    (void) r;
}

/* GOOD: an unrelated request, finalized independently */
void good_unrelated(ngx_http_request_t *r, ngx_http_request_t *other)
{
    ngx_http_finalize_request(other, NGX_DONE);
    ngx_http_core_run_phases(r);
}
