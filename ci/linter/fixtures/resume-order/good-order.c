static void
good_order(ngx_http_request_t *r)
{
    ngx_connection_t  *c = r->connection;

    ngx_http_finalize_request(r, NGX_DONE);
    ngx_http_run_posted_requests(c);
}

static void
other(ngx_http_request_t *r)
{
    ngx_http_finalize_request(r, NGX_DONE);
}
