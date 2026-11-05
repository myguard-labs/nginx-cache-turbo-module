static void
comment_only(ngx_http_request_t *r, ngx_connection_t *c)
{
    ngx_http_finalize_request(r, NGX_DONE);
    ngx_http_run_posted_requests(c);
    /* r->connection must not be read here: ngx_http_run_posted_requests(r->connection) */
    // r->done is dead too, and so is "r"
}
