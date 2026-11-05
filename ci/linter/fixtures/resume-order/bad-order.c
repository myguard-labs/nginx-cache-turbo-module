static void
bad_order(ngx_http_request_t *r, ngx_connection_t *c)
{
    ngx_http_run_posted_requests(c);
    ngx_http_finalize_request(r, NGX_DONE);
}
