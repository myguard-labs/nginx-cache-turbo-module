static void
bad_arg(ngx_http_request_t *r)
{
    ngx_http_finalize_request(r, NGX_DONE);
    ngx_http_run_posted_requests(r->connection);
}
