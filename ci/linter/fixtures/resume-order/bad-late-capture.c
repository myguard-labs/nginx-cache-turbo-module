static void
bad_late_capture(ngx_http_request_t *r)
{
    ngx_connection_t  *c;

    ngx_http_finalize_request(r, NGX_DONE);
    c = r->connection;
    ngx_http_run_posted_requests(c);
}
