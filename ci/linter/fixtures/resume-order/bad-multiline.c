static void
bad_multiline(ngx_http_request_t *r, ngx_connection_t *c)
{
    ngx_http_run_posted_requests(
        c);
    if (r->done) {
        return;
    }
}
