/* the r->main->count++ park keeps the request alive */
static void
fx_noop(ngx_http_request_t *r)
{
    /* r->main->count++; */
    // r->main->count++;
    ngx_log_debug0(0, r->connection->log, 0, "r->main->count++");
}
