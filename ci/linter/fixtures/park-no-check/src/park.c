static void
fx_park(ngx_http_request_t *r)
{
    cln->handler = fx_detach;
    CT_PARK_ENTER(r, op)
    r->main->count++;
    r->write_event_handler = fx_parked_handler;
}

static void
fx_park_finish(ngx_http_request_t *r)
{
}
