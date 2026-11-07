static void
fx_park(ngx_http_request_t *r)
{
    cln->handler = fx_detach;
    r->main->count++;
    r->write_event_handler = fx_parked_handler;
}

static void
fx_park_finish(ngx_http_request_t *r)
{
    CT_PARK_CHECK(r, op, "fx_park", drop)
}
