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
    /* The label "fx_park" in comments and outside the macro does not count. */
    CT_PARK_CHECK(r, op, "fx_other", drop) /* "fx_park" */
    CT_PARK_CHECK(r, op, "fx_other", drop) fx_log("fx_park");
}
