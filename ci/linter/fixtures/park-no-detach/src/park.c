static void
fx_park(ngx_http_request_t *r)
{
    r->main->count++;
    r->write_event_handler = fx_parked_handler;
}
