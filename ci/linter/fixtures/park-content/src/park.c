static ngx_int_t
fx_walk(ngx_http_request_t *r)
{
    cln->handler = fx_detach;
    r->main->count++;
    return NGX_DONE;
}
