static ngx_int_t
fx_walk(ngx_http_request_t *r)
{
    cln->handler = fx_detach;
    CT_PARK_ENTER_SLOT(r, ctx)
    r->main->count++;
    return NGX_DONE;
}

static void
fx_walk_finish(ngx_http_request_t *r)
{
    CT_PARK_CHECK_SLOT(r, ctx, "fx_walk")
}
