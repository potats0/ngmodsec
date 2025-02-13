#include "ngx_config.h"
#include "ngx_http.h"
#include "ngx_vs_modsec_runtime.h"
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_int_t ngx_http_modsecurity_body_filter(ngx_http_request_t *r,
                                                  ngx_chain_t *in) {
        MLOGD("entering modsecurity body filter");

        ngx_vs_modsec_ctx_t *usrdata = ngx_http_modsecurity_get_ctx(r);

        usrdata->request = r;
        
        return ngx_http_next_body_filter(r, in);
}

ngx_int_t ngx_http_modsecurity_body_filter_init() {
        ngx_http_next_body_filter = ngx_http_top_body_filter;
        ngx_http_top_body_filter = ngx_http_modsecurity_body_filter;
        return NGX_OK;
}
