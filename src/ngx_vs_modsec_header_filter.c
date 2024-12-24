#include "ngx_config.h"
#include "ngx_http.h"
#include "ngx_vs_modsec_runtime.h"

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static ngx_int_t ngx_http_modsecurity_header_filter(ngx_http_request_t *r) {
    MLOGD("entering modsecurity header filter");
    return ngx_http_next_header_filter(r);
}

ngx_int_t ngx_http_modsecurity_header_filter_init() {
    /* 保存并设置 filter chain */

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_modsecurity_header_filter;
    return NGX_OK;
}