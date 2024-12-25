#include "ngx_config.h"
#include "ngx_http.h"
#include "ngx_vs_modsec_runtime.h"

ngx_int_t ngx_http_modsecurity_precontent_handler(ngx_http_request_t *r) {
    MLOGD("Entering precontent phase handler");
    ngx_vs_modsec_ctx_t *ctx = ngx_http_modsecurity_get_ctx(r);
    if (ctx == NULL) {
        // 内存耗尽，相当于Bypass
        return NGX_DECLINED;
    }

    DO_CHECK_VARS(r->uri, HTTP_VAR_URI);
    DO_CHECK_VARS(r->unparsed_uri, HTTP_VAR_UNPARSED_URI);

    DO_CHECK_HEADER_VARS(host, HTTP_VAR_HOST);

    parse_get_args(r);

    MLOGD("Starting to process headers");

    ITERATE_NGX_LIST(&r->headers_in.headers.part, header, ngx_table_elt_t,
                     { CHECK_HTTP_PARAM_MATCH(header->key, header->value, sign_rule_mg->headers_match_context, ctx); });

    MLOGD("Finished processing headers");

    // 放在结尾，准备上报日志
    traverse_rule_hits(ctx->rule_hit_rbtree);
    MLOGD("Exiting precontent phase handler");
    return NGX_DECLINED;
}

ngx_int_t ngx_http_modsecurity_precontent_init(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /* 注册 precontent phase handler */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_modsecurity_precontent_handler;
    return NGX_OK;
}