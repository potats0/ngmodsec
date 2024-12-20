#include "ddebug.h"
#include "ngx_config.h"
#include "ngx_http.h"
#include "ngx_http_modsecurity_runtime.h"

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

static int on_match(unsigned int id, unsigned long long from,
                    unsigned long long to, unsigned int flags, void *context) {
  string_match_context_t *match_ctx =
      ((ngx_http_modsecurity_ctx_t *)context)->match_context;
  MLOGN("Matched rule ID: %d (from: %llu, to: %llu)", id, from, to);
  MLOGN("Matched pattern: %s",
        match_ctx->string_patterns_list[id].string_pattern);
  return 0; // Continue matching
}

ngx_int_t ngx_http_modsecurity_precontent_handler(ngx_http_request_t *r) {
  MLOGD("Entering precontent phase handler");
  ngx_http_modsecurity_ctx_t *ctx = ngx_http_modsecurity_get_ctx(r);
  if (ctx == NULL) {
    // 内存耗尽，相当于Bypass
    return NGX_DECLINED;
  }
  ctx->r = r;
  string_match_context_t *match_ctx =
      sign_rule_mg->string_match_context_array[HTTP_VAR_URI];
  ctx->match_context = match_ctx;
  if (match_ctx && match_ctx->db && scratch[HTTP_VAR_URI]) {
    hs_scan(match_ctx->db, (const char *)r->uri.data, r->uri.len, 0,
            scratch[HTTP_VAR_URI], on_match, ctx);
  }
  MLOGD("Exiting precontent phase handler");
  return NGX_DECLINED;
}