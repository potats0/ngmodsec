#include "ddebug.h"
#include "ngx_config.h"
#include "ngx_http.h"
#include "ngx_http_modsecurity_runtime.h"
ngx_int_t ngx_http_modsecurity_precontent_handler(ngx_http_request_t *r) {
  MLOGD("Entering precontent phase handler");
  ngx_http_modsecurity_ctx_t *ctx = ngx_http_modsecurity_get_ctx(r);
  if (ctx == NULL) {
    // 内存耗尽，相当于Bypass
    return NGX_DECLINED;
  }
  ctx->r = r;
  MLOGD("Exiting precontent phase handler");
  return NGX_DECLINED;
}