#include "ddebug.h"
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

  // FOR_EACH_HEADER_CHECK("User-Agent", HTTP_VAR_UA);

  parse_get_args(r);

  ngx_list_part_t *part = &r->headers_in.headers.part;
  ngx_table_elt_t *header = part->elts;

  for (size_t i = 0; /* void */; i++) {
    if (i >= part->nelts) {
      if (part->next == NULL) {
        // 链表遍历完毕
        break;
      }

      part = part->next;
      header = part->elts;
      i = 0;
    }

    ngx_str_t key = header[i].key;
    ngx_str_t value = header[i].value;

    MLOGD("Checking HEADERS parameter %V=%V", &key, &value);

    hash_pattern_item_t *item = NULL;
    HASH_FIND(hh, sign_rule_mg->headers_match_context, key.data, key.len, item);

    if (item) {
      string_match_context_t *match_ctx = &item->context;
      ctx->match_context = match_ctx;
      hs_scratch_t *scratch = match_ctx->scratch;

      if (match_ctx && match_ctx->db && scratch) {
        hs_scan(match_ctx->db, (const char *)value.data, value.len, 0, scratch,
                on_match, ctx);
      }
    } else {
      MLOGD("header %V not match any rule", &key);
    }
  }

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