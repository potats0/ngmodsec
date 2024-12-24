#include "ddebug.h"
#include "ngx_config.h"
#include "ngx_http.h"
#include "ngx_http_modsecurity_runtime.h"
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_int_t ngx_http_modsecurity_body_filter(ngx_http_request_t *r,
                                                  ngx_chain_t *in) {
  MLOGD("entering modsecurity body filter");

#ifdef WAF
  if (is_bypass(r, CONF1_NEW_SIGN_ENGINE) == WAF_ENABLE) {
    return ngx_http_next_body_filter(r, in);
  }

  ngx_http_core_srv_conf_t *cscf =
      ngx_http_get_module_srv_conf(r, ngx_http_core_module);
  ngx_uint_t ngx_server_id = cscf->server_conf_id;

  waf_sign_template_t *set = NULL;
  set = (waf_sign_template_t *)wafconf_general_conf_get_by_server_id(
      ngx_server_id, CONF2_VIRTUAL_SITE_SUB_EVENT);

  /* 云端只引用自定义模板情况 */
  if (NULL == set) {
    set = (waf_sign_template_t *)wafconf_general_conf_get_by_server_id(
        ngx_server_id, CONF2_VIRTUAL_SITE_SUB_CUSTOM_EVENT);
  }
  if (NULL == set) {
    return ngx_http_next_body_filter(r, in);
  }

#endif
  ngx_http_modsecurity_ctx_t *usrdata = ngx_http_modsecurity_get_ctx(r);
  // if (usrdata == NULL) {
  //   return ngx_http_next_body_filter(r, in);
  // }
  usrdata->request = r;
#ifdef WAF
  usrdata->proto_var_id = NGX_VAR_RSP_BODY;

  for (cl = in; cl; cl = cl->next) {
    b = cl->buf;
    len = ngx_buf_size(b);
    if (len <= 0) {
      continue;
    }
    if (r->upstream && r->upstream->conf &&
        usrdata->rsp_detect_len > r->upstream->conf->proxy_detect_body_size) {
      return ngx_http_next_body_filter(r, in);
    }
    usrdata->rsp_detect_len += len;

    new_sign_engin_scan(b->pos, len, usrdata);
  }
#endif
  return ngx_http_next_body_filter(r, in);
}

ngx_int_t ngx_http_modsecurity_body_filter_init() {
  ngx_http_next_body_filter = ngx_http_top_body_filter;
  ngx_http_top_body_filter = ngx_http_modsecurity_body_filter;
  return NGX_OK;
}
