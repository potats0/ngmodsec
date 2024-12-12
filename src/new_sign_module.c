// SPDX-License-Identifier: Proprietary
/*
 * VenusGroup (Beijing) Information Technology Co., Ltd.
 * Copyright (c) 2023 , All rights reserved.
 *
 */
#include "new_sign.h"
#include <hs/hs_runtime.h>
#ifdef WAF
#include "ngx_http_anti_crawler_module.h"
#include "ngx_http_is_bypass.h"
#include "ngx_protovar_pub.h"
#include "vs_sign_conf.h"
#endif

sign_rule_mg_t *sign_rule_mg = NULL;
hs_scratch_t *scratch[NGX_VAR_MAX];

static ngx_http_output_body_filter_pt ngx_http_next_body_filter;
static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

extern ngx_int_t custom_sign_checker(ngx_http_request_t *r);

void new_sign_alloc_scratch(sign_rule_mg_t *mg) {
  for (ngx_uint_t i = 0; i < NGX_VAR_MAX; i++) {
    if (mg->string_match_context_array && mg->string_match_context_array[i]) {
      hs_database_t *db = mg->string_match_context_array[i]->db;
      if (db == NULL) {
        scratch[i] = NULL;
        continue;
      }
      if (hs_alloc_scratch(db, &(scratch[i])) != HS_SUCCESS) {
        hs_free_scratch(scratch[i]);
        scratch[i] = NULL;
      }
    }
  }
}

void new_sign_rule_reload() {
#ifdef WAF
  sign_rule_mg = wafconf_conf_get_by_index(CONF1_NEW_SIGN_ENGINE, 1);
#else
  sign_rule_mg = NULL;
#endif
  if (sign_rule_mg == NULL) {
    return;
  }
  for (ngx_uint_t i = 0; i < NGX_VAR_MAX; i++) {
    if (scratch[i] != NULL) {
      hs_free_scratch(scratch[i]);
      scratch[i] = NULL;
    }
  }
  new_sign_alloc_scratch(sign_rule_mg);

  return;
}

static ngx_int_t __attribute__((unused))
ngx_new_sign_process_init(ngx_cycle_t *cycle) {
  // 查找共享内存 给 sign_rule_mg赋值
  // 创建每个进程的scratch空间
#ifdef WAF
  sign_rule_mg = wafconf_conf_get_by_index(CONF1_NEW_SIGN_ENGINE, 1);
#else
  sign_rule_mg = NULL;
#endif

  if (sign_rule_mg == NULL) {
    LOGN(cycle->log, "enter new_sign process init");
    return NGX_OK;
  }

  new_sign_alloc_scratch(sign_rule_mg);

  LOGN(cycle->log, "enter new_sign process init OK");

  return NGX_OK;
}

static void __attribute__((unused))
ngx_new_sign_process_exit(ngx_cycle_t *cycle) {
  // 释放sign_rule_mg 内存
  // 释放每个进程的scarach空间
  LOGN(cycle->log, "new_sign process exit");
}

static ngx_int_t ngx_new_sign_module_init(ngx_cycle_t *cycle) {
  LOGN(cycle->log, "enter ngx_new_sign_module_init");

  return NGX_OK;
}

static void __attribute__((unused))
ngx_new_sign_exit_master(ngx_cycle_t *cycle) {
  LOGN(cycle->log, "enter ngx_new_sign_exit_master");
}

static inline hs_search_userdata_t *
ngx_http_new_sign_get_usrdata(ngx_http_request_t *r) {

  hs_search_userdata_t *usrdata =
      ngx_http_get_module_ctx(r, ngx_http_new_sign_module);
  if (usrdata == NULL) {
    usrdata = ngx_pcalloc(r->pool, sizeof(hs_search_userdata_t));
    if (usrdata == NULL) {
      return NULL;
    }
    ngx_http_set_ctx(r, usrdata, ngx_http_new_sign_module);
  }

  return usrdata;
}

static ngx_int_t __attribute__((unused))
new_sign_check_request_body(ngx_http_request_t *r,
                            hs_search_userdata_t *usrdata) {
#ifdef WAF
  vs_proto_var_t *var = get_protovar(r, NGX_VAR_REQ_BODY);
  if (var) {
    usrdata->proto_var_id = NGX_VAR_REQ_BODY;
    new_sign_engin_scan((char *)(var->un.p), var->len, usrdata);
  }
#endif
  return NGX_OK;
}

static ngx_int_t predef_sign_chekcer(ngx_http_request_t *r) {
#ifdef WAF
  if (is_bypass(r, CONF1_NEW_SIGN_ENGINE) == WAF_ENABLE &&
      is_bypass(r, CONF3_ACL_SUB_ANT_CRAWLER) == WAF_ENABLE) {
    return NGX_DECLINED;
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

  if (NULL == set && !is_anti_crawler_enable(r)) {
    return NGX_DECLINED;
  }
#endif
  hs_search_userdata_t *usrdata = ngx_http_new_sign_get_usrdata(r);
  if (usrdata == NULL) {
    return NGX_DECLINED;
  }
  usrdata->r = r;

  // NGINX_CHECK_HEAD_STR(r->method_name, NGX_VAR_METHOD);
  //    NGINX_CHECK_HEAD_VALUE(r->http_version, NGX_VAR_HTTP_VERSION);
  // NGINX_CHECK_HEAD_STR(r->request_line, NGX_VAR_REQUEST_LINE);

  // NGINX_CHECK_HEAD_STR(r->unparsed_uri, NGX_VAR_UNPARSED_URI);

  // vs_url_vars_t *url_vars = get_url_vars(r);
  // if (url_vars) {
  //   NGINX_CHECK_URL_VARS(url_vars->unparse_path, NGX_VAR_UNPARSED_PATH);
  //   NGINX_CHECK_URL_VARS(url_vars->unparse_args, NGX_VAR_UNPARSED_ARGS);
  //   NGINX_CHECK_URL_VARS(url_vars->url, NGX_VAR_URL);
  //   NGINX_CHECK_URL_VARS(url_vars->url_path, NGX_VAR_URL_PATH);
  //   NGINX_CHECK_URL_VARS(url_vars->url_args, NGX_VAR_URL_ARGS);
  // }

  // NGINX_CHECK_HEAD_ARRAY(r->headers_in.cookies, NGX_VAR_COOKIE);

  // NGINX_CHECK_HEAD_VALUE(r->headers_in.host, NGX_VAR_HOST);
  // NGINX_CHECK_HEAD_VALUE(r->headers_in.connection, NGX_VAR_CONNECTION);
  // NGINX_CHECK_HEAD_VALUE(r->headers_in.user_agent, NGX_VAR_USERAGENT);
  // NGINX_CHECK_HEAD_VALUE(r->headers_in.referer, NGX_VAR_REFERER);
  // NGINX_CHECK_HEAD_VALUE(r->headers_in.content_length,
  // NGX_VAR_CONTENT_LENGTH0); NGINX_CHECK_HEAD_VALUE(r->headers_in.accept,
  // NGX_VAR_ACCEPT); NGINX_CHECK_HEAD_VALUE(r->headers_in.accept_encoding,
  //                        NGX_VAR_ACCEPT_ENCODING);
  // NGINX_CHECK_HEAD_VALUE(r->headers_in.authorization, NGX_VAR_AUTHORIZATION);
  // NGINX_CHECK_HEAD_VALUE(r->headers_in.content_type, NGX_VAR_CONTENT_TYPE0);
  // NGINX_CHECK_HEAD_VALUE(r->headers_in.accept_language,
  //                        NGX_VAR_ACCEPT_LANGUAGE);

  // NGINX_CHECK_HEAD_VALUE(r->headers_in.transfer_encoding,
  //                        NGX_VAR_TRANSFER_ENCODING0);

  new_sign_check_request_body(r, usrdata);

  return NGX_DECLINED;
}

static ngx_int_t new_sign_precontent_phase_handler(ngx_http_request_t *r) {
  predef_sign_chekcer(r);
#ifdef WAF
  custom_sign_checker(r);
#endif
  return NGX_DECLINED;
}

static ngx_int_t predef_sign_response_header_checker(ngx_http_request_t *r) {
#ifdef WAF
  if (is_bypass(r, CONF1_NEW_SIGN_ENGINE) == WAF_ENABLE) {
    return;
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
    return;
  }

  hs_search_userdata_t *usrdata = ngx_http_new_sign_get_usrdata(r);
  if (usrdata == NULL) {
    return;
  }
  usrdata->r = r;
  usrdata->rsp_detect_len = 0;

  NGINX_CHECK_HEAD_STR(r->headers_out.status_line, NGX_VAR_RETCODE);
  NGINX_CHECK_HEAD_ARRAY(r->headers_out.cache_control, NGX_VAR_CACHE_CONTROL1);
  NGINX_CHECK_HEAD_VALUE(r->headers_out.content_encoding,
                         NGX_VAR_CONTENT_ENCODING1);
  NGINX_CHECK_HEAD_STR(r->headers_out.content_type, NGX_VAR_CONTENT_TYPE1);
  NGINX_CHECK_HEAD_VALUE(r->headers_out.location, NGX_VAR_LOCATION);
  //    NGINX_CHECK_HEAD_VALUE(r->headers_out.content_length_n,
  //    NGX_VAR_CONTENT_LENGTH);
  NGINX_CHECK_HEAD_STR(r->headers_out.charset, NGX_VAR_ACCEPT_CHARSET);
  NGINX_CHECK_HEAD_VALUE(r->headers_out.server, NGX_VAR_SERVER);
  NGINX_CHECK_HEAD_VALUE(r->headers_out.etag, NGX_VAR_ETAG);
#endif
  return NGX_DECLINED;
}

static ngx_int_t new_sign_response_header_filter(ngx_http_request_t *r) {
  predef_sign_response_header_checker(r);
#ifdef WAF
  custom_sign_checker(r);
#endif
  return ngx_http_next_header_filter(r);
}

static ngx_int_t new_sign_response_body_filter(ngx_http_request_t *r,
                                               ngx_chain_t *in) {

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
  hs_search_userdata_t *usrdata = ngx_http_new_sign_get_usrdata(r);
  if (usrdata == NULL) {
    return ngx_http_next_body_filter(r, in);
  }
  usrdata->r = r;
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

static ngx_int_t ngx_http_new_sign_init(ngx_conf_t *cf) {
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cmcf;

  ngx_http_next_body_filter = ngx_http_top_body_filter;
  ngx_http_top_body_filter = new_sign_response_body_filter;
  ngx_http_next_header_filter = ngx_http_top_header_filter;
  ngx_http_top_header_filter = new_sign_response_header_filter;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
  if (!h) {
    return NGX_ERROR;
  }
  *h = new_sign_precontent_phase_handler;

  return NGX_OK;
}

static ngx_command_t new_sign_commands[] = {ngx_null_command};

static ngx_http_module_t new_sign_module_ctx = {
    NULL,                   /* preconfiguration */
    ngx_http_new_sign_init, /* postconfiguration */
    NULL,                   /* create main configuration */
    NULL,                   /* init main configuration */
    NULL,                   /* create server configuration */
    NULL,                   /* merge server configuration */
    NULL,                   /* create location configuration */
    NULL                    /* merge location configuration */
};

ngx_module_t ngx_http_new_sign_module = {
    NGX_MODULE_V1,
    &new_sign_module_ctx,      /* module context */
    new_sign_commands,         /* module directives */
    NGX_HTTP_MODULE,           /* module type */
    NULL,                      /* init master */
    ngx_new_sign_module_init,  /* init module */
    ngx_new_sign_process_init, /* init process */
    NULL,                      /* init thread */
    NULL,                      /* exit thread */
    NULL,                      /* exit process */
    NULL,                      /* exit master */
    NGX_MODULE_V1_PADDING};
