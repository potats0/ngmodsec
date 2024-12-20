// SPDX-License-Identifier: Proprietary
/*
 * VenusGroup (Beijing) Information Technology Co., Ltd.
 * Copyright (c) 2023 , All rights reserved.
 *
 */
#include "ddebug.h"
#include "ngx_http_modsecurity_runtime.h"
#include <hs/hs_runtime.h>
#ifdef WAF
#include "ngx_http_anti_crawler_module.h"
#include "ngx_http_is_bypass.h"
#include "ngx_protovar_pub.h"
#include "vs_sign_conf.h"
#endif

sign_rule_mg_t *sign_rule_mg = NULL;
hs_scratch_t *scratch[HTTP_VAR_MAX];

static ngx_http_output_body_filter_pt ngx_http_next_body_filter;
static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static void ngx_http_modsecurity_process_exit(ngx_cycle_t *cycle) {
  MLOGN("waf rule match engine process exit");
}

static ngx_int_t ngx_http_modsecurity_module_init(ngx_cycle_t *cycle) {
  MLOGN("enter ngx_http_modsecurity_module_init");
  return NGX_OK;
}
/**
 * @brief 获取或创建请求上下文中的用户数据
 * @details
 * 该函数负责从请求上下文中获取用户数据，如果不存在则创建新的用户数据结构。
 *          用户数据结构用于存储hyperscan搜索过程中的相关信息。
 *
 * @param r nginx请求结构体指针
 * @return hs_search_userdata_t* 成功返回用户数据指针，失败返回NULL
 */
ngx_http_modsecurity_ctx_t *
ngx_http_modsecurity_get_ctx(ngx_http_request_t *r) {
  MLOGD("Attempting to get user data from request context");

  ngx_http_modsecurity_ctx_t *usrdata =
      ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);
  if (usrdata == NULL) {
    MLOGD("User data not found in context, creating new one");

    usrdata = ngx_pcalloc(r->pool, sizeof(ngx_http_modsecurity_ctx_t));
    if (usrdata == NULL) {
      MLOGD("Failed to allocate memory for user data");
      return NULL;
    }

    ngx_http_set_ctx(r, usrdata, ngx_http_modsecurity_module);
    MLOGD("Successfully created and set new user data in context");
  }

  return usrdata;
}

static ngx_int_t predef_sign_response_header_checker(ngx_http_request_t *r) {
  return NGX_DECLINED;
}

static ngx_int_t new_sign_response_header_filter(ngx_http_request_t *r) {
  predef_sign_response_header_checker(r);
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
  ngx_http_modsecurity_ctx_t *usrdata = ngx_http_modsecurity_get_ctx(r);
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

static ngx_int_t ngx_http_modsecurity_init(ngx_conf_t *cf) {
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cmcf;

  /* 保存并设置 filter chain */
  ngx_http_next_body_filter = ngx_http_top_body_filter;
  ngx_http_top_body_filter = new_sign_response_body_filter;
  ngx_http_next_header_filter = ngx_http_top_header_filter;
  ngx_http_top_header_filter = new_sign_response_header_filter;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  /* 注册 precontent phase handler */
  h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }
  *h = ngx_http_modsecurity_precontent_handler;

  if (sign_rule_mg && sign_rule_mg->string_match_context_array) {
    if (compile_all_hyperscan_databases(sign_rule_mg) != 0) {
      MLOGN("--ERROR compile_all_hyperscan_databases failed \n");
      return NGX_ERROR;
    }
  }
  MLOGN("entering function");
  return NGX_OK;
}

// rule指令处理函数
static char *ngx_http_modsecurity_rule(ngx_conf_t *cf, ngx_command_t *cmd,
                                       void *conf) {
  // ngx_http_modsecurity_loc_conf_t *rmconf = conf;
  ngx_str_t *value;
  char *rules;
  u_char *start, *end;

  if (cf->args->nelts != 2) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid number of arguments in rule directive: %d",
                       cf->args->nelts);
    return NGX_CONF_ERROR;
  }

  value = cf->args->elts;

  // 获取第二个参数（规则字符串）
  start = value[1].data;
  end = start + value[1].len;

  // 分配空间存储规则字符串
  rules = ngx_pnalloc(cf->pool, end - start + 1);
  if (rules == NULL) {
    return NGX_CONF_ERROR;
  }

  // 复制规则内容（不包含单引号）并添加结束符
  ngx_memcpy(rules, start, end - start);
  rules[end - start] = '\0';

  // 如果规则管理器未初始化，先初始化
  if (sign_rule_mg == NULL) {
    sign_rule_mg = ngx_pcalloc(cf->pool, sizeof(sign_rule_mg_t));
    if (sign_rule_mg == NULL) {
      return NGX_CONF_ERROR;
    }

    if (init_rule_mg(sign_rule_mg) != 0) {
      MLOGN("failed to initialize rule manager");
      return NGX_CONF_ERROR;
    }
    MLOGN("rule manager initialized");
  } else {
    MLOGN("rule manager has been obtained");
  }

  // 解析规则字符串
  MLOGN("parsing rule: %s ", rules);
  if (parse_rule_string(rules, sign_rule_mg) != 0) {
    MLOGN("failed to parse rule: %s", rules);
    return NGX_CONF_ERROR;
  }
  MLOGN("rule parsed successfully");

  return NGX_CONF_OK;
}

// 模块指令定义
static ngx_command_t ngx_http_modsecurity_commands[] = {
    {ngx_string("rule"), NGX_HTTP_LOC_CONF | NGX_CONF_ANY,
     ngx_http_modsecurity_rule, NGX_HTTP_LOC_CONF_OFFSET, 0, NULL},
    ngx_null_command};

static ngx_http_module_t ngx_http_modsecurity_module_ctx = {
    NULL,                      /* preconfiguration */
    ngx_http_modsecurity_init, /* postconfiguration */
    NULL,                      /* create main configuration */
    NULL,                      /* init main configuration */
    NULL,                      /* create server configuration */
    NULL,                      /* merge server configuration */
    NULL,                      /* create location configuration */
    NULL                       /* merge location configuration */
};

ngx_module_t ngx_http_modsecurity_module = {
    NGX_MODULE_V1,
    &ngx_http_modsecurity_module_ctx,  /* module context */
    ngx_http_modsecurity_commands,     /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    ngx_http_modsecurity_module_init,  /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    ngx_http_modsecurity_process_exit, /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING};
