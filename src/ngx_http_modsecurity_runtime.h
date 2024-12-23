#include <ngx_config.h>
#include <ngx_core.h>

#ifndef __NEW_SIGN_H__
#define __NEW_SIGN_H__
#include "ngx_http.h"
#include "ruleset_types.h"
#include <hs/hs_runtime.h>
#include <stdbool.h>
#include <sys/types.h>

/** 每个request 允许记录的最大命中规则条目  **/
#define MAX_HIT_RESULT_NUM 512

/** 记录特征命中时候proto id 、 begin、end 用于log高亮 **/
typedef struct rule_log_unit_s {
  uint8_t proto_var_id; // 命中的协议变量ID
  uint16_t begin;       // 特征起始位置
  uint16_t end;         // 特征结束位置
  char *kv_name;        // 名值对的名
  char *kv_value;       // 名值对的值
} rule_log_unit_t;

// /** 每条规则的命中记录单元 **/
// typedef struct rule_hit_unit_s {
//   struct rb_node node;
//   uint32_t threat_id;
//   uint8_t save_and_bit;       // 保存记录规则命中的bit位
//   uint8_t sum_and_bit;        // 告警所需的总命中bit位
//   ngx_array_t rule_log_array; // 命中记录的始末 用于log
// } rule_hit_unit_t;

// /** 每个request 记录的规则命中情况 **/
// typedef struct rule_hit_context_s {
//   struct rb_root rule_hit_root;
//   uint32_t hit_count;      // 记录的命中规则数量
//   uint32_t save_attribute; // for http 流特征， 提高性能
// } rule_hit_context_t;

typedef struct {
  ngx_rbtree_node_t node;
  int threat_id;               // 命中规则ID
  uint32_t rule_bit_mask;      // 保存记录规则命中的bit位
  uint32_t combined_rule_mask; // 告警所需的总命中bit位
} rule_hit_node_t;

/** 用于匹配过程所需的输入和输出 **/
typedef struct ngx_http_modsecurity_ctx_s {
  string_match_context_t *match_context;
  ngx_rbtree_t *rule_hit_context;
  uint32_t rsp_detect_len;
  ngx_http_request_t *r; // for hit_ctx alloc & log
} ngx_http_modsecurity_ctx_t;

extern void new_sign_engin_scan(void *inputData, unsigned int inputLen,
                                ngx_http_modsecurity_ctx_t *usrdata);

#define DO_CHECK_URL_VARS(VAR, FIELD)                                          \
  do {                                                                         \
    string_match_context_t *match_ctx =                                        \
        sign_rule_mg->string_match_context_array[FIELD];                       \
    ctx->match_context = match_ctx;                                            \
    MLOGD("do check %*s ", VAR.len, VAR.data);                                 \
    if (match_ctx && match_ctx->db && scratch[FIELD]) {                        \
      hs_scan(match_ctx->db, (const char *)VAR.data, VAR.len, 0,               \
              scratch[FIELD], on_match, ctx);                                  \
    }                                                                          \
  } while (0)

#define NGINX_CHECK_HEAD_STR(var, proto_id)                                    \
  do {                                                                         \
    usrdata->proto_var_id = proto_id;                                          \
    new_sign_engin_scan(var.data, var.len, usrdata);                           \
  } while (0)

#define NGINX_CHECK_HEAD_VALUE(var, proto_id)                                  \
  do {                                                                         \
    if (var != NULL) {                                                         \
      ngx_str_t *var_str = &var->value;                                        \
      usrdata->proto_var_id = proto_id;                                        \
      new_sign_engin_scan(var_str->data, var_str->len, usrdata);               \
    }                                                                          \
  } while (0)

#define NGINX_CHECK_HEAD_ARRAY(v_array, proto_id)                              \
  do {                                                                         \
    ngx_table_elt_t **vars = v_array.elts;                                     \
    usrdata->proto_var_id = proto_id;                                          \
    for (ngx_uint_t i = 0; i < v_array.nelts; i++) {                           \
      ngx_str_t *var = &vars[i]->value;                                        \
      new_sign_engin_scan(var->data, var->len, usrdata);                       \
    }                                                                          \
  } while (0)

/** 全局管理数据结构mg **/
extern sign_rule_mg_t *sign_rule_mg;
extern hs_scratch_t *scratch[HTTP_VAR_MAX];

// /** hs所用到的scratch内存 进程启动时分配 **/
// extern hs_scratch_t *scratch[NGX_VAR_MAX];

/** new sign 模块结构 **/
extern ngx_module_t ngx_http_modsecurity_module;

extern int log_2_content(ngx_http_request_t *r, uint32_t threat_id,
                         rule_log_unit_t *log_unit, ngx_array_t *log_array,
                         char *dst);

// Auxiliary functions for logging and debugging
void log_rule_mg_status(sign_rule_mg_t *rule_mg);

ngx_int_t ngx_http_modsecurity_precontent_handler(ngx_http_request_t *r);
ngx_http_modsecurity_ctx_t *ngx_http_modsecurity_get_ctx(ngx_http_request_t *r);

// 初始化
ngx_int_t ngx_http_modsecurity_precontent_init(ngx_conf_t *cf);

ngx_int_t ngx_http_modsecurity_header_filter_init();
ngx_int_t ngx_http_modsecurity_body_filter_init();

// nginx 红黑树相关操作函数
void traverse_rule_hits(ngx_rbtree_t *tree);
// 创建并插入新节点的辅助函数
ngx_int_t insert_rule_hit_node(ngx_rbtree_t *tree, ngx_pool_t *pool,
                               int threat_id, uint32_t rule_bit_mask,
                               uint32_t combined_rule_mask);
// 红黑树节点插入函数
void rule_hit_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
                           ngx_rbtree_node_t *sentinel);

// hyperscan 扫描回调函数
int on_match(unsigned int id, unsigned long long from, unsigned long long to,
             unsigned int flags, void *context);
#endif
