#include <ngx_config.h>
#include <ngx_core.h>

#ifndef __NEW_SIGN_H__
#define __NEW_SIGN_H__
#include <hs/hs_runtime.h>
#include <stdbool.h>
#include <sys/types.h>

#include "ngx_http.h"
#include "ruleset_types.h"

typedef struct {
    ngx_rbtree_node_t node;
    uint32_t matched_rule_id;         // 命中规则ID ruleid <<8 | subid
    uint32_t rule_hit_bitmask;        // 保存记录规则命中的bit位
    uint32_t alert_trigger_bitmask;   // 告警触发所需的总命中bit位
    uint32_t alert_exclusion_bitmask; // 告警所需的非关系bit位
    uint32_t matched_rule_methods;    // 该规则匹配的http请求方法
    uint32_t current_request_method;  // 当前HTTP请求方法
} rule_hit_record_t;

typedef struct ngx_vs_modsec_ctx_s {
    string_match_context_t *match_context;
    ngx_rbtree_t *rule_hit_rbtree;
    ngx_http_request_t *request; // for hit_ctx alloc & log
} ngx_vs_modsec_ctx_t;

#define DO_CHECK_VARS(VAR, FIELD)                                                                   \
    do {                                                                                            \
        if (VAR.data != NULL) {                                                                     \
            string_match_context_t *match_ctx = sign_rule_mg->string_match_context_array[FIELD];    \
            ctx->match_context = match_ctx;                                                         \
            hs_scratch_t *scratch = match_ctx->scratch;                                             \
            MLOGD("do check %*s ", VAR.len, VAR.data);                                              \
            if (match_ctx && match_ctx->db && scratch) {                                            \
                hs_scan(match_ctx->db, (const char *)VAR.data, VAR.len, 0, scratch, on_match, ctx); \
            }                                                                                       \
        }                                                                                           \
    } while (0)

#define CHECK_HTTP_PARAM_MATCH(key, value, hash_context, ctx)                                                 \
    do {                                                                                                      \
        MLOGD("Checking parameter %V=%V", &(key), &(value));                                                  \
        u_char *lowcase_key = ngx_pnalloc(r->pool, (key).len);                                                \
        if (lowcase_key == NULL) {                                                                            \
            break;                                                                                            \
        }                                                                                                     \
        ngx_strlow(lowcase_key, (key).data, (key).len);                                                       \
        hash_pattern_item_t *item = NULL;                                                                     \
        HASH_FIND(hh, (hash_context), lowcase_key, (key).len, item);                                          \
        if (item) {                                                                                           \
            string_match_context_t *match_ctx = &item->context;                                               \
            (ctx)->match_context = match_ctx;                                                                 \
            hs_scratch_t *scratch = match_ctx->scratch;                                                       \
            if (match_ctx && match_ctx->db && scratch) {                                                      \
                hs_scan(match_ctx->db, (const char *)(value).data, (value).len, 0, scratch, on_match, (ctx)); \
            }                                                                                                 \
        } else {                                                                                              \
            MLOGD("parameter %V not match any rule", &(key));                                                 \
        }                                                                                                     \
    } while (0)

// 在 ngx_vs_modsec_runtime.h 中定义宏
#define ITERATE_NGX_LIST(part, item, item_type, code_block) \
    do {                                                    \
        ngx_list_part_t *_current_part = (part);            \
        item_type *item = _current_part->elts;              \
        for (size_t _i = 0;;) {                             \
            if (_i >= _current_part->nelts) {               \
                if (_current_part->next == NULL) {          \
                    break;                                  \
                }                                           \
                _current_part = _current_part->next;        \
                item = _current_part->elts;                 \
                _i = 0;                                     \
                continue;                                   \
            }                                               \
            item = &((item_type *)_current_part->elts)[_i]; \
            code_block _i++;                                \
        }                                                   \
    } while (0)

#if defined(DDEBUG) && (DDEBUG)

#define MLOG(logger, level, fmt, ...) ngx_log_error(level, logger, 0, fmt, ##__VA_ARGS__)

#define MLOGE(fmt, ...) MLOG(ngx_cycle->log, NGX_LOG_ERR, fmt, ##__VA_ARGS__)
#define MLOGW(fmt, ...) MLOG(ngx_cycle->log, NGX_LOG_WARN, fmt, ##__VA_ARGS__)
#define MLOGN(fmt, ...) MLOG(ngx_cycle->log, NGX_LOG_NOTICE, fmt, ##__VA_ARGS__)
#define MLOGD(fmt, ...) MLOG(ngx_cycle->log, NGX_LOG_DEBUG, fmt, ##__VA_ARGS__)

#endif

/** 全局管理数据结构mg **/
extern sign_rule_mg_t *sign_rule_mg;

/** new sign 模块结构 **/
extern ngx_module_t ngx_http_modsecurity_module;

// Auxiliary functions for logging and debugging
void log_rule_mg_status(sign_rule_mg_t *rule_mg);

ngx_int_t ngx_http_modsecurity_precontent_handler(ngx_http_request_t *r);
ngx_vs_modsec_ctx_t *ngx_http_modsecurity_get_ctx(ngx_http_request_t *r);

// 初始化
ngx_int_t ngx_http_modsecurity_precontent_init(ngx_conf_t *cf);

ngx_int_t ngx_http_modsecurity_header_filter_init();
ngx_int_t ngx_http_modsecurity_body_filter_init();

// nginx 红黑树相关操作函数
void traverse_rule_hits(ngx_rbtree_t *tree);
// 创建并插入新节点的辅助函数
ngx_int_t insert_rule_hit_node(ngx_rbtree_t *tree, ngx_pool_t *pool, u_int32_t threat_id, uint32_t rule_bit_mask,
                               uint32_t combined_rule_mask, uint32_t not_rule_mask, uint32_t rule_method,
                               uint32_t method);
// 红黑树节点插入函数
void rule_hit_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

// hyperscan 扫描回调函数
int on_match(unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void *context);

// 获取请求中的参数
void parse_get_args(ngx_http_request_t *r);

#endif
