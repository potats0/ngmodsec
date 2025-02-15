/* 
 * This file is part of [ngmodsec].
 *
 * [ngmodsec] is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * [ngmodsec] is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with [ngmodsec]. If not, see <https://www.gnu.org/licenses/>.
 */

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
        ngx_str_t key;
        ngx_str_t value;
        ngx_str_t decoded;
} ngx_http_arg_t;

typedef struct {
        ngx_rbtree_node_t node;
        uint32_t matched_rule_id;        // 命中规则ID ruleid <<8 | subid
        uint32_t rule_hit_bitmask;       // 保存记录规则命中的bit位
        uint32_t current_request_method; // 当前HTTP请求方法
} rule_hit_record_t;

typedef struct ngx_modsec_ctx_s {
        string_match_context_t *match_context;
        ngx_rbtree_t *rule_hit_rbtree;
        ngx_http_request_t *request; // for hit_ctx alloc & log
} ngx_modsec_ctx_t;

#define DO_CHECK_VARS(VAR, FIELD)                                              \
        do {                                                                   \
                if (VAR.data != NULL && sign_rule_mg != NULL) {                \
                        string_match_context_t *match_ctx =                    \
                            sign_rule_mg->string_match_context_array[FIELD];   \
                        ctx->match_context = match_ctx;                        \
                        MLOGD("do check %*s " #FIELD, VAR.len, VAR.data);      \
                        if (match_ctx && match_ctx->db &&                      \
                            match_ctx->scratch) {                              \
                                hs_scan(match_ctx->db, (const char *)VAR.data, \
                                        VAR.len, 0, match_ctx->scratch,        \
                                        on_match, ctx);                        \
                        } else {                                               \
                                MLOGD(#FIELD " hs db or scratch is NULL");     \
                        }                                                      \
                }                                                              \
        } while (0)

#define DO_CHECK_HEADER_VARS(VAR, FIELD)                                   \
        do {                                                               \
                ngx_str_t _val;                                            \
                if (r->headers_in.VAR) {                                   \
                        _val = r->headers_in.VAR->value;                   \
                        MLOGD("Request " #VAR ": \"%V\"", &_val);          \
                        DO_CHECK_VARS(_val, FIELD);                        \
                } else {                                                   \
                        MLOGD("No " #VAR " header found in the request."); \
                }                                                          \
        } while (0)

#define CHECK_HTTP_PARAM_MATCH(key, value, hash_context, ctx)                  \
        do {                                                                   \
                if (key.len == 0 || value.len == 0) {                          \
                        MLOGD("Invalid GET parameter, key or value is empty"); \
                        continue;                                              \
                }                                                              \
                MLOGD("Checking parameter %V=%V", &(key), &(value));           \
                u_char *lowcase_key = ngx_pnalloc(r->pool, (key).len);         \
                if (lowcase_key == NULL) {                                     \
                        break;                                                 \
                }                                                              \
                ngx_strlow(lowcase_key, (key).data, (key).len);                \
                hash_pattern_item_t *item = NULL;                              \
                HASH_FIND(hh, (hash_context), lowcase_key, (key).len, item);   \
                if (item) {                                                    \
                        string_match_context_t *match_ctx = &item->context;    \
                        (ctx)->match_context = match_ctx;                      \
                        hs_scratch_t *scratch = match_ctx->scratch;            \
                        if (match_ctx && match_ctx->db && scratch) {           \
                                hs_scan(match_ctx->db,                         \
                                        (const char *)(value).data,            \
                                        (value).len, 0, scratch, on_match,     \
                                        (ctx));                                \
                        }                                                      \
                } else {                                                       \
                        MLOGD("parameter %V not match any rule", &(key));      \
                }                                                              \
        } while (0)

#define PROCESS_ARGS(str, ctx, match_context)                                 \
        do {                                                                  \
                ngx_array_t *_args = parse_get_args(&str, r->pool);           \
                if (_args != NULL) {                                          \
                        ngx_http_arg_t *elts = _args->elts;                   \
                        for (size_t i = 0; i < _args->nelts; i++) {           \
                                MLOGD("param key:%V, value:%V", &elts[i].key, \
                                      &elts[i].decoded);                      \
                                CHECK_HTTP_PARAM_MATCH(elts[i].key,           \
                                                       elts[i].decoded,       \
                                                       match_context, ctx);   \
                                DO_CHECK_VARS(elts[i].decoded,                \
                                              HTTP_VAR_ALL_GET_VALUE);        \
                                DO_CHECK_VARS(elts[i].key,                    \
                                              HTTP_VAR_ALL_GET_NAME);         \
                        }                                                     \
                }                                                             \
        } while (0)

// 在 ngx_modsec_runtime.h 中定义宏
#define ITERATE_NGX_LIST(part, item, item_type, code_block)             \
        do {                                                            \
                ngx_list_part_t *_current_part = (part);                \
                item_type *item = _current_part->elts;                  \
                for (size_t _i = 0;;) {                                 \
                        if (_i >= _current_part->nelts) {               \
                                if (_current_part->next == NULL) {      \
                                        break;                          \
                                }                                       \
                                _current_part = _current_part->next;    \
                                item = _current_part->elts;             \
                                _i = 0;                                 \
                                continue;                               \
                        }                                               \
                        item = &((item_type *)_current_part->elts)[_i]; \
                        code_block _i++;                                \
                }                                                       \
        } while (0)

#define ALLOC_SINGLE_SCRATCH(ctx, type_name, id_fmt, ...)                   \
        do {                                                                \
                string_match_context_t *_ctx = (ctx);                       \
                if (_ctx->db == NULL) {                                     \
                        _ctx->scratch = NULL;                               \
                        MLOGE("alloc scratch for " type_name id_fmt         \
                              " failed, hyperscan db is NULL",              \
                              ##__VA_ARGS__);                               \
                } else {                                                    \
                        if (hs_alloc_scratch(_ctx->db, &_ctx->scratch) !=   \
                            HS_SUCCESS) {                                   \
                                MLOGE("alloc scratch for " type_name id_fmt \
                                      " failed",                            \
                                      ##__VA_ARGS__);                       \
                                _ctx->scratch = NULL;                       \
                        }                                                   \
                        MLOGN("alloc scratch for " type_name id_fmt         \
                              " succes"                                     \
                              "s",                                          \
                              ##__VA_ARGS__);                               \
                }                                                           \
        } while (0)

#define FREE_SINGLE_SCRATCH(ctx, type_name, id_fmt, ...)                       \
        do {                                                                   \
                string_match_context_t *_ctx = (ctx);                          \
                if (_ctx->scratch) {                                           \
                        hs_free_scratch(_ctx->scratch);                        \
                        _ctx->scratch = NULL;                                  \
                        MLOGN("free scratch for " type_name id_fmt " success", \
                              ##__VA_ARGS__);                                  \
                }                                                              \
        } while (0)

#define ALLOC_HYPERSCAN_SCRATCH_ARRAY(array, size, type_name)             \
        do {                                                              \
                for (ngx_uint_t i = 0; i < size; i++) {                   \
                        if (array && array[i]) {                          \
                                ALLOC_SINGLE_SCRATCH(array[i], type_name, \
                                                     "[%lu]", i);         \
                        }                                                 \
                }                                                         \
        } while (0)

#define FREE_HYPERSCAN_SCRATCH_ARRAY(array, size, type_name)             \
        do {                                                             \
                for (ngx_uint_t i = 0; i < size; i++) {                  \
                        if (array && array[i]) {                         \
                                FREE_SINGLE_SCRATCH(array[i], type_name, \
                                                    "[%lu]", i);         \
                        }                                                \
                }                                                        \
        } while (0)

#define ALLOC_HYPERSCAN_SCRATCH_HASH(hash_context, type_name)           \
        do {                                                            \
                if (hash_context) {                                     \
                        hash_pattern_item_t *current, *tmp;             \
                        HASH_ITER(hh, hash_context, current, tmp) {     \
                                ALLOC_SINGLE_SCRATCH(&current->context, \
                                                     type_name, " %s",  \
                                                     current->key);     \
                        }                                               \
                }                                                       \
        } while (0)

#define FREE_HYPERSCAN_SCRATCH_HASH(hash_context, type_name)           \
        do {                                                           \
                if (hash_context) {                                    \
                        hash_pattern_item_t *current, *tmp;            \
                        HASH_ITER(hh, hash_context, current, tmp) {    \
                                FREE_SINGLE_SCRATCH(&current->context, \
                                                    type_name, " %s",  \
                                                    current->key);     \
                        }                                              \
                }                                                      \
        } while (0)

#define ALLOC_HYPERSCAN_SCRATCH(context, type_name)                         \
        do {                                                                \
                if (context->type == ARRAY_CONTEXT) {                       \
                        ALLOC_HYPERSCAN_SCRATCH_ARRAY(                      \
                            context->array, context->size, type_name);      \
                } else if (context->type == HASH_CONTEXT) {                 \
                        ALLOC_HYPERSCAN_SCRATCH_HASH(context->hash_context, \
                                                     type_name);            \
                }                                                           \
        } while (0)

#define FREE_HYPERSCAN_SCRATCH(context, type_name)                         \
        do {                                                               \
                if (context->type == ARRAY_CONTEXT) {                      \
                        FREE_HYPERSCAN_SCRATCH_ARRAY(                      \
                            context->array, context->size, type_name);     \
                } else if (context->type == HASH_CONTEXT) {                \
                        FREE_HYPERSCAN_SCRATCH_HASH(context->hash_context, \
                                                    type_name);            \
                }                                                          \
        } while (0)

#if defined(DDEBUG) && (DDEBUG)

#define MLOG(logger, level, fmt, ...) \
        ngx_log_error(level, logger, 0, fmt, ##__VA_ARGS__)

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
ngx_modsec_ctx_t *ngx_http_modsecurity_get_ctx(ngx_http_request_t *r);

// 初始化
ngx_int_t ngx_http_modsecurity_precontent_init(ngx_conf_t *cf);

ngx_int_t ngx_http_modsecurity_header_filter_init();
ngx_int_t ngx_http_modsecurity_body_filter_init();

// nginx 红黑树相关操作函数
void traverse_rule_hits(ngx_rbtree_t *tree);
// 创建并插入新节点的辅助函数
ngx_int_t insert_rule_hit_node(ngx_rbtree_t *tree, ngx_pool_t *pool,
                               u_int32_t threat_id, uint32_t rule_bit_mask,
                               uint32_t method);
// 红黑树节点插入函数
void rule_hit_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
                           ngx_rbtree_node_t *sentinel);

// hyperscan 扫描回调函数
int on_match(unsigned int id, unsigned long long from, unsigned long long to,
             unsigned int flags, void *context);

// 获取请求中的参数
ngx_array_t *parse_get_args(ngx_str_t *queryString, ngx_pool_t *pool);

#endif
