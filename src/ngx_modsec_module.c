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

#include "ngx_modsec_runtime.h"

sign_rule_mg_t *sign_rule_mg = NULL;

/**
 * @brief 为WAF规则匹配引擎分配hyperscan scratch空间
 * @details 该函数负责为hyperscan规则匹配引擎分配scratch空间，scratch是hyperscan
 *          进行模式匹配时必需的临时工作空间。每个线程都需要独立的scratch空间，
 *          以保证线程安全。
 *
 * @param[in] mg WAF规则匹配引擎配置结构体指针
 *
 * @return void 无返回值
 */
void ngx_http_modsecurity_alloc_scratch(sign_rule_mg_t *mg) {
        if (mg == NULL) {
                MLOGE("alloc scratch failed, sign_rule_mg_t is NULL");
                return;
        }

        // 为所有类型的context分配scratch
        ALLOC_HYPERSCAN_SCRATCH_ARRAY(mg->string_match_context_array,
                                      HTTP_VAR_MAX, "string_match");
        ALLOC_HYPERSCAN_SCRATCH_HASH(mg->get_match_context, "GET arg");
        ALLOC_HYPERSCAN_SCRATCH_HASH(mg->headers_match_context, "header");
}

static void ngx_http_modsecurity_process_exit(ngx_cycle_t *cycle) {
        MLOGN("process exit");
        sign_rule_mg_t *mg = sign_rule_mg;

        // 释放所有类型的context的scratch
        FREE_HYPERSCAN_SCRATCH_ARRAY(mg->string_match_context_array,
                                     HTTP_VAR_MAX, "string_match");
        FREE_HYPERSCAN_SCRATCH_HASH(mg->get_match_context, "GET arg");
        FREE_HYPERSCAN_SCRATCH_HASH(mg->headers_match_context, "header");
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
ngx_modsec_ctx_t *ngx_http_modsecurity_get_ctx(ngx_http_request_t *r) {
        MLOGD("Attempting to get user data from request context");

        ngx_modsec_ctx_t *ctx =
            ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);
        if (ctx == NULL) {
                MLOGD("User data not found in context, creating new one");

                ctx = ngx_pcalloc(r->pool, sizeof(ngx_modsec_ctx_t));
                if (ctx == NULL) {
                        MLOGD("Failed to allocate memory for user data");
                        return NULL;
                }

                ngx_http_set_ctx(r, ctx, ngx_http_modsecurity_module);
                MLOGD("Successfully created and set new user data in context");

                ctx->request = r;

                // 初始化红黑树
                ngx_rbtree_t *tree = ngx_palloc(r->pool, sizeof(ngx_rbtree_t));
                ngx_rbtree_node_t *sentinel =
                    ngx_palloc(r->pool, sizeof(ngx_rbtree_node_t));
                ctx->rule_hit_rbtree = tree;

                if (tree == NULL || sentinel == NULL) {
                        MLOGE("ngx_palloc failed, rbtree init failed");
                        return NULL;
                }

                ngx_rbtree_init(tree, sentinel, rule_hit_insert_value);
                MLOGD("rbtree init success");
        }

        return ctx;
}

static ngx_int_t ngx_http_modsecurity_init(ngx_conf_t *cf) {
        if (ngx_http_modsecurity_precontent_init(cf) != NGX_OK) {
                return NGX_ERROR;
        }
        ngx_http_modsecurity_header_filter_init();
        ngx_http_modsecurity_body_filter_init();

        if (sign_rule_mg && sign_rule_mg->string_match_context_array) {
                if (compile_all_hyperscan_databases(sign_rule_mg) != 0) {
                        MLOGE("compile_all_hyperscan_databases failed ");
                        return NGX_ERROR;
                } else {
                        MLOGN("compile_all_hyperscan_databases successfully");
                }
        } else {
                MLOGN(
                    "sign_rule_mg is NULL , compile_all_hyperscan_databases "
                    "failed");
        }

        ngx_http_modsecurity_alloc_scratch(sign_rule_mg);
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
                                   "invalid number of arguments in rule "
                                   "directive: %d",
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
