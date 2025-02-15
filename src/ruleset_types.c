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

#include "ruleset_types.h"

#include <hs/hs.h>
#include <stdint.h>
#include <stdio.h>

#include "rule_parser/pattern_converter.h"


int compile_hyperscan_database(string_match_context_t *ctx) {
        if (!ctx || !ctx->string_patterns_list ||
            ctx->string_patterns_num <= 0) {
                fprintf(stderr, "Invalid context or empty patterns list\n");
                return -1;
        }

        // 准备模式数组和标志数组
        const char **patterns =
            malloc(ctx->string_patterns_num * sizeof(char *));
        unsigned int *flags =
            malloc(ctx->string_patterns_num * sizeof(unsigned int));
        unsigned int *ids =
            g_waf_rule_malloc(ctx->string_patterns_num * sizeof(unsigned int));

        if (!patterns || !flags || !ids) {
                fprintf(stderr,
                        "Failed to allocate memory for Hyperscan "
                        "compilation\n");
                free(patterns);
                free(flags);
                g_waf_rule_free(ids);
                return -1;
        }

        // 填充数组
        for (uint32_t i = 0; i < ctx->string_patterns_num; i++) {
                patterns[i] = ctx->string_patterns_list[i].string_pattern;
                // 使用 get_hyperscan_flags 获取标志位
                flags[i] =
                    get_hyperscan_flags(ctx->string_patterns_list[i].hs_flags) |
                    HS_FLAG_SOM_LEFTMOST;
                ids[i] = i; // 使用索引作为ID
        }

        // 编译数据库
        hs_compile_error_t *compile_err = NULL;
        if (hs_compile_multi(patterns, flags, ids, ctx->string_patterns_num,
                             HS_MODE_BLOCK, NULL, &ctx->db,
                             &compile_err) != HS_SUCCESS) {
                if (compile_err) {
                        fprintf(stderr, "Failed to compile patterns: %s\n",
                                compile_err->message);
                        hs_free_compile_error(compile_err);
                }
                free(patterns);
                free(flags);
                g_waf_rule_free(ids);
                return -1;
        }

        // 保存ID数组以供后续使用
        if (ctx->string_ids) {
                g_waf_rule_free(ctx->string_ids);
        }
        ctx->string_ids = ids; // 转移所有权

        // 清理
        free(patterns);
        free(flags);

        printf("Successfully compiled %d patterns into Hyperscan database\n",
               ctx->string_patterns_num);
        return 0;
}


int compile_all_hyperscan_databases(sign_rule_mg_t *rule_mg) {
        if (!rule_mg || !rule_mg->string_match_context_array) {
                fprintf(stderr, "Invalid rule manager or context array\n");
                return -1;
        }

        // 编译普通的string_match_context数组
        for (int i = 0; i < HTTP_VAR_MAX; i++) {
                string_match_context_t *ctx =
                    rule_mg->string_match_context_array[i];
                if (ctx) {
                        if (compile_hyperscan_database(ctx) != 0) {
                                fprintf(stderr,
                                        "Failed to compile Hyperscan database "
                                        "for context %d\n",
                                        i);
                                return -1;
                        }
                }
        }

        // 编译GET参数的hash表
        if (rule_mg->get_match_context) {
                hash_pattern_item_t *current, *tmp;
                HASH_ITER(hh, rule_mg->get_match_context, current, tmp) {
                        string_match_context_t *ctx = &current->context;
                        if (compile_hyperscan_database(ctx) != 0) {
                                fprintf(stderr,
                                        "Failed to compile Hyperscan database "
                                        "for GET arg %s\n",
                                        current->key);
                                return -1;
                        }
                }
        }

        // 编译HEADER参数的hash表
        if (rule_mg->headers_match_context) {
                hash_pattern_item_t *current, *tmp;
                HASH_ITER(hh, rule_mg->headers_match_context, current, tmp) {
                        string_match_context_t *ctx = &current->context;
                        if (compile_hyperscan_database(ctx) != 0) {
                                fprintf(stderr,
                                        "Failed to compile Hyperscan database "
                                        "for HEADER arg %s\n",
                                        current->key);
                                return -1;
                        }
                }
        }

        return 0;
}
