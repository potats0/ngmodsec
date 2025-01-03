#include "pattern_converter.h"

#include <stdio.h>
#include <string.h>

#include "ruleset_types.h"

// 需要转义的正则表达式特殊字符
static const char *SPECIAL_CHARS = "[](){}.*+?^$|\\";

char *escape_regex_special_chars(const char *str) {
        if (!str) return NULL;

        size_t len = strlen(str);
        // 预分配足够的空间（每个字符可能都需要转义）
        char *escaped = (char *)g_waf_rule_malloc(len * 2 + 1);
        if (!escaped) return NULL;

        size_t j = 0;
        for (size_t i = 0; i < len; i++) {
                // 检查是否需要转义
                if (strchr(SPECIAL_CHARS, str[i])) {
                        escaped[j++] = '\\';
                }
                escaped[j++] = str[i];
        }
        escaped[j] = '\0';

        // 如果没有转义任何字符，重新分配到实际需要的大小
        if (j == len) {
                char *temp = realloc(escaped, len + 1);
                if (temp) {
                        escaped = temp;
                }
        }

        return escaped;
}

unsigned int get_hyperscan_flags(operator_type_t op_type) {
        unsigned int flags = 0;
        switch (op_type) {
                case OP_CONTAINS:
                        // 对于 contains，我们设置 HS_FLAG_SOM_LEFTMOST
                        // 来获取实际的匹配起始位置
                        flags = HS_FLAG_SOM_LEFTMOST;
                        break;
                case OP_MATCHES:
                        // 对于正则表达式匹配，我们也需要 SOM
                        flags = HS_FLAG_SOM_LEFTMOST;
                        break;
                default:
                        break;
        }
        return flags;
}

char *convert_to_hyperscan_pattern(const char *pattern, operator_type_t op_type,
                                   const substr_range_t *range) {
        if (!pattern) return NULL;

        char *escaped_pattern = escape_regex_special_chars(pattern);
        if (!escaped_pattern) return NULL;

        // 第一步：处理操作符逻辑
        size_t escaped_len = strlen(escaped_pattern);
        size_t result_len = escaped_len + 10; // 初始预留空间
        char *intermediate = (char *)g_waf_rule_malloc(result_len);

        if (!intermediate) {
                g_waf_rule_free(escaped_pattern);
                return NULL;
        }

        // 处理原有的操作符逻辑
        switch (op_type) {
                case OP_CONTAINS:
                        snprintf(intermediate, result_len, "%s",
                                 escaped_pattern);
                        break;

                case OP_MATCHES:
                        // 对于matches，使用原始pattern
                        g_waf_rule_free(escaped_pattern);
                        g_waf_rule_free(intermediate);
                        return my_strdup(pattern);

                case OP_STARTS_WITH:
                        snprintf(intermediate, result_len, "^%s",
                                 escaped_pattern);
                        break;

                case OP_ENDS_WITH:
                        snprintf(intermediate, result_len, "%s$",
                                 escaped_pattern);
                        break;

                case OP_EQUALS:
                        snprintf(intermediate, result_len, "^%s$",
                                 escaped_pattern);
                        break;

                default:
                        g_waf_rule_free(escaped_pattern);
                        g_waf_rule_free(intermediate);
                        return NULL;
        }

        g_waf_rule_free(escaped_pattern); // 释放原始的转义pattern

        // 第二步：如果有substring范围，添加位置约束
        if (range && range->start != range->end) {
                // 为前瞻后顾断言预留更多空间
                size_t final_len = strlen(intermediate) + 50;
                char *result = (char *)g_waf_rule_malloc(final_len);
                if (!result) {
                        g_waf_rule_free(intermediate);
                        return NULL;
                }

                if (range->start > range->end) {
                        // 单个位置开始的任意匹配
                        snprintf(result, final_len, "^.{%zu}(%s)", range->start,
                                 intermediate);
                } else {
                        // 范围匹配
                        snprintf(result, final_len, "^.{%zu}(.{0,%zu}%s)",
                                 range->start, // 跳过起始位置前的字符
                                 range->end - range->start -
                                     1,         // 允许的最大范围
                                 intermediate); // 要匹配的模式
                }

                g_waf_rule_free(intermediate);
                return result;
        }

        // 如果没有substring范围，直接返回intermediate结果
        return intermediate;
}
