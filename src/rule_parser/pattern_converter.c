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
            // 对于 contains，我们设置 HS_FLAG_SOM_LEFTMOST 来获取实际的匹配起始位置
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

char *convert_to_hyperscan_pattern(const char *pattern, operator_type_t op_type) {
    if (!pattern) return NULL;

    char *escaped_pattern = escape_regex_special_chars(pattern);
    if (!escaped_pattern) return NULL;

    size_t escaped_len = strlen(escaped_pattern);
    size_t result_len = escaped_len + 10; // 预留一些额外空间给锚点和修饰符
    char *result = (char *)g_waf_rule_malloc(result_len);

    if (!result) {
        free(escaped_pattern);
        return NULL;
    }

    switch (op_type) {
        case OP_CONTAINS:
            // 对于 contains，我们只需要转义的模式，标志位会处理匹配位置
            snprintf(result, result_len, "%s", escaped_pattern);
            break;

        case OP_MATCHES:
            // 已经是正则表达式，直接使用
            g_waf_rule_free(escaped_pattern); // 释放不需要的escaped_pattern
            g_waf_rule_free(result);          // 释放不需要的result
            return my_strdup(pattern);

        case OP_STARTS_WITH:
            // 添加开始锚点 ^
            snprintf(result, result_len, "^%s", escaped_pattern);
            break;

        case OP_ENDS_WITH:
            // 添加结束锚点 $
            snprintf(result, result_len, "%s$", escaped_pattern);
            break;

        case OP_EQUALS:
            // 添加开始和结束锚点 ^ $
            snprintf(result, result_len, "^%s$", escaped_pattern);
            break;

        default:
            g_waf_rule_free(escaped_pattern);
            g_waf_rule_free(result);
            return NULL;
    }

    g_waf_rule_free(escaped_pattern);
    return result;
}
