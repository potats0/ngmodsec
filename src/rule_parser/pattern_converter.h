#ifndef __PATTERN_CONVERTER_H__
#define __PATTERN_CONVERTER_H__

#include <hs/hs.h>
#include <stdbool.h>

#include "ruleset_types.h"

// 操作符类型枚举
typedef enum {
        OP_CONTAINS = 1,
        OP_MATCHES,
        OP_STARTS_WITH,
        OP_ENDS_WITH,
        OP_EQUALS,
        OP_IN
} operator_type_t;

// 字符串列表结构定义
typedef struct {
        char **items;
        size_t count;
        size_t capacity;
} string_list_t;

typedef struct {
        size_t start;
        size_t end;
} substr_range_t;

// 为了支持substring
typedef struct {
        http_var_type_t var;  /* 变量名 */
        char *param;          /* 参数名 */
        substr_range_t range; /* 子串范围 */
        bool has_range;       /* 是否有范围 */
} http_var_info_t;

/**
 * @brief 将模式字符串转换为Hyperscan兼容的正则表达式
 * @param pattern 原始模式字符串
 * @param op_type 操作符类型
 * @param range 子串范围
 * @return 转换后的正则表达式字符串，调用者负责使用 g_waf_rule_free
 * 释放返回的内存
 */
char *convert_to_hyperscan_pattern(const char *pattern, operator_type_t op_type,
                                   const substr_range_t *range);

/**
 * @brief 转义正则表达式中的特殊字符
 * @param str 需要转义的字符串
 * @return 转义后的字符串，调用者负责释放内存
 */
char *escape_regex_special_chars(const char *str);

/**
 * @brief 获取操作符对应的 Hyperscan 标志位
 * @param op_type 操作符类型
 * @return Hyperscan 标志位
 */
unsigned int get_hyperscan_flags(operator_type_t op_type);

#endif // __PATTERN_CONVERTER_H__
