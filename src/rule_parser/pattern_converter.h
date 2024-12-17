#ifndef __PATTERN_CONVERTER_H__
#define __PATTERN_CONVERTER_H__

#include <stdlib.h>
#include <string.h>

// 操作符类型枚举
typedef enum {
    OP_CONTAINS = 1,
    OP_MATCHES,
    OP_STARTS_WITH,
    OP_ENDS_WITH,
    OP_EQUALS
} operator_type_t;

/**
 * @brief 将模式字符串转换为Hyperscan兼容的正则表达式
 * @param pattern 原始模式字符串
 * @param op_type 操作符类型
 * @return 转换后的正则表达式字符串，调用者负责释放内存
 */
char* convert_to_hyperscan_pattern(const char* pattern, operator_type_t op_type);

/**
 * @brief 转义正则表达式中的特殊字符
 * @param str 需要转义的字符串
 * @return 转义后的字符串，调用者负责释放内存
 */
char* escape_regex_special_chars(const char* str);

#endif // __PATTERN_CONVERTER_H__
