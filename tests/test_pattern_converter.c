#include "../src/rule_parser/pattern_converter.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

// 测试宏，用于简化测试代码
#define TEST_PATTERN(name, pattern, op_type, expected) do { \
    printf("Running test: %s\n", name); \
    char* result = convert_to_hyperscan_pattern(pattern, op_type); \
    assert(result != NULL); \
    printf("  Input: %s\n  Expected: %s\n  Got: %s\n", pattern, expected, result); \
    assert(strcmp(result, expected) == 0); \
    free(result); \
    printf("  Test passed!\n\n"); \
} while(0)

// 测试特殊字符转义
void test_escape_regex_special_chars() {
    printf("Testing escape_regex_special_chars...\n");
    
    // 测试基本字符串
    char* result = escape_regex_special_chars("hello");
    assert(strcmp(result, "hello") == 0);
    free(result);
    
    // 测试包含特殊字符的字符串
    result = escape_regex_special_chars("hello.*world");
    assert(strcmp(result, "hello\\.\\*world") == 0);
    free(result);
    
    // 测试所有特殊字符
    result = escape_regex_special_chars("[](){}.*+?^$|\\");
    assert(strcmp(result, "\\[\\]\\(\\)\\{\\}\\.\\*\\+\\?\\^\\$\\|\\\\") == 0);
    free(result);
    
    printf("All escape_regex_special_chars tests passed!\n\n");
}

// 测试 contains 操作符
void test_contains_operator() {
    // 基本字符串
    TEST_PATTERN("Contains basic", 
                "admin", 
                OP_CONTAINS,
                "admin");
    
    // 包含特殊字符
    TEST_PATTERN("Contains with special chars", 
                "admin.*page", 
                OP_CONTAINS,
                "admin\\.\\*page");
}

// 测试 matches 操作符
void test_matches_operator() {
    // 基本正则表达式
    TEST_PATTERN("Matches basic", 
                "^/api/v[0-9]+$", 
                OP_MATCHES,
                "^/api/v[0-9]+$");
    
    // 复杂正则表达式
    TEST_PATTERN("Matches complex", 
                "^/(?:admin|user)/[a-zA-Z0-9_-]+$", 
                OP_MATCHES,
                "^/(?:admin|user)/[a-zA-Z0-9_-]+$");
}

// 测试 starts_with 操作符
void test_starts_with_operator() {
    // 基本前缀
    TEST_PATTERN("Starts with basic", 
                "/api", 
                OP_STARTS_WITH,
                "^/api");
    
    // 包含特殊字符的前缀
    TEST_PATTERN("Starts with special chars", 
                "/api/v1.*", 
                OP_STARTS_WITH,
                "^/api/v1\\.\\*");
}

// 测试 ends_with 操作符
void test_ends_with_operator() {
    // 基本后缀
    TEST_PATTERN("Ends with basic", 
                ".php", 
                OP_ENDS_WITH,
                "\\.php$");
    
    // 包含特殊字符的后缀
    TEST_PATTERN("Ends with special chars", 
                ".*admin", 
                OP_ENDS_WITH,
                "\\.\\*admin$");
}

// 测试 equals 操作符
void test_equals_operator() {
    // 基本完全匹配
    TEST_PATTERN("Equals basic", 
                "/login", 
                OP_EQUALS,
                "^/login$");
    
    // 包含特殊字符的完全匹配
    TEST_PATTERN("Equals with special chars", 
                "/page?id=1", 
                OP_EQUALS,
                "^/page\\?id=1$");
}

// 测试边界情况
void test_edge_cases() {
    // 空字符串
    TEST_PATTERN("Empty string", 
                "", 
                OP_CONTAINS,
                "");
    
    // 只有特殊字符
    TEST_PATTERN("Only special chars", 
                ".*+?", 
                OP_CONTAINS,
                "\\.\\*\\+\\?");
    
    // 非常长的字符串
    char long_str[1024] = {0};
    memset(long_str, 'a', 1023);
    char* result = convert_to_hyperscan_pattern(long_str, OP_CONTAINS);
    assert(result != NULL);
    assert(strlen(result) == 1023);
    free(result);
    printf("Long string test passed!\n");
}

int main() {
    printf("Starting pattern converter tests...\n\n");
    
    // 运行所有测试
    test_escape_regex_special_chars();
    test_contains_operator();
    test_matches_operator();
    test_starts_with_operator();
    test_ends_with_operator();
    test_equals_operator();
    test_edge_cases();
    
    printf("All tests passed successfully!\n");
    return 0;
}
