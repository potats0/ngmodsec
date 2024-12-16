#define TEST_PARSER
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/waf_rule_types.h"
#include "../src/rule_parser.h"

// 全局测试计数器
static int total_tests = 0;
static int passed_tests = 0;

// 测试框架宏定义
#define TEST_SUITE_BEGIN() \
    total_tests = 0; \
    passed_tests = 0;

#define TEST_SUITE_END() \
    printf("\n=== Test Summary ===\n"); \
    printf("Total Tests: %d\n", total_tests); \
    printf("Passed Tests: %d\n", passed_tests); \
    printf("Failed Tests: %d\n", total_tests - passed_tests); \
    return (passed_tests == total_tests) ? 0 : 1;

#define TEST_CASE(name) \
    void test_##name(); \
    struct test_##name { \
        void (*func)(); \
        const char* name; \
    } _test_##name = {test_##name, #name}; \
    void test_##name()

#define RUN_TEST(name) \
    do { \
        printf("\n=== Running Test: %s ===\n", _test_##name.name); \
        total_tests++; \
        _test_##name.func(); \
    } while(0)

#define ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("FAIL: %s\n", message); \
            printf("  at %s:%d\n", __FILE__, __LINE__); \
            return; \
        } \
    } while(0)

#define ASSERT_EQ(expected, actual, message) \
    do { \
        if ((expected) != (actual)) { \
            printf("FAIL: %s\n", message); \
            printf("  Expected: %d\n", (int)(expected)); \
            printf("  Actual: %d\n", (int)(actual)); \
            printf("  at %s:%d\n", __FILE__, __LINE__); \
            return; \
        } \
    } while(0)

#define ASSERT_STR_EQ(expected, actual, message) \
    do { \
        if (strcmp((expected), (actual)) != 0) { \
            printf("FAIL: %s\n", message); \
            printf("  Expected: %s\n", expected); \
            printf("  Actual: %s\n", actual); \
            printf("  at %s:%d\n", __FILE__, __LINE__); \
            return; \
        } \
    } while(0)

// 测试用例
TEST_CASE(simple_and) {
    const char* rule_str = "rule 1000 http.uri content \"a\" and http.uri content \"b\";";
    
    // 解析规则
    sign_rule_mg_t* rule_mg = parse_rule_string(rule_str);
    ASSERT(rule_mg != NULL, "Failed to parse rule");
    ASSERT(rule_mg->string_match_context_array[0] != NULL, "No context created");
    
    // 验证结果
    string_match_context_t* ctx = rule_mg->string_match_context_array[0];
    ASSERT_EQ(2, ctx->string_patterns_num, "Wrong number of patterns");
    
    // 检查第一个pattern
    string_pattern_t* pattern = &ctx->string_patterns_list[0];
    ASSERT_EQ(1, pattern->relation_count, "Pattern 0 wrong relation count");
    ASSERT_EQ(0x1, pattern->relations[0].and_bit, "Pattern 0 wrong and_bit");
    
    // 检查第二个pattern
    pattern = &ctx->string_patterns_list[1];
    ASSERT_EQ(1, pattern->relation_count, "Pattern 1 wrong relation count");
    ASSERT_EQ(0x2, pattern->relations[0].and_bit, "Pattern 1 wrong and_bit");
    
    cleanup_rule_mg(rule_mg);
    passed_tests++;
    printf("PASS: Simple AND Rule test passed\n");
}

TEST_CASE(complex_and_or) {
    const char* rule_str = 
        "rule 1000 http.uri content \"t66y\" and "
        "(http.uri content \"admin\" or http.uri content \"manager\") and "
        "http.uri content \"login.php\";";
    
    // 解析规则
    sign_rule_mg_t* rule_mg = parse_rule_string(rule_str);
    ASSERT(rule_mg != NULL, "Failed to parse rule");
    ASSERT(rule_mg->string_match_context_array[0] != NULL, "No context created");
    
    // 验证结果
    string_match_context_t* ctx = rule_mg->string_match_context_array[0];
    ASSERT_EQ(4, ctx->string_patterns_num, "Wrong number of patterns");
    
    // 验证 t66y pattern
    string_pattern_t* pattern = &ctx->string_patterns_list[3];
    ASSERT_EQ(2, pattern->relation_count, "t66y pattern wrong relation count");
    ASSERT_EQ(0x1, pattern->relations[0].and_bit, "t66y pattern wrong and_bit for sub_rule 1");
    ASSERT_EQ(0x1, pattern->relations[1].and_bit, "t66y pattern wrong and_bit for sub_rule 2");
    
    // 验证 admin pattern
    pattern = &ctx->string_patterns_list[0];
    ASSERT_EQ(1, pattern->relation_count, "admin pattern wrong relation count");
    ASSERT_EQ(0x2, pattern->relations[0].and_bit, "admin pattern wrong and_bit");
    
    // 验证 manager pattern
    pattern = &ctx->string_patterns_list[1];
    ASSERT_EQ(1, pattern->relation_count, "manager pattern wrong relation count");
    ASSERT_EQ(0x4, pattern->relations[0].and_bit, "manager pattern wrong and_bit");
    
    // 验证 login.php pattern
    pattern = &ctx->string_patterns_list[2];
    ASSERT_EQ(2, pattern->relation_count, "login.php pattern wrong relation count");
    ASSERT_EQ(0x1, pattern->relations[0].and_bit, "login.php pattern wrong and_bit for sub_rule 1");
    ASSERT_EQ(0x1, pattern->relations[1].and_bit, "login.php pattern wrong and_bit for sub_rule 2");
    
    cleanup_rule_mg(rule_mg);
    passed_tests++;
    printf("PASS: Complex AND-OR Rule test passed\n");
}

int main() {
    TEST_SUITE_BEGIN();
    
    RUN_TEST(simple_and);
    RUN_TEST(complex_and_or);
    
    TEST_SUITE_END();
}
