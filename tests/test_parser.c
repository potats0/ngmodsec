#define TEST_PARSER
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hs/hs.h>
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

#define ASSERT_NOT_NULL(value, message) \
    if ((value) == NULL) { \
        printf("FAIL: %s\n  at %s:%d\n", message, __FILE__, __LINE__); \
        return; \
    }

string_pattern_t* get_pattern_by_content(sign_rule_mg_t* rule_mg, const char* content) {
    string_match_context_t* ctx = rule_mg->string_match_context_array[0];
    for (int i = 0; i < ctx->string_patterns_num; i++) {
        if (strcmp(ctx->string_patterns_list[i].string_pattern, content) == 0) {
            return &ctx->string_patterns_list[i];
        }
    }
    return NULL;
}

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
    const char* rule_str = "rule 1000 http.uri content \"t66y\" and (http.uri content \"admin\" or http.uri content \"manager\") and http.uri content \"login.php\";";
    sign_rule_mg_t* rule_mg = parse_rule_string(rule_str);
    ASSERT_NOT_NULL(rule_mg, "Rule parsing failed");

    string_match_context_t* ctx = rule_mg->string_match_context_array[0];
    ASSERT_EQ(4, ctx->string_patterns_num, "Wrong number of patterns");
    
    string_pattern_t* pattern;

    // Check t66y pattern
    pattern = get_pattern_by_content(rule_mg, "t66y");
    ASSERT_NOT_NULL(pattern, "t66y pattern not found");
    ASSERT_EQ(1, pattern->relations[0].and_bit, "t66y pattern wrong and_bit for sub_rule 1");
    ASSERT_EQ(0, pattern->is_pcre, "t66y pattern wrong is_pcre");
    ASSERT_EQ(0, pattern->hs_flags, "t66y pattern wrong flags");

    // Check admin pattern
    pattern = get_pattern_by_content(rule_mg, "admin");
    ASSERT_NOT_NULL(pattern, "admin pattern not found");
    ASSERT_EQ(2, pattern->relations[0].and_bit, "admin pattern wrong and_bit");
    ASSERT_EQ(0, pattern->is_pcre, "admin pattern wrong is_pcre");
    ASSERT_EQ(0, pattern->hs_flags, "admin pattern wrong flags");

    // Check manager pattern
    pattern = get_pattern_by_content(rule_mg, "manager");
    ASSERT_NOT_NULL(pattern, "manager pattern not found");
    ASSERT_EQ(4, pattern->relations[0].and_bit, "manager pattern wrong and_bit");
    ASSERT_EQ(0, pattern->is_pcre, "manager pattern wrong is_pcre");
    ASSERT_EQ(0, pattern->hs_flags, "manager pattern wrong flags");

    // Check login.php pattern
    pattern = get_pattern_by_content(rule_mg, "login.php");
    ASSERT_NOT_NULL(pattern, "login.php pattern not found");
    ASSERT_EQ(4, pattern->relations[0].and_bit, "login.php pattern wrong and_bit for sub_rule 1");
    ASSERT_EQ(0, pattern->is_pcre, "login.php pattern wrong is_pcre");
    ASSERT_EQ(0, pattern->hs_flags, "login.php pattern wrong flags");
    
    cleanup_rule_mg(rule_mg);
    passed_tests++;
}

// 测试 Hyperscan 标志位
TEST_CASE(hyperscan_flags) {
    const char* rule_str = 
        "rule 1000 "
        "http.uri content \"test\" /i and "
        "http.uri content \"test2\" /m/s and "
        "http.uri content \"test3\" /f/i;";
    
    // 解析规则
    sign_rule_mg_t* rule_mg = parse_rule_string(rule_str);
    ASSERT(rule_mg != NULL, "Failed to parse rule");
    ASSERT(rule_mg->string_match_context_array[0] != NULL, "No context created");
    
    // 验证结果
    string_match_context_t* ctx = rule_mg->string_match_context_array[0];
    ASSERT_EQ(3, ctx->string_patterns_num, "Wrong number of patterns");
    
    // 检查第一个 pattern (test /i)
    string_pattern_t* pattern = &ctx->string_patterns_list[0];
    ASSERT_STR_EQ("test", pattern->string_pattern, "Pattern 0 wrong content");
    ASSERT_EQ(HS_FLAG_CASELESS, pattern->hs_flags, "Pattern 0 wrong flags");
    ASSERT_EQ(0, pattern->is_pcre, "Pattern 0 wrong is_pcre");
    
    // 检查第二个 pattern (test2 /m/s)
    pattern = &ctx->string_patterns_list[1];
    ASSERT_STR_EQ("test2", pattern->string_pattern, "Pattern 1 wrong content");
    ASSERT_EQ(HS_FLAG_MULTILINE | HS_FLAG_DOTALL, pattern->hs_flags, "Pattern 1 wrong flags");
    ASSERT_EQ(0, pattern->is_pcre, "Pattern 1 wrong is_pcre");
    
    // 检查第三个 pattern (test3 /f/i)
    pattern = &ctx->string_patterns_list[2];
    ASSERT_STR_EQ("test3", pattern->string_pattern, "Pattern 2 wrong content");
    ASSERT_EQ(HS_FLAG_SINGLEMATCH | HS_FLAG_CASELESS, pattern->hs_flags, "Pattern 2 wrong flags");
    ASSERT_EQ(0, pattern->is_pcre, "Pattern 2 wrong is_pcre");
    
    cleanup_rule_mg(rule_mg);
    passed_tests++;
    printf("PASS: Hyperscan flags test passed\n");
}

// 测试 PCRE 模式和 Hyperscan 标志位组合
TEST_CASE(pcre_with_flags) {
    const char* rule_str = 
        "rule 1000 "
        "http.uri pcre \"^test.*\" /i and "
        "http.uri pcre \"\\d+\" /m/s;";
    
    // 解析规则
    sign_rule_mg_t* rule_mg = parse_rule_string(rule_str);
    ASSERT(rule_mg != NULL, "Failed to parse rule");
    ASSERT(rule_mg->string_match_context_array[0] != NULL, "No context created");
    
    // 验证结果
    string_match_context_t* ctx = rule_mg->string_match_context_array[0];
    ASSERT_EQ(2, ctx->string_patterns_num, "Wrong number of patterns");
    
    // 检查第一个 pattern (^test.* /i)
    string_pattern_t* pattern = &ctx->string_patterns_list[0];
    ASSERT_STR_EQ("^test.*", pattern->string_pattern, "Pattern 0 wrong content");
    ASSERT_EQ(HS_FLAG_CASELESS, pattern->hs_flags, "Pattern 0 wrong flags");
    ASSERT_EQ(1, pattern->is_pcre, "Pattern 0 wrong is_pcre");
    
    // 检查第二个 pattern (\d+ /m/s)
    pattern = &ctx->string_patterns_list[1];
    ASSERT_STR_EQ("\\d+", pattern->string_pattern, "Pattern 1 wrong content");
    ASSERT_EQ(HS_FLAG_MULTILINE | HS_FLAG_DOTALL, pattern->hs_flags, "Pattern 1 wrong flags");
    ASSERT_EQ(1, pattern->is_pcre, "Pattern 1 wrong is_pcre");
    
    cleanup_rule_mg(rule_mg);
    passed_tests++;
    printf("PASS: PCRE with flags test passed\n");
}

int main() {
    TEST_SUITE_BEGIN();

    RUN_TEST(simple_and);
    RUN_TEST(complex_and_or);
    RUN_TEST(hyperscan_flags);
    RUN_TEST(pcre_with_flags);

    TEST_SUITE_END();
}
