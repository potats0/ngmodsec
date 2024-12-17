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

// 测试简单的AND组合
TEST_CASE(simple_and) {
    const char* rule_str = "rule 1000 http.uri contains \"test\" and http.uri contains \"123\";";
    sign_rule_mg_t* rule_mg = parse_rule_string(rule_str);
    ASSERT(rule_mg != NULL, "Rule parsing failed");
    ASSERT(rule_mg->max_rule_id == 1000, "Rule ID mismatch");
    
    // 检查规则掩码
    ASSERT(rule_mg->rule_masks[1000].sub_rules_count == 1, "Sub rules count mismatch");
    ASSERT(get_rule_and_mask(&rule_mg->rule_masks[1000], 0) == 0x3, "AND mask mismatch");
    ASSERT(get_rule_not_mask(&rule_mg->rule_masks[1000], 0) == 0, "NOT mask mismatch");
    
    cleanup_rule_mg(rule_mg);
    passed_tests++;
}

// 测试复杂的AND/OR组合
TEST_CASE(complex_and_or) {
    const char* rule_str = "rule 1000 (http.uri contains \"test\" and http.uri contains \"123\") or "
                          "(http.uri contains \"abc\" and http.uri contains \"xyz\");";
    sign_rule_mg_t* rule_mg = parse_rule_string(rule_str);
    ASSERT(rule_mg != NULL, "Rule parsing failed");
    ASSERT(rule_mg->max_rule_id == 1000, "Rule ID mismatch");
    
    // 检查规则掩码
    ASSERT(rule_mg->rule_masks[1000].sub_rules_count == 1, "Sub rules count mismatch");
    ASSERT(get_rule_and_mask(&rule_mg->rule_masks[1000], 0) == 0xF, "First sub-rule AND mask mismatch");  
    ASSERT(get_rule_not_mask(&rule_mg->rule_masks[1000], 0) == 0, "NOT mask mismatch");
    
    cleanup_rule_mg(rule_mg);
    passed_tests++;
}

// 测试带有NOT条件的规则
TEST_CASE(not_condition) {
    const char* rule_str = "rule 1000 http.uri contains \"test\" and not http.uri contains \"123\";";
    sign_rule_mg_t* rule_mg = parse_rule_string(rule_str);
    ASSERT(rule_mg != NULL, "Rule parsing failed");
    ASSERT(rule_mg->max_rule_id == 1000, "Rule ID mismatch");
    
    // 检查规则掩码
    ASSERT(rule_mg->rule_masks[1000].sub_rules_count == 1, "Sub rules count mismatch");
    ASSERT(get_rule_and_mask(&rule_mg->rule_masks[1000], 0) == 0x3, "AND mask mismatch");
    ASSERT(get_rule_not_mask(&rule_mg->rule_masks[1000], 0) == 0x2, "NOT mask mismatch");
    
    cleanup_rule_mg(rule_mg);
    passed_tests++;
}

// 测试带有Hyperscan标志的规则
TEST_CASE(hyperscan_flags) {
    const char* rule_str = "rule 1000 http.uri matches \"test.*\" /i /m /s;";
    sign_rule_mg_t* rule_mg = parse_rule_string(rule_str);
    ASSERT(rule_mg != NULL, "Rule parsing failed");
    ASSERT(rule_mg->max_rule_id == 1000, "Rule ID mismatch");
    
    // 检查规则掩码
    ASSERT(rule_mg->rule_masks[1000].sub_rules_count == 1, "Sub rules count mismatch");
    
    // 检查Hyperscan标志
    string_pattern_t* pattern = get_pattern_by_content(rule_mg, "test.*");
    ASSERT(pattern != NULL, "Pattern not found");
    ASSERT(pattern->hs_flags & HS_FLAG_CASELESS, "Caseless flag not set");
    ASSERT(pattern->hs_flags & HS_FLAG_MULTILINE, "Multiline flag not set");
    ASSERT(pattern->hs_flags & HS_FLAG_DOTALL, "Dotall flag not set");
    
    cleanup_rule_mg(rule_mg);
    passed_tests++;
}

// 测试带有PCRE和标志的规则
TEST_CASE(pcre_with_flags) {
    const char* rule_str = "rule 1000 http.uri matches \"test.*\" /i /m;";
    sign_rule_mg_t* rule_mg = parse_rule_string(rule_str);
    ASSERT(rule_mg != NULL, "Rule parsing failed");
    ASSERT(rule_mg->max_rule_id == 1000, "Rule ID mismatch");
    
    // 检查规则掩码
    ASSERT(rule_mg->rule_masks[1000].sub_rules_count == 1, "Sub rules count mismatch");
    
    // 检查Hyperscan标志
    string_pattern_t* pattern = get_pattern_by_content(rule_mg, "test.*");
    ASSERT(pattern != NULL, "Pattern not found");
    ASSERT(pattern->hs_flags & HS_FLAG_CASELESS, "Caseless flag not set");
    ASSERT(pattern->hs_flags & HS_FLAG_MULTILINE, "Multiline flag not set");
    
    cleanup_rule_mg(rule_mg);
    passed_tests++;
}

int main() {
    TEST_SUITE_BEGIN();

    RUN_TEST(simple_and);
    RUN_TEST(complex_and_or);
    RUN_TEST(hyperscan_flags);
    RUN_TEST(not_condition);
    RUN_TEST(pcre_with_flags);

    TEST_SUITE_END();
}
