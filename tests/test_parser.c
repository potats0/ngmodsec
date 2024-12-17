#define TEST_PARSER
#include "../src/rule_parser.h"
#include "../src/waf_rule_types.h"
#include <hs/hs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 全局测试计数器
static int total_tests = 0;
static int passed_tests = 0;

// 测试框架宏定义
#define TEST_SUITE_BEGIN()                                                     \
  total_tests = 0;                                                             \
  passed_tests = 0;

#define TEST_SUITE_END()                                                       \
  printf("\n=== Test Summary ===\n");                                          \
  printf("Total Tests: %d\n", total_tests);                                    \
  printf("Passed Tests: %d\n", passed_tests);                                  \
  printf("Failed Tests: %d\n", total_tests - passed_tests);                    \
  return (passed_tests == total_tests) ? 0 : 1;

#define TEST_CASE(name)                                                        \
  void test_##name();                                                          \
  struct test_##name {                                                         \
    void (*func)();                                                            \
    const char *name;                                                          \
  } _test_##name = {test_##name, #name};                                       \
  void test_##name()

#define RUN_TEST(name)                                                         \
  do {                                                                         \
    printf("\n=== Running Test: %s ===\n", _test_##name.name);                 \
    total_tests++;                                                             \
    _test_##name.func();                                                       \
  } while (0)

#define ASSERT(condition, message)                                             \
  do {                                                                         \
    if (!(condition)) {                                                        \
      printf("FAIL: %s\n", message);                                           \
      printf("  at %s:%d\n", __FILE__, __LINE__);                              \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_EQ(expected, actual, message)                                   \
  do {                                                                         \
    if ((expected) != (actual)) {                                              \
      printf("FAIL: %s\n", message);                                           \
      printf("  Expected: %d\n", (int)(expected));                             \
      printf("  Actual: %d\n", (int)(actual));                                 \
      printf("  at %s:%d\n", __FILE__, __LINE__);                              \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_STR_EQ(expected, actual, message)                               \
  do {                                                                         \
    if (strcmp((expected), (actual)) != 0) {                                   \
      printf("FAIL: %s\n", message);                                           \
      printf("  Expected: %s\n", expected);                                    \
      printf("  Actual: %s\n", actual);                                        \
      printf("  at %s:%d\n", __FILE__, __LINE__);                              \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_NOT_NULL(value, message)                                        \
  if ((value) == NULL) {                                                       \
    printf("FAIL: %s\n  at %s:%d\n", message, __FILE__, __LINE__);             \
    return;                                                                    \
  }

string_pattern_t *get_pattern_by_content(sign_rule_mg_t *rule_mg,
                                         const char *content) {
  string_match_context_t *ctx = rule_mg->string_match_context_array[0];
  for (int i = 0; i < ctx->string_patterns_num; i++) {
    if (strcmp(ctx->string_patterns_list[i].string_pattern, content) == 0) {
      return &ctx->string_patterns_list[i];
    }
  }
  return NULL;
}

// 测试单个 http.uri contains
TEST_CASE(single_contains) {
    const char *rule_str = "rule 1000 http.uri contains \"a\";";
    sign_rule_mg_t *rule_mg = parse_rule_string(rule_str);
    ASSERT(rule_mg != NULL, "Rule parsing failed");
    
    // 验证规则计数和ID
    ASSERT(rule_mg->rules_count == 1, "Expected one rule");
    ASSERT(rule_mg->rule_ids != NULL, "Rule IDs array is NULL");
    ASSERT(rule_mg->rule_ids[0] == 1000, "Wrong rule ID");
    ASSERT(rule_mg->max_rules > 1000, "Max rules too small");

    // 检查规则掩码数组是否分配
    ASSERT(rule_mg->rule_masks != NULL, "Rule masks array is NULL");

    // 应该只有一个子规则
    ASSERT(rule_mg->rule_masks[1000].and_masks[0] == 0x1, "Wrong AND mask for sub rule");

    // 检查字符串匹配上下文
    ASSERT(rule_mg->string_match_context_array != NULL, "String match context array is NULL");
    ASSERT(rule_mg->string_match_context_array[0] != NULL, "First string match context is NULL");
    ASSERT(strcmp(rule_mg->string_match_context_array[0]->proto_var_name, "http.uri") == 0,
           "Wrong protocol variable name");

    cleanup_rule_mg(rule_mg);
    passed_tests++;
}

// 打印规则管理器状态的辅助函数
void print_rule_mg_state(sign_rule_mg_t *rule_mg, uint32_t rule_id) {
    printf("\n=== Rule Management State ===\n");
    printf("Total Rules: %u\n", rule_mg->rules_count);
    printf("Rule IDs: ");
    for (uint32_t i = 0; i < rule_mg->rules_count; i++) {
        printf("%u ", rule_mg->rule_ids[i]);
    }
    printf("\n");
    
    printf("\nChecking Rule ID: %u\n", rule_id);
    printf("Sub Rules Count: %u\n", rule_mg->rule_masks[rule_id].sub_rules_count);

    // 打印子规则掩码
    for (int i = 0; i < rule_mg->rule_masks[rule_id].sub_rules_count; i++) {
        printf("\nSub Rule %d:\n", i);
        printf("  AND Mask: 0x%x\n", rule_mg->rule_masks[rule_id].and_masks[i]);
        printf("  NOT Mask: 0x%x\n", rule_mg->rule_masks[rule_id].not_masks[i]);
    }

    // 打印所有的 pattern
    printf("\nPatterns:\n");
    if (rule_mg->string_match_context_array) {
        for (int i = 0; rule_mg->string_match_context_array[i] != NULL; i++) {
            string_match_context_t *ctx = rule_mg->string_match_context_array[i];
            printf("\nProtocol Variable: %s\n", ctx->proto_var_name);
            printf("Pattern Count: %d\n", ctx->string_patterns_num);

            for (int j = 0; j < ctx->string_patterns_num; j++) {
                string_pattern_t *pattern = &ctx->string_patterns_list[j];
                printf("  Pattern %d:\n", j);
                printf("    Content: %s\n", pattern->string_pattern);
                printf("    Is PCRE: %s\n", pattern->is_pcre ? "Yes" : "No");
                printf("    HS Flags: 0x%x\n", pattern->hs_flags);
                printf("    Relations Count: %d\n", pattern->relation_count);

                // 打印每个 pattern 的关系
                for (int k = 0; k < pattern->relation_count; k++) {
                    rule_relation_t *rel = &pattern->relations[k];
                    printf("    Relation %d:\n", k);
                    printf("      Threat ID: %u\n", rel->threat_id);
                    printf("      Pattern ID: %u\n", rel->pattern_id);
                    printf("      AND Bit: 0x%x\n", rel->and_bit);
                    printf("      Operator Type: %u\n", rel->operator_type);
                }
            }
        }
    } else {
        printf("No string match contexts found.\n");
    }

    printf("========================\n\n");
}

int main() {
    TEST_SUITE_BEGIN();
    RUN_TEST(single_contains);  // 只运行这个测试
    TEST_SUITE_END();
    return 0;
}
