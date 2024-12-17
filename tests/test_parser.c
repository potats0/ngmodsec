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

// 打印规则管理器状态的辅助函数
void print_rule_mg_state(sign_rule_mg_t *rule_mg, uint32_t rule_id) {
  printf("\n=== Rule Management State ===\n");
  printf("Rule ID: %u\n", rule_id);
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

// 测试简单的AND组合
TEST_CASE(simple_and) {
  const char *rule_str =
      "rule 1000 http.uri contains \"test\" and http.uri contains \"123\";";
  sign_rule_mg_t *rule_mg = parse_rule_string(rule_str);
  ASSERT(rule_mg != NULL, "Rule parsing failed");
  ASSERT(rule_mg->max_rule_id == 1000, "Rule ID mismatch");

  // 检查规则掩码
  ASSERT(rule_mg->rule_masks[1000].sub_rules_count == 1,
         "Sub rules count mismatch");
  ASSERT(get_rule_and_mask(&rule_mg->rule_masks[1000], 0) == 0x3,
         "AND mask mismatch");
  ASSERT(get_rule_not_mask(&rule_mg->rule_masks[1000], 0) == 0,
         "NOT mask mismatch");

  cleanup_rule_mg(rule_mg);
  passed_tests++;
}

// 测试复杂的AND/OR组合
TEST_CASE(complex_and_or) {
  const char *rule_str =
      "rule 1000 (http.uri contains \"test\" and http.uri contains \"123\") or "
      "(http.uri contains \"abc\" and http.uri contains \"xyz\");";
  sign_rule_mg_t *rule_mg = parse_rule_string(rule_str);
  ASSERT(rule_mg != NULL, "Rule parsing failed");
  ASSERT(rule_mg->max_rule_id == 1000, "Rule ID mismatch");

  // 检查规则掩码
  ASSERT(rule_mg->rule_masks[1000].sub_rules_count == 1,
         "Sub rules count mismatch");
  ASSERT(get_rule_and_mask(&rule_mg->rule_masks[1000], 0) == 0xF,
         "First sub-rule AND mask mismatch");
  ASSERT(get_rule_not_mask(&rule_mg->rule_masks[1000], 0) == 0,
         "NOT mask mismatch");

  cleanup_rule_mg(rule_mg);
  passed_tests++;
}

// 测试带有NOT条件的规则
TEST_CASE(not_condition) {
  const char *rule_str =
      "rule 1000 http.uri contains \"test\" and not http.uri contains \"123\";";
  sign_rule_mg_t *rule_mg = parse_rule_string(rule_str);
  ASSERT(rule_mg != NULL, "Rule parsing failed");
  ASSERT(rule_mg->max_rule_id == 1000, "Rule ID mismatch");

  // 检查规则掩码
  ASSERT(rule_mg->rule_masks[1000].sub_rules_count == 1,
         "Sub rules count mismatch");
  ASSERT(get_rule_and_mask(&rule_mg->rule_masks[1000], 0) == 0x3,
         "AND mask mismatch");
  ASSERT(get_rule_not_mask(&rule_mg->rule_masks[1000], 0) == 0x2,
         "NOT mask mismatch");

  cleanup_rule_mg(rule_mg);
  passed_tests++;
}

// 测试带有Hyperscan标志的规则
TEST_CASE(hyperscan_flags) {
  const char *rule_str = "rule 1000 http.uri matches \"test.*\" /i /m /s;";
  sign_rule_mg_t *rule_mg = parse_rule_string(rule_str);
  ASSERT(rule_mg != NULL, "Rule parsing failed");
  ASSERT(rule_mg->max_rule_id == 1000, "Rule ID mismatch");

  // 检查规则掩码
  ASSERT(rule_mg->rule_masks[1000].sub_rules_count == 1,
         "Sub rules count mismatch");

  // 检查Hyperscan标志
  string_pattern_t *pattern = get_pattern_by_content(rule_mg, "test.*");
  ASSERT(pattern != NULL, "Pattern not found");
  ASSERT(pattern->hs_flags & HS_FLAG_CASELESS, "Caseless flag not set");
  ASSERT(pattern->hs_flags & HS_FLAG_MULTILINE, "Multiline flag not set");
  ASSERT(pattern->hs_flags & HS_FLAG_DOTALL, "Dotall flag not set");

  cleanup_rule_mg(rule_mg);
  passed_tests++;
}

// 测试带有PCRE和标志的规则
TEST_CASE(pcre_with_flags) {
  const char *rule_str = "rule 1000 http.uri matches \"test.*\" /i /m;";
  sign_rule_mg_t *rule_mg = parse_rule_string(rule_str);
  ASSERT(rule_mg != NULL, "Rule parsing failed");
  ASSERT(rule_mg->max_rule_id == 1000, "Rule ID mismatch");

  // 检查规则掩码
  ASSERT(rule_mg->rule_masks[1000].sub_rules_count == 1,
         "Sub rules count mismatch");

  // 检查Hyperscan标志
  string_pattern_t *pattern = get_pattern_by_content(rule_mg, "test.*");
  ASSERT(pattern != NULL, "Pattern not found");
  ASSERT(pattern->hs_flags & HS_FLAG_CASELESS, "Caseless flag not set");
  ASSERT(pattern->hs_flags & HS_FLAG_MULTILINE, "Multiline flag not set");

  cleanup_rule_mg(rule_mg);
  passed_tests++;
}

// 测试带括号的AND-OR组合
TEST_CASE(and_or_with_parentheses) {
  const char *rule_str = "rule 1000 http.uri contains \"a\" and (http.uri "
                         "contains \"b\" or http.uri contains \"c\");";
  sign_rule_mg_t *rule_mg = parse_rule_string(rule_str);
  ASSERT(rule_mg != NULL, "Rule parsing failed");
  ASSERT(rule_mg->max_rule_id == 1000, "Rule ID mismatch");

  // 检查规则掩码
  // 应该生成两个子规则：
  // 子规则1：a AND b
  // 子规则2：a AND c
  if (rule_mg->rule_masks[1000].sub_rules_count != 2) {
    printf("Error: Expected sub_rules_count = 2, but got %u\n",
           rule_mg->rule_masks[1000].sub_rules_count);
    print_rule_mg_state(rule_mg, 1000);
    ASSERT(0, "Sub rules count mismatch");
  }

  // 第一个子规则：a AND b
  uint16_t first_and_mask = get_rule_and_mask(&rule_mg->rule_masks[1000], 0);
  if (first_and_mask != 0x3) {
    printf("Error: Expected first sub-rule AND mask = 0x3, but got 0x%x\n",
           first_and_mask);
    print_rule_mg_state(rule_mg, 1000);
    ASSERT(0, "First sub-rule AND mask mismatch");
  }

  uint16_t first_not_mask = get_rule_not_mask(&rule_mg->rule_masks[1000], 0);
  if (first_not_mask != 0) {
    printf("Error: Expected first sub-rule NOT mask = 0x0, but got 0x%x\n",
           first_not_mask);
    print_rule_mg_state(rule_mg, 1000);
    ASSERT(0, "First sub-rule NOT mask mismatch");
  }

  // 第二个子规则：a AND c
  uint16_t second_and_mask = get_rule_and_mask(&rule_mg->rule_masks[1000], 1);
  if (second_and_mask != 0x5) {
    printf("Error: Expected second sub-rule AND mask = 0x3, but got 0x%x\n",
           second_and_mask);
    print_rule_mg_state(rule_mg, 1000);
    ASSERT(0, "Second sub-rule AND mask mismatch");
  }

  uint16_t second_not_mask = get_rule_not_mask(&rule_mg->rule_masks[1000], 1);
  if (second_not_mask != 0) {
    printf("Error: Expected second sub-rule NOT mask = 0x0, but got 0x%x\n",
           second_not_mask);
    print_rule_mg_state(rule_mg, 1000);
    ASSERT(0, "Second sub-rule NOT mask mismatch");
  }

  // 无论测试是否通过，都打印最终状态
  printf("\nFinal state after all checks:\n");
  print_rule_mg_state(rule_mg, 1000);

  cleanup_rule_mg(rule_mg);
  passed_tests++;
}

// 测试 A|(B&C) 组合
TEST_CASE(or_and_combination) {
  const char* rule_str = "rule 1000 http.uri contains \"a\" or (http.uri contains \"b\" and http.uri contains \"c\");";
  sign_rule_mg_t* rule_mg = parse_rule_string(rule_str);
  ASSERT(rule_mg != NULL, "Rule parsing failed");
  ASSERT(rule_mg->max_rule_id == 1000, "Rule ID mismatch");
  
  // 检查规则掩码
  // 应该生成两个子规则：
  // 子规则1：A
  // 子规则2：B AND C
  if (rule_mg->rule_masks[1000].sub_rules_count != 2) {
    printf("Error: Expected sub_rules_count = 2, but got %u\n", 
           rule_mg->rule_masks[1000].sub_rules_count);
    print_rule_mg_state(rule_mg, 1000);
    ASSERT(0, "Sub rules count mismatch");
  }
  
  // 第一个子规则：A
  uint16_t first_and_mask = get_rule_and_mask(&rule_mg->rule_masks[1000], 0);
  if (first_and_mask != 0x1) {  // 只需要匹配 A
    printf("Error: Expected first sub-rule AND mask = 0x1, but got 0x%x\n", first_and_mask);
    print_rule_mg_state(rule_mg, 1000);
    ASSERT(0, "First sub-rule AND mask mismatch");
  }
  
  uint16_t first_not_mask = get_rule_not_mask(&rule_mg->rule_masks[1000], 0);
  if (first_not_mask != 0) {
    printf("Error: Expected first sub-rule NOT mask = 0x0, but got 0x%x\n", first_not_mask);
    print_rule_mg_state(rule_mg, 1000);
    ASSERT(0, "First sub-rule NOT mask mismatch");
  }
  
  // 第二个子规则：B AND C
  uint16_t second_and_mask = get_rule_and_mask(&rule_mg->rule_masks[1000], 1);
  if (second_and_mask != 0x3) {  // B 和 C 都需要匹配
    printf("Error: Expected second sub-rule AND mask = 0x3, but got 0x%x\n", second_and_mask);
    print_rule_mg_state(rule_mg, 1000);
    ASSERT(0, "Second sub-rule AND mask mismatch");
  }
  
  uint16_t second_not_mask = get_rule_not_mask(&rule_mg->rule_masks[1000], 1);
  if (second_not_mask != 0) {
    printf("Error: Expected second sub-rule NOT mask = 0x0, but got 0x%x\n", second_not_mask);
    print_rule_mg_state(rule_mg, 1000);
    ASSERT(0, "Second sub-rule NOT mask mismatch");
  }
  
  // 无论测试是否通过，都打印最终状态
  printf("\nFinal state after all checks:\n");
  print_rule_mg_state(rule_mg, 1000);
  
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
  RUN_TEST(and_or_with_parentheses);
  RUN_TEST(or_and_combination);
  
  TEST_SUITE_END();
}
