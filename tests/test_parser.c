#define TEST_PARSER
#include "../src/ruleset_types.h"
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
  static inline void test_##name();                                            \
  struct test_##name {                                                         \
    void (*func)();                                                            \
    const char *name;                                                          \
  } _test_##name = {test_##name, #name};                                       \
  static inline void test_##name()

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

// 测试用的协议变量ID定义
#define TEST_VAR_URI 0    // http.uri
#define TEST_VAR_HEADER 1 // http.header
#define TEST_VAR_BODY 2   // http.body
#define TEST_VAR_MAX 3

// Hyperscan match callback function
static int on_match(unsigned int id, unsigned long long from,
                    unsigned long long to, unsigned int flags, void *context) {
  printf("Matched rule ID: %d (from: %llu, to: %llu)\n", id, from, to);
  return 0; // Continue matching
}

// 测试单个 http.uri contains
TEST_CASE(single_contains) {
  const char *rule_str = "rule 1000 http.uri contains \"a\" and http.uri "
                         "contains \"b\"and http.uri contains \"c\";";
  sign_rule_mg_t *rule_mg = calloc(1, sizeof(sign_rule_mg_t));
  ASSERT_NOT_NULL(rule_mg, "Failed to allocate rule_mg");
  ASSERT_EQ(0, init_rule_mg(rule_mg), "Failed to initialize rule_mg");

  int result = parse_rule_string(rule_str, rule_mg);
  ASSERT_EQ(0, result, "Rule parsing failed");

  // 验证规则计数和ID
  ASSERT(rule_mg->rules_count == 1, "Expected one rule");
  ASSERT(rule_mg->rule_ids != NULL, "Rule IDs array is NULL");
  ASSERT(rule_mg->rule_ids[0] == 1000, "Wrong rule ID");
  ASSERT(rule_mg->max_rules >= 1000, "Max rules too small");

  // 检查规则掩码数组是否分配
  ASSERT(rule_mg->rule_masks != NULL, "Rule masks array is NULL");

  // 检查 HTTP_VAR_URI 上下文
  string_match_context_t *uri_ctx =
      rule_mg->string_match_context_array[HTTP_VAR_URI];
  ASSERT(uri_ctx != NULL, "URI string match context is NULL");
  ASSERT(uri_ctx->string_patterns_list != NULL, "String patterns list is NULL");
  ASSERT(uri_ctx->string_patterns_num == 1, "Expected one pattern");
  ASSERT(uri_ctx->string_patterns_list[0].string_pattern != NULL,
         "Pattern string is NULL");
  ASSERT_STR_EQ("a", uri_ctx->string_patterns_list[0].string_pattern,
                "Wrong pattern string");
  ASSERT(uri_ctx->string_patterns_list[0].relation_count == 1,
         "Expected one relation");

  destroy_rule_mg(rule_mg);
  passed_tests++;
}

// 测试基本路径匹配的正则表达式
TEST_CASE(regex_basic_path) {
  const char *rule_str =
      "rule 2001 http.uri matches \"^/api/v[0-9]+/users/[0-9]+$\";";
  sign_rule_mg_t *rule_mg = calloc(1, sizeof(sign_rule_mg_t));
  ASSERT_NOT_NULL(rule_mg, "Failed to allocate rule_mg");
  ASSERT_EQ(0, init_rule_mg(rule_mg), "Failed to initialize rule_mg");

  int result = parse_rule_string(rule_str, rule_mg);
  ASSERT_EQ(0, result, "Rule parsing failed");
  ASSERT_EQ(1, rule_mg->rules_count, "Expected one rule");
  ASSERT_EQ(2001, rule_mg->rule_ids[0], "Wrong rule ID");
  destroy_rule_mg(rule_mg);
  passed_tests++;
}

// 测试带有分组和选择的正则表达式
TEST_CASE(regex_groups_and_choices) {
  const char *rule_str =
      "rule 2002 http.uri matches "
      "\"^/(?:admin|manager)/[a-zA-Z0-9_-]+/(?:edit|delete|view)$\" /i;";
  sign_rule_mg_t *rule_mg = calloc(1, sizeof(sign_rule_mg_t));
  ASSERT_NOT_NULL(rule_mg, "Failed to allocate rule_mg");
  ASSERT_EQ(0, init_rule_mg(rule_mg), "Failed to initialize rule_mg");

  int result = parse_rule_string(rule_str, rule_mg);
  ASSERT_EQ(0, result, "Rule parsing failed");
  ASSERT_EQ(1, rule_mg->rules_count, "Expected one rule");
  ASSERT_EQ(2002, rule_mg->rule_ids[0], "Wrong rule ID");
  destroy_rule_mg(rule_mg);
  passed_tests++;
}

// 测试文件扩展名匹配
TEST_CASE(regex_file_extensions) {
  const char *rule_str =
      "rule 2003 http.uri matches \"/download/.*\\.(?:exe|dll)$\" /i;";
  sign_rule_mg_t *rule_mg = calloc(1, sizeof(sign_rule_mg_t));
  ASSERT_NOT_NULL(rule_mg, "Failed to allocate rule_mg");
  ASSERT_EQ(0, init_rule_mg(rule_mg), "Failed to initialize rule_mg");

  int result = parse_rule_string(rule_str, rule_mg);
  ASSERT_EQ(0, result, "Rule parsing failed");
  ASSERT_EQ(1, rule_mg->rules_count, "Expected one rule");
  ASSERT_EQ(2003, rule_mg->rule_ids[0], "Wrong rule ID");
  destroy_rule_mg(rule_mg);
  passed_tests++;
}

// 测试Unicode字符类
TEST_CASE(regex_unicode_classes) {
  const char *rule_str = "rule 2004 http.uri matches "
                         "\"[\\p{Han}\\p{Hiragana}\\p{Katakana}]+\" /i;";
  sign_rule_mg_t *rule_mg = calloc(1, sizeof(sign_rule_mg_t));
  ASSERT_NOT_NULL(rule_mg, "Failed to allocate rule_mg");
  ASSERT_EQ(0, init_rule_mg(rule_mg), "Failed to initialize rule_mg");

  int result = parse_rule_string(rule_str, rule_mg);
  ASSERT_EQ(0, result, "Rule parsing failed");
  ASSERT_EQ(1, rule_mg->rules_count, "Expected one rule");
  ASSERT_EQ(2004, rule_mg->rule_ids[0], "Wrong rule ID");
  destroy_rule_mg(rule_mg);
  passed_tests++;
}

// 测试复杂的路径结构
TEST_CASE(regex_complex_path) {
  const char *rule_str =
      "rule 2005 http.uri matches "
      "\"^/(en|zh|ja)/blog/([0-9]{4})/([0-9]{2})/([^/]+)(?:\\.html)?$\" /i;";
  sign_rule_mg_t *rule_mg = calloc(1, sizeof(sign_rule_mg_t));
  ASSERT_NOT_NULL(rule_mg, "Failed to allocate rule_mg");
  ASSERT_EQ(0, init_rule_mg(rule_mg), "Failed to initialize rule_mg");

  int result = parse_rule_string(rule_str, rule_mg);
  ASSERT_EQ(0, result, "Rule parsing failed");
  ASSERT_EQ(1, rule_mg->rules_count, "Expected one rule");
  ASSERT_EQ(2005, rule_mg->rule_ids[0], "Wrong rule ID");
  destroy_rule_mg(rule_mg);
  passed_tests++;
}

// 测试反向引用
TEST_CASE(regex_backreferences) {
  const char *rule_str =
      "rule 2007 http.uri matches \"<([a-z]+)>.*?</\\1>\" /i /s;";
  sign_rule_mg_t *rule_mg = calloc(1, sizeof(sign_rule_mg_t));
  ASSERT_NOT_NULL(rule_mg, "Failed to allocate rule_mg");
  ASSERT_EQ(0, init_rule_mg(rule_mg), "Failed to initialize rule_mg");

  int result = parse_rule_string(rule_str, rule_mg);
  ASSERT_EQ(0, result, "Rule parsing failed");
  ASSERT_EQ(1, rule_mg->rules_count, "Expected one rule");
  ASSERT_EQ(2007, rule_mg->rule_ids[0], "Wrong rule ID");
  destroy_rule_mg(rule_mg);
  passed_tests++;
}

// 测试邮箱格式验证
TEST_CASE(regex_email) {
  const char *rule_str =
      "rule 2008 http.uri matches "
      "\"[\\w.-]+@[\\w-]+(?:\\.[\\w-]+)*\\.[A-Za-z]{2,6}\" /i;";
  sign_rule_mg_t *rule_mg = calloc(1, sizeof(sign_rule_mg_t));
  ASSERT_NOT_NULL(rule_mg, "Failed to allocate rule_mg");
  ASSERT_EQ(0, init_rule_mg(rule_mg), "Failed to initialize rule_mg");

  int result = parse_rule_string(rule_str, rule_mg);
  ASSERT_EQ(0, result, "Rule parsing failed");
  ASSERT_EQ(1, rule_mg->rules_count, "Expected one rule");
  ASSERT_EQ(2008, rule_mg->rule_ids[0], "Wrong rule ID");
  destroy_rule_mg(rule_mg);
  passed_tests++;
}

// 测试多条件组合
TEST_CASE(regex_multiple_conditions) {
  const char *rule_str =
      "rule 2010 http.uri matches \"^/api/v[0-9]+/users/[0-9]+$\" and "
      "http.header matches "
      "\"^Bearer\\s+[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$\" "
      "/i;";
  sign_rule_mg_t *rule_mg = calloc(1, sizeof(sign_rule_mg_t));
  ASSERT_NOT_NULL(rule_mg, "Failed to allocate rule_mg");
  ASSERT_EQ(0, init_rule_mg(rule_mg), "Failed to initialize rule_mg");

  int result = parse_rule_string(rule_str, rule_mg);
  ASSERT_EQ(0, result, "Rule parsing failed");
  ASSERT_EQ(1, rule_mg->rules_count, "Expected one rule");
  ASSERT_EQ(2010, rule_mg->rule_ids[0], "Wrong rule ID");
  destroy_rule_mg(rule_mg);
  passed_tests++;
}

// 测试嵌套括号
TEST_CASE(regex_nested_parentheses) {
  const char *rule_str = "rule 2011 http.body matches "
                         "\"^(?:[^()]*(?:\\([^()]*\\)[^()]*)*){0,100}$\" /s;";
  sign_rule_mg_t *rule_mg = calloc(1, sizeof(sign_rule_mg_t));
  ASSERT_NOT_NULL(rule_mg, "Failed to allocate rule_mg");
  ASSERT_EQ(0, init_rule_mg(rule_mg), "Failed to initialize rule_mg");

  int result = parse_rule_string(rule_str, rule_mg);
  ASSERT_EQ(0, result, "Rule parsing failed");
  ASSERT_EQ(1, rule_mg->rules_count, "Expected one rule");
  ASSERT_EQ(2011, rule_mg->rule_ids[0], "Wrong rule ID");
  destroy_rule_mg(rule_mg);
  passed_tests++;
}

// 测试多规则合并
TEST_CASE(multiple_rules_merge) {
  const char *rule_str1 = "rule 3001 http.uri starts_with \"/api\";";
  const char *rule_str2 = "rule 3002 http.uri ends_with \".json\";";

  sign_rule_mg_t *rule_mg = calloc(1, sizeof(sign_rule_mg_t));
  ASSERT_NOT_NULL(rule_mg, "Failed to allocate rule_mg");
  ASSERT_EQ(0, init_rule_mg(rule_mg), "Failed to initialize rule_mg");

  // 解析第一条规则
  int result = parse_rule_string(rule_str1, rule_mg);
  ASSERT_EQ(0, result, "First rule parsing failed");
  ASSERT_EQ(1, rule_mg->rules_count, "Expected one rule after first parse");
  ASSERT_EQ(3001, rule_mg->rule_ids[0], "Wrong first rule ID");

  // 解析第二条规则
  result = parse_rule_string(rule_str2, rule_mg);
  ASSERT_EQ(0, result, "Second rule parsing failed");
  ASSERT_EQ(2, rule_mg->rules_count, "Expected two rules after second parse");
  ASSERT_EQ(3002, rule_mg->rule_ids[1], "Wrong second rule ID");

  destroy_rule_mg(rule_mg);
  passed_tests++;
}

// 测试 starts_with 操作符
TEST_CASE(starts_with_basic) {
  const char *rule_str = "rule 3010 http.uri starts_with \"/api\";";
  sign_rule_mg_t *rule_mg = calloc(1, sizeof(sign_rule_mg_t));
  ASSERT_NOT_NULL(rule_mg, "Failed to allocate rule_mg");
  ASSERT_EQ(0, init_rule_mg(rule_mg), "Failed to initialize rule_mg");

  int result = parse_rule_string(rule_str, rule_mg);
  ASSERT_EQ(0, result, "Rule parsing failed");

  // 验证规则计数和ID
  ASSERT(rule_mg->rules_count == 1, "Expected one rule");
  ASSERT(rule_mg->rule_ids != NULL, "Rule IDs array is NULL");
  ASSERT(rule_mg->rule_ids[0] == 3010, "Wrong rule ID");

  // 检查 HTTP_VAR_URI 上下文
  string_match_context_t *ctx =
      rule_mg->string_match_context_array[HTTP_VAR_URI];
  ASSERT(ctx != NULL, "Pattern context is NULL");
  ASSERT(ctx->string_patterns_num == 1, "Wrong pattern count");
  ASSERT(ctx->string_patterns_list != NULL, "Pattern list is NULL");
  ASSERT(ctx->string_patterns_list[0].string_pattern != NULL,
         "Pattern string is NULL");

  destroy_rule_mg(rule_mg);
  passed_tests++;
}

// 测试 ends_with 操作符
TEST_CASE(ends_with_basic) {
  const char *rule_str = "rule 3011 http.uri ends_with \".php\";";
  sign_rule_mg_t *rule_mg = calloc(1, sizeof(sign_rule_mg_t));
  ASSERT_NOT_NULL(rule_mg, "Failed to allocate rule_mg");
  ASSERT_EQ(0, init_rule_mg(rule_mg), "Failed to initialize rule_mg");

  int result = parse_rule_string(rule_str, rule_mg);
  ASSERT_EQ(0, result, "Rule parsing failed");

  // 验证规则计数和ID
  ASSERT(rule_mg->rules_count == 1, "Expected one rule");
  ASSERT(rule_mg->rule_ids != NULL, "Rule IDs array is NULL");
  ASSERT(rule_mg->rule_ids[0] == 3011, "Wrong rule ID");

  // 检查 HTTP_VAR_URI 上下文
  string_match_context_t *ctx =
      rule_mg->string_match_context_array[HTTP_VAR_URI];
  ASSERT(ctx != NULL, "Pattern context is NULL");
  ASSERT(ctx->string_patterns_num == 1, "Wrong pattern count");
  ASSERT(ctx->string_patterns_list != NULL, "Pattern list is NULL");
  ASSERT(ctx->string_patterns_list[0].string_pattern != NULL,
         "Pattern string is NULL");

  destroy_rule_mg(rule_mg);
  passed_tests++;
}

// 测试 equals 操作符
TEST_CASE(equals_basic) {
  const char *rule_str = "rule 3012 http.uri equals \"/login\";";
  sign_rule_mg_t *rule_mg = calloc(1, sizeof(sign_rule_mg_t));
  ASSERT_NOT_NULL(rule_mg, "Failed to allocate rule_mg");
  ASSERT_EQ(0, init_rule_mg(rule_mg), "Failed to initialize rule_mg");

  int result = parse_rule_string(rule_str, rule_mg);
  ASSERT_EQ(0, result, "Rule parsing failed");

  // 验证规则计数和ID
  ASSERT(rule_mg->rules_count == 1, "Expected one rule");
  ASSERT(rule_mg->rule_ids != NULL, "Rule IDs array is NULL");
  ASSERT(rule_mg->rule_ids[0] == 3012, "Wrong rule ID");

  // 检查 HTTP_VAR_URI 上下文
  string_match_context_t *ctx =
      rule_mg->string_match_context_array[HTTP_VAR_URI];
  ASSERT(ctx != NULL, "Pattern context is NULL");
  ASSERT(ctx->string_patterns_num == 1, "Wrong pattern count");
  ASSERT(ctx->string_patterns_list != NULL, "Pattern list is NULL");
  ASSERT(ctx->string_patterns_list[0].string_pattern != NULL,
         "Pattern string is NULL");

  destroy_rule_mg(rule_mg);
  passed_tests++;
}

// 测试带有特殊字符的 contains 操作符
TEST_CASE(contains_special_chars) {
  const char *rule_str = "rule 3013 http.uri contains \"user?id=[0-9]+\";";
  sign_rule_mg_t *rule_mg = calloc(1, sizeof(sign_rule_mg_t));
  ASSERT_NOT_NULL(rule_mg, "Failed to allocate rule_mg");
  ASSERT_EQ(0, init_rule_mg(rule_mg), "Failed to initialize rule_mg");

  int result = parse_rule_string(rule_str, rule_mg);
  ASSERT_EQ(0, result, "Rule parsing failed");

  // 验证规则计数和ID
  ASSERT(rule_mg->rules_count == 1, "Expected one rule");
  ASSERT(rule_mg->rule_ids != NULL, "Rule IDs array is NULL");
  ASSERT(rule_mg->rule_ids[0] == 3013, "Wrong rule ID");

  // 检查 HTTP_VAR_URI 上下文
  string_match_context_t *ctx =
      rule_mg->string_match_context_array[HTTP_VAR_URI];
  ASSERT(ctx != NULL, "Pattern context is NULL");
  ASSERT(ctx->string_patterns_num == 1, "Wrong pattern count");
  ASSERT(ctx->string_patterns_list != NULL, "Pattern list is NULL");
  ASSERT(ctx->string_patterns_list[0].string_pattern != NULL,
         "Pattern string is NULL");

  destroy_rule_mg(rule_mg);
  passed_tests++;
}

// 测试带有特殊字符的 starts_with 操作符
TEST_CASE(starts_with_special_chars) {
  const char *rule_str = "rule 3014 http.uri starts_with \"/api/v[1-3]\";";
  sign_rule_mg_t *rule_mg = calloc(1, sizeof(sign_rule_mg_t));
  ASSERT_NOT_NULL(rule_mg, "Failed to allocate rule_mg");
  ASSERT_EQ(0, init_rule_mg(rule_mg), "Failed to initialize rule_mg");

  int result = parse_rule_string(rule_str, rule_mg);
  ASSERT_EQ(0, result, "Rule parsing failed");

  // 验证规则计数和ID
  ASSERT(rule_mg->rules_count == 1, "Expected one rule");
  ASSERT(rule_mg->rule_ids != NULL, "Rule IDs array is NULL");
  ASSERT(rule_mg->rule_ids[0] == 3014, "Wrong rule ID");

  // 检查 HTTP_VAR_URI 上下文
  string_match_context_t *ctx =
      rule_mg->string_match_context_array[HTTP_VAR_URI];
  ASSERT(ctx != NULL, "Pattern context is NULL");
  ASSERT(ctx->string_patterns_num == 1, "Wrong pattern count");
  ASSERT(ctx->string_patterns_list != NULL, "Pattern list is NULL");
  ASSERT(ctx->string_patterns_list[0].string_pattern != NULL,
         "Pattern string is NULL");

  destroy_rule_mg(rule_mg);
  passed_tests++;
}

// 测试带有特殊字符的 ends_with 操作符
TEST_CASE(ends_with_special_chars) {
  const char *rule_str = "rule 3015 http.uri ends_with \".(php|jsp)\";";
  sign_rule_mg_t *rule_mg = calloc(1, sizeof(sign_rule_mg_t));
  ASSERT_NOT_NULL(rule_mg, "Failed to allocate rule_mg");
  ASSERT_EQ(0, init_rule_mg(rule_mg), "Failed to initialize rule_mg");

  int result = parse_rule_string(rule_str, rule_mg);
  ASSERT_EQ(0, result, "Rule parsing failed");

  // 验证规则计数和ID
  ASSERT(rule_mg->rules_count == 1, "Expected one rule");
  ASSERT(rule_mg->rule_ids != NULL, "Rule IDs array is NULL");
  ASSERT(rule_mg->rule_ids[0] == 3015, "Wrong rule ID");

  // 检查 HTTP_VAR_URI 上下文
  string_match_context_t *ctx =
      rule_mg->string_match_context_array[HTTP_VAR_URI];
  ASSERT(ctx != NULL, "Pattern context is NULL");
  ASSERT(ctx->string_patterns_num == 1, "Wrong pattern count");
  ASSERT(ctx->string_patterns_list != NULL, "Pattern list is NULL");
  ASSERT(ctx->string_patterns_list[0].string_pattern != NULL,
         "Pattern string is NULL");

  destroy_rule_mg(rule_mg);
  passed_tests++;
}

// 测试多模式匹配
TEST_CASE(multi_pattern_hyperscan) {
  // Test multiple patterns with different matching types
  const char *rule_str =
      "rule 4001 http.uri contains \"admin\" and http.uri contains \"php\";";
  sign_rule_mg_t *rule_mg = calloc(1, sizeof(sign_rule_mg_t));
  ASSERT_NOT_NULL(rule_mg, "Failed to allocate rule_mg");
  ASSERT_EQ(0, init_rule_mg(rule_mg), "Failed to initialize rule_mg");

  // 解析规则
  int ret = parse_rule_string(rule_str, rule_mg);
  ASSERT_EQ(0, ret, "Failed to parse rule");

  // 编译 Hyperscan 数据库
  ret = compile_all_hyperscan_databases(rule_mg);
  ASSERT_EQ(0, ret, "Failed to compile Hyperscan databases");

  // 创建 Hyperscan scratch
  hs_scratch_t *scratch = NULL;
  for (int i = 0; i < HTTP_VAR_MAX; i++) {
    string_match_context_t *ctx = rule_mg->string_match_context_array[i];
    if (ctx && ctx->db) {
      ret = hs_alloc_scratch(ctx->db, &scratch);
      ASSERT_EQ(HS_SUCCESS, ret, "Failed to allocate scratch");
      break; // 只需要一个 scratch，因为它可以在相同类型的数据库之间共享
    }
  }

  // 测试匹配
  const char *test_url = "/admin/users.php?id=123";
  printf("\nTesting URL: %s\n", test_url);
  for (int i = 0; i < HTTP_VAR_MAX; i++) {
    string_match_context_t *ctx = rule_mg->string_match_context_array[i];
    if (ctx && ctx->db) {
      ret = hs_scan(ctx->db, test_url, strlen(test_url), 0, scratch, on_match,
                    NULL);
      ASSERT_EQ(HS_SUCCESS, ret, "Failed to scan");
    }
  }

  // 清理
  hs_free_scratch(scratch);
  destroy_rule_mg(rule_mg);
  passed_tests++;
}

// 测试规则管理器复制功能
TEST_CASE(rule_mg_duplication) {
  const char *rule_str =
      "rule 1001 http.uri contains \"admin\" and http.header contains \"evil\" "
      "or http.body contains \"hack\";";
  sign_rule_mg_t *rule_mg = calloc(1, sizeof(sign_rule_mg_t));
  ASSERT_NOT_NULL(rule_mg, "Failed to allocate rule_mg");
  ASSERT_EQ(0, init_rule_mg(rule_mg), "Failed to initialize rule_mg");

  // 解析原始规则
  ASSERT_EQ(0, parse_rule_string(rule_str, rule_mg), "Failed to parse rule");

  // 复制规则管理器
  sign_rule_mg_t *dup_mg = dup_rule_mg(rule_mg);
  ASSERT_NOT_NULL(dup_mg, "Failed to duplicate rule_mg");

  // 验证基本属性
  ASSERT_EQ(rule_mg->rules_count, dup_mg->rules_count, "Rules count mismatch");
  ASSERT_EQ(rule_mg->rule_ids[0], dup_mg->rule_ids[0], "Rule ID mismatch");

  // 验证规则掩码
  for (size_t i = 0; i < rule_mg->rules_count; i++) {
    ASSERT_EQ(rule_mg->rule_masks[i].sub_rules_count,
              dup_mg->rule_masks[i].sub_rules_count,
              "Sub rules count mismatch");

    for (size_t j = 0; j < rule_mg->rule_masks[i].sub_rules_count; j++) {
      ASSERT_EQ(rule_mg->rule_masks[i].and_masks[j],
                dup_mg->rule_masks[i].and_masks[j], "AND mask mismatch");
      ASSERT_EQ(rule_mg->rule_masks[i].not_masks[j],
                dup_mg->rule_masks[i].not_masks[j], "NOT mask mismatch");
    }
  }

  // 验证字符串匹配上下文
  for (int i = 0; i < HTTP_VAR_MAX; i++) {
    if (rule_mg->string_match_context_array[i] != NULL) {
      ASSERT_NOT_NULL(dup_mg->string_match_context_array[i],
                      "String match context not duplicated");

      string_match_context_t *src_ctx = rule_mg->string_match_context_array[i];
      string_match_context_t *dup_ctx = dup_mg->string_match_context_array[i];

      ASSERT_EQ(src_ctx->string_patterns_num, dup_ctx->string_patterns_num,
                "Pattern count mismatch");

      // 验证模式字符串
      for (int j = 0; j < src_ctx->string_patterns_num; j++) {
        ASSERT_STR_EQ(src_ctx->string_patterns_list[j].string_pattern,
                      dup_ctx->string_patterns_list[j].string_pattern,
                      "Pattern string mismatch");

        // 验证规则关系
        ASSERT_EQ(src_ctx->string_patterns_list[j].relation_count,
                  dup_ctx->string_patterns_list[j].relation_count,
                  "Relation count mismatch");
      }
    }
  }

  // 清理资源
  destroy_rule_mg(rule_mg);
  destroy_rule_mg(dup_mg);
  passed_tests++;
}

int main() {
  TEST_SUITE_BEGIN();

  RUN_TEST(single_contains);
  RUN_TEST(regex_basic_path);
  RUN_TEST(regex_groups_and_choices);
  RUN_TEST(regex_file_extensions);
  RUN_TEST(regex_unicode_classes);
  RUN_TEST(regex_complex_path);
  RUN_TEST(regex_backreferences);
  RUN_TEST(regex_email);
  RUN_TEST(regex_multiple_conditions);
  RUN_TEST(regex_nested_parentheses);
  RUN_TEST(multiple_rules_merge);
  RUN_TEST(starts_with_basic);
  RUN_TEST(ends_with_basic);
  RUN_TEST(equals_basic);
  RUN_TEST(contains_special_chars);
  RUN_TEST(starts_with_special_chars);
  RUN_TEST(ends_with_special_chars);
  RUN_TEST(multi_pattern_hyperscan);
  RUN_TEST(rule_mg_duplication); // 添加新的测试用例

  TEST_SUITE_END();
  return 0;
}