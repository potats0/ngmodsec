#include "waf_rule_types.h"
#include <hs/hs.h>
#include <string.h>

// 默认的内存分配函数
waf_rule_malloc_fn g_waf_rule_malloc = malloc;
waf_rule_free_fn g_waf_rule_free = free;

// 设置自定义内存分配函数
void sign_rule_set_alloc(waf_rule_malloc_fn f_malloc, waf_rule_free_fn f_free) {
  if (f_malloc && f_free) {
    g_waf_rule_malloc = f_malloc;
    g_waf_rule_free = f_free;
  }
}

int init_rule_mg(sign_rule_mg_t *rule_mg) {
  if (!rule_mg) {
    return -1;
  }

  // 初始化规则相关的字段
  rule_mg->max_rules = MAX_RULES_NUM;
  rule_mg->rules_count = 0;
  rule_mg->rule_ids = g_waf_rule_malloc(rule_mg->max_rules * sizeof(uint32_t));
  if (!rule_mg->rule_ids) {
    return -1;
  }
  memset(rule_mg->rule_ids, 0, rule_mg->max_rules * sizeof(uint32_t));

  rule_mg->rule_masks =
      g_waf_rule_malloc(rule_mg->max_rules * sizeof(rule_mask_array_t));
  if (!rule_mg->rule_masks) {
    g_waf_rule_free(rule_mg->rule_ids);
    return -1;
  }

  // 初始化掩码数组为0
  for (uint32_t i = 0; i < rule_mg->max_rules; i++) {
    memset(&rule_mg->rule_masks[i], 0, sizeof(rule_mask_array_t));
  }

  // 分配字符串匹配上下文数组
  rule_mg->string_match_context_array =
      g_waf_rule_malloc(HTTP_VAR_MAX * sizeof(string_match_context_t *));
  if (!rule_mg->string_match_context_array) {
    g_waf_rule_free(rule_mg->rule_masks);
    g_waf_rule_free(rule_mg->rule_ids);
    return -1;
  }
  memset(rule_mg->string_match_context_array, 0,
         HTTP_VAR_MAX * sizeof(string_match_context_t *));

  return 0;
}

void destroy_rule_mg(sign_rule_mg_t *rule_mg) {
  if (!rule_mg) {
    return;
  }

  // 释放字符串匹配上下文数组
  if (rule_mg->string_match_context_array) {
    for (int i = 0; i < HTTP_VAR_MAX; i++) {
      string_match_context_t *ctx = rule_mg->string_match_context_array[i];
      if (!ctx)
        continue;

      if (ctx->string_patterns_list) {
        for (int j = 0; j < ctx->string_patterns_num; j++) {
          if (ctx->string_patterns_list[j].string_pattern) {
            g_waf_rule_free(ctx->string_patterns_list[j].string_pattern);
          }
          if (ctx->string_patterns_list[j].relations) {
            g_waf_rule_free(ctx->string_patterns_list[j].relations);
          }
        }
        g_waf_rule_free(ctx->string_patterns_list);
      }
      if (ctx->string_ids) {
        g_waf_rule_free(ctx->string_ids);
      }
      if (ctx->db) {
        hs_free_database(ctx->db);
      }
      g_waf_rule_free(ctx);
    }
    g_waf_rule_free(rule_mg->string_match_context_array);
  }

  // 释放规则掩码数组
  if (rule_mg->rule_masks) {
    g_waf_rule_free(rule_mg->rule_masks);
  }

  // 释放规则ID数组
  if (rule_mg->rule_ids) {
    g_waf_rule_free(rule_mg->rule_ids);
  }
}
