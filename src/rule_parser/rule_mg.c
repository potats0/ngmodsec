#include "waf_rule_types.h"
#include <hs/hs.h>
#include <string.h>
#include <stdio.h>

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

// 声明解析函数
int parse_rule_input(const char* rule_str, const char* filename, sign_rule_mg_t* rule_mg);

int parse_rule_string(const char* rule_str, sign_rule_mg_t* rule_mg) {
    if (!rule_str || !rule_mg) {
        return -1;
    }
    return parse_rule_input(rule_str, NULL, rule_mg);
}

int parse_rule_file(const char* filename, sign_rule_mg_t* rule_mg) {
    if (!filename || !rule_mg) {
        return -1;
    }
    return parse_rule_input(NULL, filename, rule_mg);
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

sign_rule_mg_t* dup_rule_mg(const sign_rule_mg_t* src) {
    if (!src) {
        return NULL;
    }

    // 分配新的规则管理器
    sign_rule_mg_t* dst = g_waf_rule_malloc(sizeof(sign_rule_mg_t));
    if (!dst) {
        return NULL;
    }

    // 初始化基本字段
    dst->max_rules = src->max_rules;
    dst->rules_count = src->rules_count;

    // 复制规则ID数组
    dst->rule_ids = g_waf_rule_malloc(dst->max_rules * sizeof(uint32_t));
    if (!dst->rule_ids) {
        g_waf_rule_free(dst);
        return NULL;
    }
    memcpy(dst->rule_ids, src->rule_ids, dst->max_rules * sizeof(uint32_t));

    // 复制规则掩码数组
    dst->rule_masks = g_waf_rule_malloc(dst->max_rules * sizeof(rule_mask_array_t));
    if (!dst->rule_masks) {
        g_waf_rule_free(dst->rule_ids);
        g_waf_rule_free(dst);
        return NULL;
    }
    memcpy(dst->rule_masks, src->rule_masks, dst->max_rules * sizeof(rule_mask_array_t));

    // 分配字符串匹配上下文数组
    dst->string_match_context_array = g_waf_rule_malloc(HTTP_VAR_MAX * sizeof(string_match_context_t*));
    if (!dst->string_match_context_array) {
        g_waf_rule_free(dst->rule_masks);
        g_waf_rule_free(dst->rule_ids);
        g_waf_rule_free(dst);
        return NULL;
    }
    memset(dst->string_match_context_array, 0, HTTP_VAR_MAX * sizeof(string_match_context_t*));

    // 复制每个字符串匹配上下文
    for (int i = 0; i < HTTP_VAR_MAX; i++) {
        string_match_context_t* src_ctx = src->string_match_context_array[i];
        if (!src_ctx) {
            continue;
        }

        // 创建新的上下文
        string_match_context_t* dst_ctx = g_waf_rule_malloc(sizeof(string_match_context_t));
        if (!dst_ctx) {
            goto cleanup;
        }
        memset(dst_ctx, 0, sizeof(string_match_context_t));
        dst->string_match_context_array[i] = dst_ctx;

        // 复制基本字段
        dst_ctx->string_patterns_num = src_ctx->string_patterns_num;
        dst_ctx->db = NULL;  // 数据库需要重新编译

        // 分配并复制模式列表
        dst_ctx->string_patterns_list = g_waf_rule_malloc(MAX_RULE_PATTERNS * sizeof(string_pattern_t));
        if (!dst_ctx->string_patterns_list) {
            goto cleanup;
        }
        memset(dst_ctx->string_patterns_list, 0, MAX_RULE_PATTERNS * sizeof(string_pattern_t));

        // 复制每个模式
        for (int j = 0; j < src_ctx->string_patterns_num; j++) {
            string_pattern_t* src_pattern = &src_ctx->string_patterns_list[j];
            string_pattern_t* dst_pattern = &dst_ctx->string_patterns_list[j];

            // 复制模式字符串
            dst_pattern->string_pattern = g_waf_rule_malloc(strlen(src_pattern->string_pattern) + 1);
            if (!dst_pattern->string_pattern) {
                goto cleanup;
            }
            strcpy(dst_pattern->string_pattern, src_pattern->string_pattern);

            // 复制关系数组
            dst_pattern->relation_count = src_pattern->relation_count;
            dst_pattern->hs_flags = src_pattern->hs_flags;

            if (src_pattern->relation_count > 0) {
                dst_pattern->relations = g_waf_rule_malloc(src_pattern->relation_count * sizeof(rule_relation_t));
                if (!dst_pattern->relations) {
                    goto cleanup;
                }
                memcpy(dst_pattern->relations, src_pattern->relations, 
                       src_pattern->relation_count * sizeof(rule_relation_t));
            }
        }

        // 复制string_ids数组（如果存在）
        if (src_ctx->string_ids) {
            dst_ctx->string_ids = g_waf_rule_malloc(src_ctx->string_patterns_num * sizeof(unsigned int));
            if (!dst_ctx->string_ids) {
                goto cleanup;
            }
            memcpy(dst_ctx->string_ids, src_ctx->string_ids, 
                   src_ctx->string_patterns_num * sizeof(unsigned int));
        }
    }

    return dst;

cleanup:
    // 清理已分配的资源
    destroy_rule_mg(dst);
    return NULL;
}
