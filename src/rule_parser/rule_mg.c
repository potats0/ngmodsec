#include "ruleset_types.h"
#include <hs/hs.h>
#include <stdint.h>
#include <stdio.h>
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

// 声明解析函数
int parse_rule_input(const char *rule_str, const char *filename,
                     sign_rule_mg_t *rule_mg);

int parse_rule_string(const char *rule_str, sign_rule_mg_t *rule_mg) {
  if (!rule_str || !rule_mg) {
    return -1;
  }
  return parse_rule_input(rule_str, NULL, rule_mg);
}

int parse_rule_file(const char *filename, sign_rule_mg_t *rule_mg) {
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
  rule_mg->max_rules = INITIAL_RULESETS_CAPACITY;
  rule_mg->rules_count = 0;
  rule_mg->rule_ids = g_waf_rule_malloc(rule_mg->max_rules * sizeof(uint32_t));
  if (!rule_mg->rule_ids) {
    return -1;
  }
  memset(rule_mg->rule_ids, 0, rule_mg->max_rules * sizeof(uint32_t));

  rule_mg->rule_masks =
      g_waf_rule_malloc(rule_mg->max_rules * sizeof(rule_mask_array_t));
  if (!rule_mg->rule_masks) {
    fprintf(stderr, "Failed to allocate rule masks array\n");
    goto error;
  }
  memset(rule_mg->rule_masks, 0, rule_mg->max_rules * sizeof(rule_mask_array_t));

  // 初始化get参数hash表
  rule_mg->get_match_context = NULL;  // uthash需要初始化为NULL

  // 初始化所有规则的 method 为 0xFFFFFFFF
  for (uint32_t i = 0; i < rule_mg->max_rules; i++) {
    for (uint32_t j = 0; j < MAX_SUB_RULES_NUM; j++) {
      rule_mg->rule_masks[i].method[j] = 0xFFFFFFFF;
    }
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

error:
  g_waf_rule_free(rule_mg->rule_ids);
  g_waf_rule_free(rule_mg->rule_masks);
  return -1;
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
        for (uint32_t j = 0; j < ctx->string_patterns_num; j++) {
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

  // 释放get参数hash表
  if (rule_mg->get_match_context) {
    hash_pattern_item_t *current, *tmp;
    HASH_ITER(hh, rule_mg->get_match_context, current, tmp) {
      // 从hash表中删除
      HASH_DEL(rule_mg->get_match_context, current);

      // 释放item的内容
      if (current->key) {
        g_waf_rule_free(current->key);
      }
      
      // 释放context中的内容
      string_match_context_t *ctx = &current->context;
      if (ctx->string_patterns_list) {
        for (uint32_t j = 0; j < ctx->string_patterns_num; j++) {
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
      
      // 释放item本身
      g_waf_rule_free(current);
    }
    g_waf_rule_free(rule_mg->get_match_context);
  }

  // 释放规则ID数组
  if (rule_mg->rule_ids) {
    g_waf_rule_free(rule_mg->rule_ids);
  }
}

sign_rule_mg_t *dup_rule_mg(const sign_rule_mg_t *src) {
  if (!src) {
    return NULL;
  }

  // 分配新的规则管理器
  sign_rule_mg_t *dst = g_waf_rule_malloc(sizeof(sign_rule_mg_t));
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
  if (src->rule_masks) {
    dst->rule_masks = g_waf_rule_malloc(dst->max_rules * sizeof(rule_mask_array_t));
    if (!dst->rule_masks) {
      fprintf(stderr, "Failed to allocate rule masks array\n");
      goto error;
    }
    memcpy(dst->rule_masks, src->rule_masks, src->max_rules * sizeof(rule_mask_array_t));
  }

  // 复制get参数hash表
  if (src->get_match_context) {
    // 初始化为NULL，因为我们使用HASH_ADD_KEYPTR来添加项目
    dst->get_match_context = NULL;

    // 遍历源hash表并复制每个item
    hash_pattern_item_t *src_item, *tmp;
    HASH_ITER(hh, src->get_match_context, src_item, tmp) {
      hash_pattern_item_t *new_item = g_waf_rule_malloc(sizeof(hash_pattern_item_t));
      if (!new_item) {
        fprintf(stderr, "Failed to allocate hash pattern item\n");
        goto error;
      }
      memset(new_item, 0, sizeof(hash_pattern_item_t));

      // 复制key
      new_item->key = strdup(src_item->key);
      if (!new_item->key) {
        g_waf_rule_free(new_item);
        fprintf(stderr, "Failed to duplicate key\n");
        goto error;
      }

      // 复制context
      string_match_context_t *src_ctx = &src_item->context;
      string_match_context_t *dst_ctx = &new_item->context;

      if (src_ctx->string_patterns_list) {
        dst_ctx->string_patterns_capacity = src_ctx->string_patterns_capacity;
        dst_ctx->string_patterns_num = src_ctx->string_patterns_num;
        dst_ctx->string_patterns_list = g_waf_rule_malloc(
            dst_ctx->string_patterns_capacity * sizeof(string_pattern_t));
        if (!dst_ctx->string_patterns_list) {
          g_waf_rule_free(new_item->key);
          g_waf_rule_free(new_item);
          fprintf(stderr, "Failed to allocate patterns list\n");
          goto error;
        }

        // 复制每个pattern
        for (uint32_t i = 0; i < src_ctx->string_patterns_num; i++) {
          string_pattern_t *src_pattern = &src_ctx->string_patterns_list[i];
          string_pattern_t *dst_pattern = &dst_ctx->string_patterns_list[i];

          if (src_pattern->string_pattern) {
            dst_pattern->string_pattern = strdup(src_pattern->string_pattern);
            if (!dst_pattern->string_pattern) {
              fprintf(stderr, "Failed to duplicate pattern string\n");
              goto error;
            }
          }

          dst_pattern->hs_flags = src_pattern->hs_flags;
          dst_pattern->relation_count = src_pattern->relation_count;

          if (src_pattern->relation_count > 0) {
            dst_pattern->relations = g_waf_rule_malloc(dst_pattern->relation_count *
                                                       sizeof(rule_relation_t));
            if (!dst_pattern->relations) {
              fprintf(stderr, "Failed to allocate relations\n");
              goto error;
            }
            memcpy(dst_pattern->relations, src_pattern->relations,
                   dst_pattern->relation_count * sizeof(rule_relation_t));
          }
        }
      }

      // 添加到hash表
      HASH_ADD_KEYPTR(hh, dst->get_match_context, new_item->key, strlen(new_item->key), new_item);
    }
  }

  // 分配字符串匹配上下文数组
  dst->string_match_context_array =
      g_waf_rule_malloc(HTTP_VAR_MAX * sizeof(string_match_context_t *));
  if (!dst->string_match_context_array) {
    g_waf_rule_free(dst->rule_masks);
    g_waf_rule_free(dst->rule_ids);
    g_waf_rule_free(dst);
    return NULL;
  }
  memset(dst->string_match_context_array, 0,
         HTTP_VAR_MAX * sizeof(string_match_context_t *));

  // 复制每个字符串匹配上下文
  for (int i = 0; i < HTTP_VAR_MAX; i++) {
    string_match_context_t *src_ctx = src->string_match_context_array[i];
    if (!src_ctx) {
      continue;
    }

    // 创建新的上下文
    string_match_context_t *dst_ctx =
        g_waf_rule_malloc(sizeof(string_match_context_t));
    if (!dst_ctx) {
      goto cleanup;
    }
    memset(dst_ctx, 0, sizeof(string_match_context_t));
    dst->string_match_context_array[i] = dst_ctx;

    // 复制基本字段
    dst_ctx->string_patterns_num = src_ctx->string_patterns_num;
    dst_ctx->db = NULL; // 数据库需要重新编译

    // 分配并复制模式列表
    dst_ctx->string_patterns_capacity = src_ctx->string_patterns_capacity;
    dst_ctx->string_patterns_list = g_waf_rule_malloc(
        dst_ctx->string_patterns_capacity * sizeof(string_pattern_t));
    if (!dst_ctx->string_patterns_list) {
      goto cleanup;
    }
    memset(dst_ctx->string_patterns_list, 0,
           dst_ctx->string_patterns_capacity * sizeof(string_pattern_t));

    // 复制每个模式
    for (uint32_t j = 0; j < src_ctx->string_patterns_num; j++) {
      string_pattern_t *src_pattern = &src_ctx->string_patterns_list[j];
      string_pattern_t *dst_pattern = &dst_ctx->string_patterns_list[j];

      // 复制模式字符串
      dst_pattern->string_pattern =
          g_waf_rule_malloc(strlen(src_pattern->string_pattern) + 1);
      if (!dst_pattern->string_pattern) {
        goto cleanup;
      }
      strcpy(dst_pattern->string_pattern, src_pattern->string_pattern);

      // 复制关系数组
      dst_pattern->relation_count = src_pattern->relation_count;
      dst_pattern->hs_flags = src_pattern->hs_flags;

      if (src_pattern->relation_count > 0) {
        dst_pattern->relations = g_waf_rule_malloc(src_pattern->relation_count *
                                                   sizeof(rule_relation_t));
        if (!dst_pattern->relations) {
          goto cleanup;
        }
        memcpy(dst_pattern->relations, src_pattern->relations,
               src_pattern->relation_count * sizeof(rule_relation_t));
      }
    }

    // 复制string_ids数组（如果存在）
    if (src_ctx->string_ids) {
      dst_ctx->string_ids = g_waf_rule_malloc(src_ctx->string_patterns_num *
                                              sizeof(unsigned int));
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

error:
  // 清理get参数hash表
  if (dst->get_match_context) {
    hash_pattern_item_t *current, *tmp;
    HASH_ITER(hh, dst->get_match_context, current, tmp) {
      // 从hash表中删除
      HASH_DEL(dst->get_match_context, current);

      // 释放item的内容
      if (current->key) {
        g_waf_rule_free(current->key);
      }
      
      // 释放context中的内容
      string_match_context_t *ctx = &current->context;
      if (ctx->string_patterns_list) {
        for (uint32_t j = 0; j < ctx->string_patterns_num; j++) {
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
      
      // 释放item本身
      g_waf_rule_free(current);
    }
    g_waf_rule_free(dst->get_match_context);
  }

  // 清理其他资源
  if (dst->rule_masks) {
    g_waf_rule_free(dst->rule_masks);
  }
  if (dst->rule_ids) {
    g_waf_rule_free(dst->rule_ids);
  }
  if (dst->string_match_context_array) {
    for (int i = 0; i < HTTP_VAR_MAX; i++) {
      string_match_context_t *ctx = dst->string_match_context_array[i];
      if (!ctx)
        continue;

      if (ctx->string_patterns_list) {
        for (uint32_t j = 0; j < ctx->string_patterns_num; j++) {
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
    g_waf_rule_free(dst->string_match_context_array);
  }
  g_waf_rule_free(dst);
  return NULL;
}
