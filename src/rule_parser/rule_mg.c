#include <stdlib.h>
#include <string.h>
#include <hs/hs.h>
#include "../waf_rule_types.h"

#define DEFAULT_MAX_RULES 10000

int init_rule_mg(sign_rule_mg_t *rule_mg) {
    if (!rule_mg) {
        return -1;
    }

    // 初始化基本字段
    rule_mg->max_rules = DEFAULT_MAX_RULES;
    rule_mg->rules_count = 0;

    // 分配规则ID数组
    rule_mg->rule_ids = calloc(DEFAULT_MAX_RULES, sizeof(uint32_t));
    if (!rule_mg->rule_ids) {
        return -1;
    }

    // 分配规则掩码数组
    rule_mg->rule_masks = calloc(1, sizeof(rule_mask_array_t));
    if (!rule_mg->rule_masks) {
        free(rule_mg->rule_ids);
        return -1;
    }

    // 初始化掩码数组为0
    memset(rule_mg->rule_masks->and_masks, 0, sizeof(rule_mg->rule_masks->and_masks));
    memset(rule_mg->rule_masks->not_masks, 0, sizeof(rule_mg->rule_masks->not_masks));

    // 分配字符串匹配上下文数组
    rule_mg->string_match_context_array = calloc(DEFAULT_MAX_RULES + 1, sizeof(string_match_context_t*));
    if (!rule_mg->string_match_context_array) {
        free(rule_mg->rule_masks);
        free(rule_mg->rule_ids);
        return -1;
    }

    return 0;
}

void destroy_rule_mg(sign_rule_mg_t* rule_mg) {
    if (!rule_mg) {
        return;
    }

    // 释放字符串匹配上下文数组中的每个元素
    if (rule_mg->string_match_context_array) {
        for (uint32_t i = 0; i < rule_mg->rules_count; i++) {
            if (rule_mg->string_match_context_array[i]) {
                // 释放 Hyperscan 数据库
                if (rule_mg->string_match_context_array[i]->db) {
                    hs_free_database(rule_mg->string_match_context_array[i]->db);
                    rule_mg->string_match_context_array[i]->db = NULL;
                }
                // TODO: 这里需要实现string_match_context_t的清理函数
                free(rule_mg->string_match_context_array[i]);
            }
        }
        free(rule_mg->string_match_context_array);
    }

    // 释放规则掩码数组
    if (rule_mg->rule_masks) {
        free(rule_mg->rule_masks);
    }

    // 释放规则ID数组
    if (rule_mg->rule_ids) {
        free(rule_mg->rule_ids);
    }

    // 释放规则管理器本身
    free(rule_mg);
}
