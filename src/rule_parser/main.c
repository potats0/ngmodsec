#include "waf_rule_types.h"
#include <hs/hs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 函数声明
void print_binary16(uint16_t num);
void print_binary(unsigned int num);
void print_rule_info(sign_rule_mg_t *rule_mg);
int parse_main(int argc, char *argv[]);
int match_rule_mg(sign_rule_mg_t *rule_mg);

#ifndef TEST_PARSER

void print_rule_info(sign_rule_mg_t *rule_mg) {
  if (!rule_mg) {
    printf("Rule management structure is NULL\n");
    return;
  }

  printf("\nRule Management Structure Info:\n");
  printf("Total Rules: %u\n", rule_mg->rules_count);
  printf("Rule IDs: ");
  for (uint32_t i = 0; i < rule_mg->rules_count; i++) {
    printf("%u ", rule_mg->rule_ids[i]);
  }
  printf("\n\n");

  // 遍历所有有效规则
  for (uint32_t i = 0; i < rule_mg->rules_count; i++) {
    uint32_t rule_id = rule_mg->rule_ids[i];
    rule_mask_array_t *rule_mask = &rule_mg->rule_masks[rule_id];
    printf("Rule %u:\n", rule_id);
    printf("  Sub-rules count: %u\n", rule_mask->sub_rules_count);

    // 遍历所有匹配上下文，找到与当前规则相关的andbit
    if (rule_mg->string_match_context_array) {
      printf("  Rule AndBits:\n");
      for (int ctx_idx = 0;
           rule_mg->string_match_context_array[ctx_idx] != NULL; ctx_idx++) {
        string_match_context_t *ctx =
            rule_mg->string_match_context_array[ctx_idx];
        for (int pat_idx = 0; pat_idx < ctx->string_patterns_num; pat_idx++) {
          string_pattern_t *pattern = &ctx->string_patterns_list[pat_idx];
          for (int rel_idx = 0; rel_idx < pattern->relation_count; rel_idx++) {
            rule_relation_t *rel = &pattern->relations[rel_idx];
            if ((rel->threat_id >> 8) == rule_id) {
              uint8_t sub_id = rel->threat_id & 0xFF;
              printf("    Context %d, Pattern %d (Sub-rule %u): AndBit=0x%x (",
                     ctx_idx, pat_idx, sub_id, rel->and_bit);
              print_binary16(rel->and_bit);
              printf(")\n");
            }
          }
        }
      }
    }

    for (uint8_t sub_id = 0; sub_id < rule_mask->sub_rules_count; sub_id++) {
      printf("  Sub-rule %u:\n", sub_id);
      printf("    AND mask: 0x%x (", rule_mask->and_masks[sub_id]);
      print_binary16(rule_mask->and_masks[sub_id]);
      printf(")\n");
      printf("    NOT mask: 0x%x (", rule_mask->not_masks[sub_id]);
      print_binary16(rule_mask->not_masks[sub_id]);
      printf(")\n");
    }
    printf("\n");
  }

  // 打印所有的匹配上下文
  if (rule_mg->string_match_context_array) {
    for (int i = 0; rule_mg->string_match_context_array[i] != NULL; i++) {
      string_match_context_t *ctx = rule_mg->string_match_context_array[i];
      printf("Match Context %d:\n", i);
      printf("  Protocol Variable: %s\n", ctx->proto_var_name);
      printf("  Pattern Count: %d\n", ctx->string_patterns_num);

      for (int j = 0; j < ctx->string_patterns_num; j++) {
        string_pattern_t *pattern = &ctx->string_patterns_list[j];
        printf("  Pattern %d:\n", j);
        printf("    Content: %s\n", pattern->string_pattern);
        printf("    Is PCRE: %s\n", pattern->is_pcre ? "Yes" : "No");
        printf("    HS Flags: 0x%x\n", pattern->hs_flags);
        printf("    Relations Count: %d\n", pattern->relation_count);

        for (int k = 0; k < pattern->relation_count; k++) {
          rule_relation_t *rel = &pattern->relations[k];
          printf("    Relation %d:\n", k);
          printf("      Threat ID: %u\n", rel->threat_id);
          printf("      Pattern ID: %u\n", rel->pattern_id);
          printf("      AND Bit: 0x%x\n", rel->and_bit);
          printf("      Operator Type: %u\n", rel->operator_type);
        }
      }
      printf("\n");
    }
  } else {
    printf("No string match contexts found.\n");
  }
}

void print_binary16(uint16_t num) {
  char binary[17] = {0}; // 16位二进制数 + 结束符
  int i;

  // 转换为二进制字符串，添加前导零
  for (i = 15; i >= 0; i--) {
    binary[i] = (num & 1) ? '1' : '0';
    num >>= 1;
  }

  // 打印所有16位
  printf("0b%s", binary);
}

void print_binary(unsigned int num) {
  char binary[33] = {0}; // 32位二进制数 + 结束符
  int i;

  // 转换为二进制字符串，添加前导零
  for (i = 31; i >= 0; i--) {
    binary[i] = (num & 1) ? '1' : '0';
    num >>= 1;
  }

  // 打印所有32位
  printf("0b%s", binary);
}

uint16_t find_rule_mask(sign_rule_mg_t *rule_mg, uint32_t threat_id) {
  if (!rule_mg)
    return 0;

  uint32_t rule_id = threat_id >> 8;
  uint8_t sub_id = threat_id & 0xFF;

  if (!rule_mg || rule_id >= rule_mg->max_rules || sub_id == 0 ||
      sub_id > MAX_SUB_RULES_NUM) {
    return 0;
  }

  rule_mask_array_t *rule_mask = &rule_mg->rule_masks[rule_id];
  if (sub_id > rule_mask->sub_rules_count) {
    return 0;
  }

  return rule_mask->and_masks[sub_id - 1]; // 子规则ID从1开始，数组索引从0开始
}

// 检查规则是否匹配
int match_rule_mg(sign_rule_mg_t *rule_mg) {
  if (!rule_mg)
    return 0;

  // 遍历所有有效规则
  for (uint32_t i = 0; i < rule_mg->rules_count; i++) {
    uint32_t rule_id = rule_mg->rule_ids[i];
    rule_mask_array_t *rule_mask = &rule_mg->rule_masks[rule_id];

    // 检查每个子规则
    for (uint8_t sub_id = 0; sub_id < rule_mask->sub_rules_count; sub_id++) {
      uint16_t and_mask = rule_mask->and_masks[sub_id];
      uint16_t not_mask = rule_mask->not_masks[sub_id];

      // 在这里添加规则匹配逻辑
      printf("Checking rule %u sub-rule %u (and_mask: 0x%x, not_mask: 0x%x)\n",
             rule_id, sub_id, and_mask, not_mask);
    }
  }

  return 0;
}

int parse_main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <rule_file>\n", argv[0]);
    return 1;
  }

  printf("Starting rule parser...\n");
  printf("Parsing rules from file: %s\n", argv[1]);

  // 创建并初始化 rule_mg
  sign_rule_mg_t *rule_mg = calloc(1, sizeof(sign_rule_mg_t));
  if (!rule_mg) {
    fprintf(stderr, "Failed to allocate rule_mg\n");
    return 1;
  }

  // 初始化 rule_mg
  if (init_rule_mg(rule_mg) != 0) {
    fprintf(stderr, "Failed to initialize rule_mg\n");
    free(rule_mg);
    return 1;
  }

  // 解析规则文件
  int result = parse_rule_file(argv[1], rule_mg);
  if (result != 0) {
    fprintf(stderr, "Failed to parse rules\n");
    destroy_rule_mg(rule_mg);
    return 1;
  }

  printf("\nParsing completed. Printing results:\n");
  print_rule_info(rule_mg);

  printf("\nCleaning up resources...\n");
  destroy_rule_mg(rule_mg);
  printf("Done.\n");

  return 0;
}

int main(int argc, char *argv[]) { return parse_main(argc, argv); }
#endif
