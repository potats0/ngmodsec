#include "rule_parser.h"
#include "waf_rule_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hs/hs.h>

// 函数声明
void print_binary16(uint16_t num);
void print_binary(unsigned int num);
void print_rule_info(sign_rule_mg_t *rule_mg);
int parse_main(int argc, char *argv[]);
int match_rule_mg(sign_rule_mg_t *rule_mg);

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

    for (uint8_t sub_id = 0; sub_id < rule_mask->sub_rules_count; sub_id++) {
      printf("  Sub-rule %u:\n", sub_id);
      printf("    AND mask: 0x%x\n", rule_mask->and_masks[sub_id]);
      printf("    NOT mask: 0x%x\n", rule_mask->not_masks[sub_id]);
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

  if (!rule_mg || rule_id >= rule_mg->max_rules || sub_id == 0 || sub_id > MAX_SUB_RULES_NUM) {
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
  if (!rule_mg) return 0;

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

  sign_rule_mg_t *rule_mg = parse_rule_file(argv[1]);
  if (!rule_mg) {
    fprintf(stderr, "Failed to parse rules\n");
    return 1;
  }

  printf("\nParsing completed. Printing results:\n");
  print_rule_info(rule_mg);

  printf("\nCleaning up resources...\n");
  printf("Done.\n");

  return 0;
}

#ifndef TEST_PARSER
int main(int argc, char *argv[]) { return parse_main(argc, argv); }
#endif
