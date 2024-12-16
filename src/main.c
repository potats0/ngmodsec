#include "rule_parser.h"
#include "waf_rule_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 函数声明
void print_binary16(uint16_t num);
void print_binary(unsigned int num);
void print_rule_info(sign_rule_mg_t *rule_mg);
void cleanup_rule_mg(sign_rule_mg_t *rule_mg);
int parse_main(int argc, char *argv[]);

void print_rule_info(sign_rule_mg_t *rule_mg) {
  if (!rule_mg) {
    printf("Rule management structure is NULL\n");
    return;
  }

  printf("Rule Management Structure Info:\n");

  // 打印规则掩码
  printf("\nRule Masks:\n");
  for (uint32_t rule_id = 0; rule_id <= rule_mg->max_rule_id; rule_id++) {
    rule_mask_array_t *rule_mask = &rule_mg->rule_masks[rule_id];
    if (rule_mask->sub_rules_count > 0) {
      printf("Rule %u:\n", rule_id);
      for (uint8_t sub_id = 0; sub_id < rule_mask->sub_rules_count; sub_id++) {
        printf("  Sub-rule %u: and_mask = ", sub_id + 1);
        print_binary16(rule_mask->and_masks[sub_id]);
        printf("\n");
      }
    }
  }

  // 打印上下文信息
  if (rule_mg->string_match_context_array) {
    int i;
    for (i = 0; rule_mg->string_match_context_array[i] != NULL; i++) {
      string_match_context_t *ctx = rule_mg->string_match_context_array[i];
      printf("\nContext %d:\n", i);
      printf("Protocol Variable: %s\n", ctx->proto_var_name);
      printf("Number of patterns: %d\n", ctx->string_patterns_num);

      for (int j = 0; j < ctx->string_patterns_num; j++) {
        string_pattern_t *pattern = &ctx->string_patterns_list[j];
        if (pattern && pattern->string_pattern) {
          printf("  Pattern %d:\n", j);
          printf("    Pattern: %s\n", pattern->string_pattern);
          printf("    Relations count: %d\n", pattern->relation_count);
          printf("    Relations:\n");
          for (int k = 0; k < pattern->relation_count; k++) {
            rule_relation_t *relation = &pattern->relations[k];
            uint32_t rule_id = relation->threat_id >> 8;
            uint8_t sub_id = relation->threat_id & 0xFF;
            printf(
                "      - Rule ID: %u (0x%x), Sub Rule ID: %u, Pattern ID: %u\n",
                rule_id, relation->threat_id, sub_id, relation->pattern_id);
            printf("        and_bit:\t");
            print_binary16(relation->and_bit);
            printf("\n");
          }
        }
      }
    }
    printf("\nTotal contexts: %d\n", i);
  } else {
    printf("No string match contexts found\n");
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

  if (rule_id >= MAX_RULES_NUM || sub_id == 0 || sub_id > MAX_SUB_RULES_NUM) {
    return 0;
  }

  rule_mask_array_t *rule_mask = &rule_mg->rule_masks[rule_id];
  if (sub_id > rule_mask->sub_rules_count) {
    return 0;
  }

  return rule_mask->and_masks[sub_id - 1]; // 子规则ID从1开始，数组索引从0开始
}

// 清理资源
void cleanup_rule_mg(sign_rule_mg_t *rule_mg) {
  if (!rule_mg)
    return;

  if (rule_mg->string_match_context_array) {
    for (int i = 0; rule_mg->string_match_context_array[i] != NULL; i++) {
      string_match_context_t *ctx = rule_mg->string_match_context_array[i];
      if (ctx) {
        if (ctx->string_patterns_list) {
          for (int j = 0; j < ctx->string_patterns_num; j++) {
            string_pattern_t *pattern = &ctx->string_patterns_list[j];
            if (pattern) {
              free(pattern->string_pattern);
              free(pattern->relations);
            }
          }
          free(ctx->string_patterns_list);
        }
        free(ctx);
      }
    }
    free(rule_mg->string_match_context_array);
  }
  free(rule_mg);
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
  cleanup_rule_mg(rule_mg);
  printf("Done.\n");

  return 0;
}

#ifndef TEST_PARSER
int main(int argc, char *argv[]) { return parse_main(argc, argv); }
#endif
