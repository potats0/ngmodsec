#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "waf_rule_types.h"
#include "rule_parser.h"

// 函数声明
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
                        printf("      - Rule ID: %u (0x%x), Sub Rule ID: %u, Pattern ID: %u\n", 
                               relation->threat_id >> 8,
                               relation->threat_id,
                               relation->threat_id & 0xFF,
                               relation->pattern_id);
                        printf("        and_bit: ");
                        print_binary(relation->and_bit);
                        printf(" (0x%x)\n        sum_and_bit: ", relation->and_bit);
                        print_binary(relation->sum_and_bit);
                        printf(" (0x%x)\n", relation->sum_and_bit);
                    }
                    printf("    Attribute bit: %u\n", pattern->attribute_bit);
                }
            }
        }
        printf("\nTotal contexts: %d\n", i);
    } else {
        printf("No string match contexts found\n");
    }
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

// 清理资源
void cleanup_rule_mg(sign_rule_mg_t* rule_mg) {
    if (!rule_mg) return;

    if (rule_mg->string_match_context_array) {
        for (int i = 0; rule_mg->string_match_context_array[i] != NULL; i++) {
            string_match_context_t* ctx = rule_mg->string_match_context_array[i];
            if (ctx) {
                if (ctx->string_patterns_list) {
                    for (int j = 0; j < ctx->string_patterns_num; j++) {
                        string_pattern_t* pattern = &ctx->string_patterns_list[j];
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

    sign_rule_mg_t* rule_mg = parse_rule_file(argv[1]);
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
int main(int argc, char *argv[]) {
    return parse_main(argc, argv);
}
#endif
