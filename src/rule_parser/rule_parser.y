%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "waf_rule_types.h"
#include "pattern_converter.h"
#include <hs/hs.h>

extern int yylex();
extern int yyparse();
extern FILE* yyin;
extern int yylineno;
extern char* yytext;
extern void yy_switch_to_buffer(void* buffer);
extern void* yy_scan_string(const char* str);
extern void yy_delete_buffer(void* buffer);

void yyerror(const char* s);
static sign_rule_mg_t* current_rule_mg = NULL;
static uint32_t current_rule_id = 0;    // 当前规则ID
static uint8_t current_sub_id = 0;      // 当前子规则ID
static uint16_t current_and_bit = 1;    // 当前and_bit，每个子式左移一位
static uint16_t current_not_mask = 0;   // 当前NOT掩码

static void add_pattern_to_context(http_var_type_t proto_var, const char* pattern, int is_pcre, uint16_t and_bit, uint32_t flags) {
    uint32_t rule_id = current_rule_id;
    uint8_t sub_id = current_sub_id;
    
    // 检查当前规则和子规则的掩码是否已包含此and_bit
    if (current_rule_mg && rule_id < current_rule_mg->max_rules) {
        uint16_t current_mask = current_rule_mg->rule_masks[rule_id].and_masks[sub_id - 1];
        if (current_mask & and_bit) {
            // 如果当前and_bit已存在于掩码中，生成新的未使用的and_bit
            uint16_t new_bit = 1;
            while ((current_mask & new_bit) && new_bit) {
                new_bit <<= 1;
            }
            if (!new_bit) {
                fprintf(stderr, "Error: No available and_bit for rule %u sub_rule %u\n", rule_id, sub_id);
                return;
            }
            and_bit = new_bit;
        }
    }
    
    printf("Adding pattern: %s to %d (is_pcre: %d, flags: 0x%x) for rule ID: %u (sub_id: %u, and_bit: 0x%x, not_mask: 0x%x)\n", 
           pattern, proto_var, is_pcre, flags, rule_id, sub_id, and_bit, current_not_mask);
    
    if (!current_rule_mg) {
        fprintf(stderr, "Failed to allocate rule_mg\n");
        return;
    }

    // 检查规则ID是否有效，如果需要扩展规则掩码数组
    if (rule_id >= current_rule_mg->max_rules) {
        uint32_t new_size = rule_id + 128; // 每次多分配一些空间
        rule_mask_array_t *new_masks = g_waf_rule_malloc(new_size * sizeof(rule_mask_array_t));
        if (!new_masks) {
            fprintf(stderr, "Failed to reallocate rule masks array\n");
            return;
        }
        // 将新分配的内存初始化为0
        memset(new_masks, 0, new_size * sizeof(rule_mask_array_t));
        memcpy(new_masks, current_rule_mg->rule_masks, current_rule_mg->max_rules * sizeof(rule_mask_array_t));
        g_waf_rule_free(current_rule_mg->rule_masks);
        current_rule_mg->rule_masks = new_masks;
        current_rule_mg->max_rules = new_size;
    }

    // 更新规则掩码
    rule_mask_array_t* rule_mask = &current_rule_mg->rule_masks[rule_id];
    rule_mask->and_masks[sub_id] |= and_bit;  // 注意：sub_id从0开始
    rule_mask->not_masks[sub_id] |= (current_not_mask & and_bit);
    
    // 更新子规则数量
    if (sub_id >= rule_mask->sub_rules_count) {
        rule_mask->sub_rules_count = sub_id + 1;
    }

    // 查找或创建对应的context
    string_match_context_t* ctx = current_rule_mg->string_match_context_array[proto_var];
    if (!ctx) {
        ctx = g_waf_rule_malloc(sizeof(string_match_context_t));
        if (!ctx) {
            fprintf(stderr, "Failed to allocate context\n");
            return;
        }
        memset(ctx, 0, sizeof(string_match_context_t));
        ctx->string_patterns_list = g_waf_rule_malloc(MAX_RULE_PATTERNS_LEN * sizeof(string_pattern_t));
        if (!ctx->string_patterns_list) {
            fprintf(stderr, "Failed to allocate patterns list\n");
            g_waf_rule_free(ctx);
            return;
        }
        memset(ctx->string_patterns_list, 0, MAX_RULE_PATTERNS_LEN * sizeof(string_pattern_t));
        ctx->string_patterns_num = 0;
        current_rule_mg->string_match_context_array[proto_var] = ctx;
        printf("Created new context at index %d\n", proto_var);
    }

    // 查找是否已存在相同的pattern
    string_pattern_t* pattern_entry = NULL;
    for (int i = 0; i < ctx->string_patterns_num; i++) {
        if (strcmp(ctx->string_patterns_list[i].string_pattern, pattern) == 0) {
            pattern_entry = &ctx->string_patterns_list[i];
            printf("Found existing pattern at index %d\n", i);
            break;
        }
    }

    if (!pattern_entry) {
        if (ctx->string_patterns_num >= MAX_RULE_PATTERNS_LEN) {
            fprintf(stderr, "Too many patterns\n");
            return;
        }
        pattern_entry = &ctx->string_patterns_list[ctx->string_patterns_num];
        pattern_entry->string_pattern = g_waf_rule_malloc(strlen(pattern) + 1);
        if (!pattern_entry->string_pattern) {
            fprintf(stderr, "Failed to allocate pattern string\n");
            return;
        }
        strcpy(pattern_entry->string_pattern, pattern);
        pattern_entry->relations = NULL;
        pattern_entry->relation_count = 0;
        pattern_entry->is_pcre = is_pcre;
        pattern_entry->hs_flags = flags;
        ctx->string_patterns_num++;
        printf("Created new pattern at index %d\n", ctx->string_patterns_num - 1);
    }

    // 添加或更新relation
    rule_relation_t* new_relations = g_waf_rule_malloc((pattern_entry->relation_count + 1) * sizeof(rule_relation_t));
    if (!new_relations) {
        fprintf(stderr, "Failed to allocate relation\n");
        return;
    }
    if (pattern_entry->relations) {
        memcpy(new_relations, pattern_entry->relations, pattern_entry->relation_count * sizeof(rule_relation_t));
        g_waf_rule_free(pattern_entry->relations);
    }
    pattern_entry->relations = new_relations;
    
    // 添加新的relation
    pattern_entry->relations[pattern_entry->relation_count].threat_id = (rule_id << 8) | (sub_id + 1);
    pattern_entry->relations[pattern_entry->relation_count].pattern_id = pattern_entry->relation_count;
    pattern_entry->relations[pattern_entry->relation_count].and_bit = and_bit;
    pattern_entry->relation_count++;
    
    printf("Successfully added relation to pattern. Total relations: %d\n", pattern_entry->relation_count);
}
%}

%union {
    char* string;
    int number;
    unsigned int flags;
    http_var_type_t var_type;
}

%token <string> STRING
%token <number> NUMBER
%token <flags> FLAGS
%token <var_type> HTTP_VAR

%token CONTAINS MATCHES STARTS_WITH ENDS_WITH EQUALS
%token AND OR NOT
%token LPAREN RPAREN
%token RULE SEMICOLON
%token NOCASE MULTILINE DOTALL SINGLEMATCH

%type <flags> pattern_flags
%type <flags> pattern_flag

// 定义运算符优先级和结合性
%left OR
%left AND
%right NOT

%%

rules:
    /* empty */
    | rules rule
    ;

rule:
    RULE NUMBER {
        printf("Processing rule %d\n", $2);
        current_rule_id = $2;
        current_sub_id = 0;
        current_and_bit = 1;
        current_not_mask = 0;

        // 检查规则ID是否已存在
        for (uint32_t i = 0; i < current_rule_mg->rules_count; i++) {
            if (current_rule_mg->rule_ids[i] == current_rule_id) {
                yyerror("Duplicate rule ID");
                YYERROR;
            }
        }
    } rule_expr SEMICOLON {
        // 添加规则ID到列表中
        uint32_t* new_ids = g_waf_rule_malloc((current_rule_mg->rules_count + 1) * sizeof(uint32_t));
        if (!new_ids) {
            yyerror("Failed to allocate memory for rule IDs");
            YYERROR;
        }
        memcpy(new_ids, current_rule_mg->rule_ids, current_rule_mg->rules_count * sizeof(uint32_t));
        g_waf_rule_free(current_rule_mg->rule_ids);
        current_rule_mg->rule_ids = new_ids;
        current_rule_mg->rule_ids[current_rule_mg->rules_count++] = current_rule_id;
    }
    ;

rule_expr:
    match_expr {
        printf("Converting match_expr to rule_expr\n");
    }
    | NOT rule_expr {
        printf("NOT operation\n");
        current_not_mask |= current_and_bit;
    }
    | rule_expr AND rule_expr {
        printf("AND operation\n");
    }
    | rule_expr OR rule_expr {
        printf("OR operation\n");
        current_and_bit <<= 1;  // 为OR操作准备新的and_bit
    }
    | LPAREN rule_expr RPAREN {
        printf("Parentheses expression\n");
    }
    ;

match_expr:
    HTTP_VAR CONTAINS STRING pattern_flags {
        printf("Matched HTTP variable type %d CONTAINS: %s with flags: 0x%x\n", $1, $3, $4);
        char* converted_pattern = convert_to_hyperscan_pattern($3, OP_CONTAINS);
        if (!converted_pattern) {
            yyerror("Failed to convert pattern");
            YYERROR;
        }
        add_pattern_to_context($1, converted_pattern, 0, current_and_bit, $4);
        g_waf_rule_free(converted_pattern);
    }
    | HTTP_VAR MATCHES STRING pattern_flags {
        printf("Matched HTTP variable type %d MATCHES: %s with flags: 0x%x\n", $1, $3, $4);
        char* converted_pattern = convert_to_hyperscan_pattern($3, OP_MATCHES);
        if (!converted_pattern) {
            yyerror("Failed to convert pattern");
            YYERROR;
        }
        add_pattern_to_context($1, converted_pattern, 1, current_and_bit, $4);
        g_waf_rule_free(converted_pattern);
    }
    | HTTP_VAR STARTS_WITH STRING pattern_flags {
        printf("Matched HTTP variable type %d STARTS_WITH: %s with flags: 0x%x\n", $1, $3, $4);
        char* converted_pattern = convert_to_hyperscan_pattern($3, OP_STARTS_WITH);
        if (!converted_pattern) {
            yyerror("Failed to convert pattern");
            YYERROR;
        }
        add_pattern_to_context($1, converted_pattern, 0, current_and_bit, $4);
        g_waf_rule_free(converted_pattern);
    }
    | HTTP_VAR ENDS_WITH STRING pattern_flags {
        printf("Matched HTTP variable type %d ENDS_WITH: %s with flags: 0x%x\n", $1, $3, $4);
        char* converted_pattern = convert_to_hyperscan_pattern($3, OP_ENDS_WITH);
        if (!converted_pattern) {
            yyerror("Failed to convert pattern");
            YYERROR;
        }
        add_pattern_to_context($1, converted_pattern, 0, current_and_bit, $4);
        g_waf_rule_free(converted_pattern);
    }
    | HTTP_VAR EQUALS STRING pattern_flags {
        printf("Matched HTTP variable type %d EQUALS: %s with flags: 0x%x\n", $1, $3, $4);
        char* converted_pattern = convert_to_hyperscan_pattern($3, OP_EQUALS);
        if (!converted_pattern) {
            yyerror("Failed to convert pattern");
            YYERROR;
        }
        add_pattern_to_context($1, converted_pattern, 0, current_and_bit, $4);
        g_waf_rule_free(converted_pattern);
    }
    ;

pattern_flags:
    /* empty */ { $$ = 0; }
    | pattern_flags pattern_flag { $$ = $1 | $2; }
    ;

pattern_flag:
    NOCASE { $$ = HS_FLAG_CASELESS; }
    | MULTILINE { $$ = HS_FLAG_MULTILINE; }
    | DOTALL { $$ = HS_FLAG_DOTALL; }
    | SINGLEMATCH { $$ = HS_FLAG_SINGLEMATCH; }
    ;

%%

void yyerror(const char* s) {
    fprintf(stderr, "Parse error near line %d: %s (at or near '%s')\n", 
            yylineno, s, yytext);
}

int parse_rule_string(const char* rule_str, sign_rule_mg_t* rule_mg) {
    if (!rule_str) {
        fprintf(stderr, "Error: NULL rule string provided\n");
        return -1;
    }

    if (!rule_mg) {
        fprintf(stderr, "Error: NULL rule_mg provided\n");
        return -1;
    }

    // 设置全局变量
    current_rule_mg = rule_mg;
    current_rule_id = rule_mg->rules_count;  // 从当前规则数开始，这样可以追加新规则
    current_sub_id = 0;
    current_and_bit = 1;
    current_not_mask = 0;

    printf("Starting rule parsing from string\n");
    void* buffer = yy_scan_string(rule_str);
    if (!buffer) {
        fprintf(stderr, "Error: Failed to create scan buffer\n");
        return -1;
    }

    int result = yyparse();
    yy_delete_buffer(buffer);

    // 重置全局变量
    current_rule_mg = NULL;
    
    if (result != 0) {
        fprintf(stderr, "Error: Parsing failed with code %d\n", result);
        return -1;
    }

    printf("Successfully parsed rules, total count: %u\n", rule_mg->rules_count);
    return 0;
}

int parse_rule_file(const char* filename, sign_rule_mg_t* rule_mg) {
    if (!filename) {
        fprintf(stderr, "Error: NULL filename provided\n");
        return -1;
    }

    if (!rule_mg) {
        fprintf(stderr, "Error: NULL rule_mg provided\n");
        return -1;
    }

    FILE* file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file: %s\n", filename);
        return -1;
    }

    // 设置全局变量
    current_rule_mg = rule_mg;
    current_rule_id = rule_mg->rules_count;  // 从当前规则数开始，这样可以追加新规则
    current_sub_id = 0;
    current_and_bit = 1;
    current_not_mask = 0;
    
    printf("Starting rule parsing from file: %s\n", filename);
    yyin = file;
    int result = yyparse();
    fclose(file);

    // 重置全局变量
    current_rule_mg = NULL;
    
    if (result != 0) {
        fprintf(stderr, "Error: Parsing failed with code %d\n", result);
        return -1;
    }

    printf("Successfully parsed rules, total count: %u\n", rule_mg->rules_count);
    return 0;

}
