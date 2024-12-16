%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "waf_rule_types.h"
#include "rule_parser.h"
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
sign_rule_mg_t* current_rule_mg = NULL;
uint32_t current_rule_id = 0;    // 当前规则ID
uint8_t current_sub_id = 0;      // 当前子规则ID
uint16_t current_and_bit = 1;    // 当前and_bit，每个子式左移一位
uint16_t current_not_mask = 0;   // 当前NOT掩码

// 用于构建规则管理结构
static void add_pattern_to_context(const char* proto_var, const char* pattern, int is_pcre, uint16_t and_bit, uint32_t flags) {
    uint32_t rule_id = current_rule_id;
    uint8_t sub_id = current_sub_id;
    
    // 检查当前规则和子规则的掩码是否已包含此and_bit
    if (current_rule_mg && rule_id < MAX_RULES_NUM) {
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
    
    printf("Adding pattern: %s to %s (is_pcre: %d, flags: 0x%x) for rule ID: %u (sub_id: %u, and_bit: 0x%x, not_mask: 0x%x)\n", 
           pattern, proto_var, is_pcre, flags, rule_id, sub_id, and_bit, current_not_mask);
    
    if (!current_rule_mg) {
        current_rule_mg = calloc(1, sizeof(sign_rule_mg_t));
        if (!current_rule_mg) {
            fprintf(stderr, "Failed to allocate rule_mg\n");
            return;
        }
        current_rule_mg->string_match_context_array = calloc(4, sizeof(string_match_context_t*));
        if (!current_rule_mg->string_match_context_array) {
            fprintf(stderr, "Failed to allocate context array\n");
            free(current_rule_mg);
            current_rule_mg = NULL;
            return;
        }
        current_rule_mg->max_rule_id = 0;
    }

    // 更新最大规则ID
    if (rule_id > current_rule_mg->max_rule_id) {
        current_rule_mg->max_rule_id = rule_id;
    }

    // 检查规则ID是否有效
    if (rule_id >= MAX_RULES_NUM) {
        fprintf(stderr, "Rule ID %u exceeds maximum allowed (%d)\n", rule_id, MAX_RULES_NUM);
        return;
    }

    // 检查子规则ID是否有效
    if (sub_id >= MAX_SUB_RULES_NUM) {
        fprintf(stderr, "Sub rule ID %u exceeds maximum allowed (%d)\n", sub_id, MAX_SUB_RULES_NUM);
        return;
    }

    // 更新规则掩码
    rule_mask_array_t* rule_mask = &current_rule_mg->rule_masks[rule_id];
    if (sub_id > rule_mask->sub_rules_count) {
        rule_mask->sub_rules_count = sub_id;
    }
    rule_mask->and_masks[sub_id - 1] |= and_bit;  // 子规则ID从1开始，数组索引从0开始
    rule_mask->not_masks[sub_id - 1] |= (current_not_mask & and_bit);  // 更新NOT掩码

    // 查找或创建对应的context
    string_match_context_t* ctx = NULL;
    int ctx_index;
    for (ctx_index = 0; current_rule_mg->string_match_context_array[ctx_index] != NULL; ctx_index++) {
        if (strcmp(current_rule_mg->string_match_context_array[ctx_index]->proto_var_name, proto_var) == 0) {
            ctx = current_rule_mg->string_match_context_array[ctx_index];
            break;
        }
    }

    if (!ctx) {
        ctx = calloc(1, sizeof(string_match_context_t));
        if (!ctx) {
            fprintf(stderr, "Failed to allocate context\n");
            return;
        }
        strncpy(ctx->proto_var_name, proto_var, sizeof(ctx->proto_var_name) - 1);
        ctx->string_patterns_list = calloc(MAX_STRINGS_NUM, sizeof(string_pattern_t));
        if (!ctx->string_patterns_list) {
            fprintf(stderr, "Failed to allocate patterns list\n");
            free(ctx);
            return;
        }
        current_rule_mg->string_match_context_array[ctx_index] = ctx;
        printf("Created new context for %s at index %d\n", proto_var, ctx_index);
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
        if (ctx->string_patterns_num >= MAX_STRINGS_NUM) {
            fprintf(stderr, "Too many patterns for %s\n", proto_var);
            return;
        }
        pattern_entry = &ctx->string_patterns_list[ctx->string_patterns_num];
        pattern_entry->string_pattern = strdup(pattern);
        if (!pattern_entry->string_pattern) {
            fprintf(stderr, "Failed to allocate pattern string\n");
            return;
        }
        pattern_entry->relations = NULL;
        pattern_entry->relation_count = 0;
        pattern_entry->is_pcre = is_pcre;
        pattern_entry->hs_flags = flags;
        ctx->string_patterns_num++;
        printf("Created new pattern at index %d\n", ctx->string_patterns_num - 1);
    }

    // 添加或更新relation
    rule_relation_t* new_relations = realloc(pattern_entry->relations, 
                                           (pattern_entry->relation_count + 1) * sizeof(rule_relation_t));
    if (!new_relations) {
        fprintf(stderr, "Failed to allocate relation\n");
        return;
    }
    pattern_entry->relations = new_relations;
    
    // 添加新的relation
    pattern_entry->relations[pattern_entry->relation_count].threat_id = (rule_id << 8) | sub_id;
    pattern_entry->relations[pattern_entry->relation_count].pattern_id = pattern_entry->relation_count;
    pattern_entry->relations[pattern_entry->relation_count].and_bit = and_bit;
    pattern_entry->relation_count++;
    
    printf("Successfully added relation to pattern. Total relations: %d\n", pattern_entry->relation_count);
}

%}

%union {
    int number;
    char* string;
    uint32_t flags;
    struct {
        char* proto_var;
        char* pattern;
        int is_pcre;
        uint16_t and_bit;
        int is_not;
        uint32_t flags;  // 新增：Hyperscan标志位
    } match_info;
}

%token <number> NUMBER
%token <string> STRING IDENTIFIER
%token RULE CONTAINS MATCHES
%token HTTP_URI HTTP_HEADER HTTP_BODY
%token AND OR NOT
%token LPAREN RPAREN SEMICOLON
%token NOCASE MULTILINE DOTALL SINGLEMATCH  // 新增的选项token

%type <match_info> match_expr
%type <match_info> rule_expr
%type <flags> pattern_flags
%type <flags> pattern_flag

%left OR
%left AND
%right NOT

%%

rules:
    | rules rule
    ;

rule:
    RULE NUMBER {
        printf("Starting rule %d\n", $2);
        current_rule_id = $2;
        current_sub_id = 1;
        current_and_bit = 1;
        current_not_mask = 0;
    } rule_expr SEMICOLON {
        printf("Completed rule %d\n", current_rule_id);
        if ($4.proto_var && $4.pattern) {
            if ($4.is_not) {
                current_not_mask |= $4.and_bit;
                printf("Added NOT mask: 0x%x\n", current_not_mask);
            }
            add_pattern_to_context($4.proto_var, $4.pattern, $4.is_pcre, $4.and_bit, $4.flags);
            free($4.proto_var);
            free($4.pattern);
        }
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

match_expr:
    HTTP_URI CONTAINS STRING pattern_flags {
        printf("Matched HTTP_URI CONTAINS: %s with flags: 0x%x\n", $3, $4);
        $$.proto_var = strdup("http.uri");
        $$.pattern = $3;
        $$.is_pcre = 0;
        $$.and_bit = current_and_bit;
        $$.is_not = 0;
        $$.flags = $4;
        current_and_bit <<= 1;
    }
    | HTTP_URI MATCHES STRING pattern_flags {
        printf("Matched HTTP_URI MATCHES: %s with flags: 0x%x\n", $3, $4);
        $$.proto_var = strdup("http.uri");
        $$.pattern = $3;
        $$.is_pcre = 1;
        $$.and_bit = current_and_bit;
        $$.is_not = 0;
        $$.flags = $4;
        current_and_bit <<= 1;
    }
    | HTTP_HEADER CONTAINS STRING pattern_flags {
        printf("Matched HTTP_HEADER CONTAINS: %s with flags: 0x%x\n", $3, $4);
        $$.proto_var = strdup("http.header");
        $$.pattern = $3;
        $$.is_pcre = 0;
        $$.and_bit = current_and_bit;
        $$.is_not = 0;
        $$.flags = $4;
        current_and_bit <<= 1;
    }
    | HTTP_HEADER MATCHES STRING pattern_flags {
        printf("Matched HTTP_HEADER MATCHES: %s with flags: 0x%x\n", $3, $4);
        $$.proto_var = strdup("http.header");
        $$.pattern = $3;
        $$.is_pcre = 1;
        $$.and_bit = current_and_bit;
        $$.is_not = 0;
        $$.flags = $4;
        current_and_bit <<= 1;
    }
    | HTTP_BODY CONTAINS STRING pattern_flags {
        printf("Matched HTTP_BODY CONTAINS: %s with flags: 0x%x\n", $3, $4);
        $$.proto_var = strdup("http.body");
        $$.pattern = $3;
        $$.is_pcre = 0;
        $$.and_bit = current_and_bit;
        $$.is_not = 0;
        $$.flags = $4;
        current_and_bit <<= 1;
    }
    | HTTP_BODY MATCHES STRING pattern_flags {
        printf("Matched HTTP_BODY MATCHES: %s with flags: 0x%x\n", $3, $4);
        $$.proto_var = strdup("http.body");
        $$.pattern = $3;
        $$.is_pcre = 1;
        $$.and_bit = current_and_bit;
        $$.is_not = 0;
        $$.flags = $4;
        current_and_bit <<= 1;
    }
    ;

rule_expr:
    match_expr {
        printf("Converting match_expr to rule_expr\n");
        $$ = $1;
    }
    | NOT match_expr {
        printf("Processing NOT expression\n");
        $$ = $2;
        $$.is_not = 1;  // 标记为NOT操作
    }
    | NOT LPAREN rule_expr RPAREN {
        printf("Processing NOT group expression\n");
        $$ = $3;
        $$.is_not = 1;  // 标记整个组为NOT操作
        
        // 对于复合NOT，我们需要设置组内所有条件的NOT标记
        if ($3.proto_var && $3.pattern) {
            current_not_mask |= $3.and_bit;
        }
    }
    | rule_expr AND rule_expr {
        printf("Processing AND expression (sub_id: %d)\n", current_sub_id);
        uint8_t max_sub_id = current_sub_id;

        if ($1.proto_var && $1.pattern) {
            if ($1.is_not) {
                current_not_mask |= $1.and_bit;
                printf("Added NOT mask: 0x%x for left expr\n", current_not_mask);
            }
            uint8_t original_sub_id = current_sub_id;
            for (uint8_t sub = 1; sub <= max_sub_id; sub++) {
                current_sub_id = sub;
                add_pattern_to_context($1.proto_var, $1.pattern, $1.is_pcre, $1.and_bit, $1.flags);
            }
            current_sub_id = original_sub_id;
            free($1.proto_var);
            free($1.pattern);
        }

        if ($3.proto_var && $3.pattern) {
            if ($3.is_not) {
                current_not_mask |= $3.and_bit;
                printf("Added NOT mask: 0x%x for right expr\n", current_not_mask);
            }
            uint8_t original_sub_id = current_sub_id;
            for (uint8_t sub = 1; sub <= max_sub_id; sub++) {
                current_sub_id = sub;
                add_pattern_to_context($3.proto_var, $3.pattern, $3.is_pcre, $3.and_bit, $3.flags);
            }
            current_sub_id = original_sub_id;
            free($3.proto_var);
            free($3.pattern);
        }

        $$.proto_var = NULL;
        $$.pattern = NULL;
    }
    | rule_expr OR rule_expr {
        printf("Processing OR expression, creating new sub-rule\n");
        if ($1.proto_var && $1.pattern) {
            if ($1.is_not) {
                current_not_mask |= $1.and_bit;
                printf("Added NOT mask: 0x%x for left expr\n", current_not_mask);
            }
            add_pattern_to_context($1.proto_var, $1.pattern, $1.is_pcre, $1.and_bit, $1.flags);
            free($1.proto_var);
            free($1.pattern);
        }
        current_sub_id++;
        current_and_bit = 1;
        current_not_mask = 0;  // 重置NOT掩码
        printf("Switched to sub-rule %d\n", current_sub_id);
        if ($3.proto_var && $3.pattern) {
            if ($3.is_not) {
                current_not_mask |= $3.and_bit;
                printf("Added NOT mask: 0x%x for right expr\n", current_not_mask);
            }
            add_pattern_to_context($3.proto_var, $3.pattern, $3.is_pcre, $3.and_bit, $3.flags);
            free($3.proto_var);
            free($3.pattern);
        }
        $$.proto_var = NULL;
        $$.pattern = NULL;
    }
    | LPAREN rule_expr RPAREN {
        printf("Processing parenthesized expression\n");
        $$ = $2;
    }
    ;

%%

void yyerror(const char* s) {
    fprintf(stderr, "Parse error near line %d: %s (at or near '%s')\n", 
            yylineno, s, yytext);
}

sign_rule_mg_t* parse_rule_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Cannot open file: %s\n", filename);
        return NULL;
    }

    // 确保全局变量被重置
    if (current_rule_mg) {
        fprintf(stderr, "Warning: current_rule_mg not NULL at start of parsing\n");
        current_rule_mg = NULL;
    }
    current_rule_id = 0;
    current_sub_id = 0;
    current_and_bit = 1;
    current_not_mask = 0;
    
    yyin = file;
    int result = yyparse();
    
    fclose(file);
    
    if (result != 0) {
        fprintf(stderr, "Parsing failed with code %d\n", result);
        return NULL;
    }
    
    return current_rule_mg;
}

sign_rule_mg_t* parse_rule_string(const char* rule_str) {
    // 确保全局变量被重置
    if (current_rule_mg) {
        fprintf(stderr, "Warning: current_rule_mg not NULL at start of parsing\n");
        current_rule_mg = NULL;
    }
    current_rule_id = 0;
    current_sub_id = 0;
    current_and_bit = 1;
    current_not_mask = 0;
    
    void* buffer = yy_scan_string(rule_str);
    if (!buffer) {
        fprintf(stderr, "Failed to create scan buffer\n");
        return NULL;
    }
    
    yy_switch_to_buffer(buffer);
    
    int result = yyparse();
    
    yy_delete_buffer(buffer);
    
    if (result != 0) {
        fprintf(stderr, "Parsing failed with code %d\n", result);
        return NULL;
    }
    
    return current_rule_mg;
}
