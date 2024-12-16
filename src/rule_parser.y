%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "waf_rule_types.h"
#include "rule_parser.h"

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

// 用于构建规则管理结构
static void add_pattern_to_context(const char* proto_var, const char* pattern, int is_pcre, uint16_t and_bit, uint16_t sum_and_bit) {
    uint32_t threat_id = (current_rule_id << 8) | current_sub_id;
    printf("Adding pattern: %s to %s (is_pcre: %d) for rule ID: %u (sub_id: %u, and_bit: 0x%x, sum_and_bit: 0x%x)\n", 
           pattern, proto_var, is_pcre, current_rule_id, current_sub_id, and_bit, sum_and_bit);
    
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
    }

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
    pattern_entry->relations[pattern_entry->relation_count].threat_id = threat_id;
    pattern_entry->relations[pattern_entry->relation_count].pattern_id = pattern_entry->relation_count;
    pattern_entry->relations[pattern_entry->relation_count].and_bit = and_bit;
    pattern_entry->relations[pattern_entry->relation_count].sum_and_bit = sum_and_bit;
    pattern_entry->relation_count++;
    
    printf("Successfully added relation to pattern. Total relations: %d\n", pattern_entry->relation_count);
}

%}

%union {
    int number;
    char* string;
    struct {
        char* proto_var;
        char* pattern;
        int is_pcre;
        uint16_t and_bit;
        uint16_t sum_and_bit;
    } match_info;
}

%token <number> NUMBER
%token <string> IDENTIFIER STRING
%token RULE CONTENT PCRE
%token HTTP_URI HTTP_HEADER HTTP_BODY
%token AND OR
%token LPAREN RPAREN SEMICOLON

%type <match_info> match_expr
%type <match_info> rule_expr

%%

rules:
    | rules rule
    ;

rule:
    RULE NUMBER {
        printf("Starting rule %d\n", $2);
        current_rule_id = $2;  // 在解析规则内容之前设置规则ID
        current_sub_id = 1;    // 初始化为第一个子规则
        current_and_bit = 1;   // 重置and_bit为1
    } rule_expr SEMICOLON {
        printf("Completed rule %d\n", current_rule_id);
        if ($4.proto_var && $4.pattern) {
            add_pattern_to_context($4.proto_var, $4.pattern, $4.is_pcre, $4.and_bit, $4.sum_and_bit);
            free($4.proto_var);
            free($4.pattern);
        }
    }
    ;

rule_expr:
    match_expr {
        printf("Converting match_expr to rule_expr\n");
        $$ = $1;
        $$.sum_and_bit = $$.and_bit;  // 单个表达式的sum_and_bit等于自己的and_bit
    }
    | rule_expr AND rule_expr {
        printf("Processing AND expression (sub_id: %d)\n", current_sub_id);
        uint16_t sum_and_bit = $1.sum_and_bit | $3.sum_and_bit;  // 合并两边的sum_and_bit
        uint8_t max_sub_id = current_sub_id;

        // 先处理左侧表达式，同样需要添加到所有子规则中
        if ($1.proto_var && $1.pattern) {
            uint8_t original_sub_id = current_sub_id;
            for (uint8_t sub = 1; sub <= max_sub_id; sub++) {
                current_sub_id = sub;
                add_pattern_to_context($1.proto_var, $1.pattern, $1.is_pcre, $1.and_bit, sum_and_bit);
            }
            current_sub_id = original_sub_id;
            free($1.proto_var);
            free($1.pattern);
        }

        // 再处理右侧表达式，需要添加到所有子规则中
        if ($3.proto_var && $3.pattern) {
            uint8_t original_sub_id = current_sub_id;
            for (uint8_t sub = 1; sub <= max_sub_id; sub++) {
                current_sub_id = sub;
                add_pattern_to_context($3.proto_var, $3.pattern, $3.is_pcre, $3.and_bit, sum_and_bit);
            }
            current_sub_id = original_sub_id;
            free($3.proto_var);
            free($3.pattern);
        }

        $$.proto_var = NULL;
        $$.pattern = NULL;
        $$.sum_and_bit = sum_and_bit;
    }
    | rule_expr OR rule_expr {
        printf("Processing OR expression, creating new sub-rule\n");
        if ($1.proto_var && $1.pattern) {
            add_pattern_to_context($1.proto_var, $1.pattern, $1.is_pcre, $1.and_bit, $1.sum_and_bit);
            free($1.proto_var);
            free($1.pattern);
        }
        current_sub_id++;  // 为OR的右边部分创建新的子规则
        current_and_bit = 1;  // 重置and_bit
        printf("Switched to sub-rule %d\n", current_sub_id);
        if ($3.proto_var && $3.pattern) {
            add_pattern_to_context($3.proto_var, $3.pattern, $3.is_pcre, $3.and_bit, $3.sum_and_bit);
            free($3.proto_var);
            free($3.pattern);
        }
        $$.proto_var = NULL;
        $$.pattern = NULL;
        $$.sum_and_bit = 0;  // OR关系不需要sum_and_bit
    }
    | LPAREN rule_expr RPAREN {
        printf("Processing parenthesized expression\n");
        $$ = $2;
    }
    ;

match_expr:
    HTTP_URI CONTENT STRING {
        printf("Matched HTTP_URI CONTENT: %s\n", $3);
        $$.proto_var = strdup("http.uri");
        $$.pattern = $3;
        $$.is_pcre = 0;
        $$.and_bit = current_and_bit;
        current_and_bit <<= 1;  // 为下一个子式准备and_bit
    }
    | HTTP_HEADER CONTENT STRING {
        printf("Matched HTTP_HEADER CONTENT: %s\n", $3);
        $$.proto_var = strdup("http.header");
        $$.pattern = $3;
        $$.is_pcre = 0;
        $$.and_bit = current_and_bit;
        current_and_bit <<= 1;
    }
    | HTTP_BODY CONTENT STRING {
        printf("Matched HTTP_BODY CONTENT: %s\n", $3);
        $$.proto_var = strdup("http.body");
        $$.pattern = $3;
        $$.is_pcre = 0;
        $$.and_bit = current_and_bit;
        current_and_bit <<= 1;
    }
    | HTTP_URI PCRE STRING {
        printf("Matched HTTP_URI PCRE: %s\n", $3);
        $$.proto_var = strdup("http.uri");
        $$.pattern = $3;
        $$.is_pcre = 1;
        $$.and_bit = current_and_bit;
        current_and_bit <<= 1;
    }
    | HTTP_HEADER PCRE STRING {
        printf("Matched HTTP_HEADER PCRE: %s\n", $3);
        $$.proto_var = strdup("http.header");
        $$.pattern = $3;
        $$.is_pcre = 1;
        $$.and_bit = current_and_bit;
        current_and_bit <<= 1;
    }
    | HTTP_BODY PCRE STRING {
        printf("Matched HTTP_BODY PCRE: %s\n", $3);
        $$.proto_var = strdup("http.body");
        $$.pattern = $3;
        $$.is_pcre = 1;
        $$.and_bit = current_and_bit;
        current_and_bit <<= 1;
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
    current_rule_id = 0;  // 重置规则ID
    current_sub_id = 0;   // 重置子规则ID
    
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
    current_rule_id = 0;  // 重置规则ID
    current_sub_id = 0;   // 重置子规则ID
    
    // 创建一个新的扫描缓冲区
    void* buffer = yy_scan_string(rule_str);
    if (!buffer) {
        fprintf(stderr, "Failed to create scan buffer\n");
        return NULL;
    }
    
    // 切换到新的缓冲区
    yy_switch_to_buffer(buffer);
    
    // 解析规则
    int result = yyparse();
    
    // 删除缓冲区
    yy_delete_buffer(buffer);
    
    if (result != 0) {
        fprintf(stderr, "Parsing failed with code %d\n", result);
        return NULL;
    }
    
    return current_rule_mg;
}
