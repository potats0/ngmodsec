%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ruleset_types.h"
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

// 函数声明
void yyerror(const char *s);
int yylex(void);
int yyparse(void);
int parse_rule_input(const char* rule_str, const char* filename, sign_rule_mg_t* rule_mg);
int parse_rule_string(const char* rule_str, sign_rule_mg_t* rule_mg);
int parse_rule_file(const char* filename, sign_rule_mg_t* rule_mg);

static sign_rule_mg_t* current_rule_mg = NULL;
static uint32_t current_rule_id = 0;    // 当前规则ID
static uint8_t current_sub_id = 0;      // 当前子规则ID
static uint16_t current_and_bit = 1;    // 当前and_bit，每个子式左移一位
static uint16_t current_not_mask = 0;   // 当前NOT掩码

// 字符串列表相关函数声明和实现
static string_list_t* create_string_list(char* first_str);
static string_list_t* append_to_string_list(string_list_t* list, char* str);

static void clenaup_ptr(char** ptr) {
    if (!ptr || !*ptr) return;
    g_waf_rule_free(*ptr);
    *ptr = NULL;
}

// cleanup 
static void cleanup_string_list(string_list_t **list_ptr) {
    if (!list_ptr || !*list_ptr) return;
    
    string_list_t *list = *list_ptr;
    // 释放所有字符串
    for (size_t i = 0; i < list->count; i++) {
        if (list->items[i]) {
            g_waf_rule_free(list->items[i]);
        }
    }
    
    // 释放items数组
    if (list->items) {
        g_waf_rule_free(list->items);
    }
    
    // 释放list结构体本身
    g_waf_rule_free(list);
    *list_ptr = NULL;  // 清空指针
}


static string_list_t* create_string_list(char* first_str) {
    string_list_t* list = g_waf_rule_malloc(sizeof(string_list_t));
    if (!list) return NULL;
    
    list->capacity = 4;  // 初始容量
    list->items = g_waf_rule_malloc(list->capacity * sizeof(char*));
    if (!list->items) {
        g_waf_rule_free(list);
        return NULL;
    }
    
    list->items[0] = first_str;
    list->count = 1;
    return list;
}

static string_list_t* append_to_string_list(string_list_t* list, char* str) {
    if (!list) return NULL;
    
    if (list->count >= list->capacity) {
        size_t new_capacity = list->capacity * 2;
        char** new_items = g_waf_rule_malloc(new_capacity * sizeof(char*));
        if (!new_items) return NULL;
        
        memcpy(new_items, list->items, list->count * sizeof(char*));
        g_waf_rule_free(list->items);
        list->items = new_items;
        list->capacity = new_capacity;
    }
    
    list->items[list->count++] = str;
    return list;
}

// 生成新的未使用的and_bit
static uint16_t generate_new_and_bit(uint16_t current_mask) {
    uint16_t new_bit = 1;
    while ((current_mask & new_bit) && new_bit) {
        new_bit <<= 1;
    }
    return new_bit;
}

// 生成新的未使用的and_bit，并设置到全局变量中current_and_bit
static void set_new_andbit(){
    // 检查并调整and_bit in 中所有的子式共用一个掩码
    if (current_rule_id < current_rule_mg->max_rules) {
        uint16_t current_mask = current_rule_mg->rule_masks[current_rule_id].and_masks[current_sub_id];
        if (current_mask != 0) {  // 如果已经有模式，生成新的 and_bit
            uint16_t new_bit = generate_new_and_bit(current_mask);
            if (!new_bit) {
                fprintf(stderr, "Error: No available and_bit for rule %u sub_rule %u\n", current_rule_id, current_sub_id);
                return ;
            }
            current_and_bit = new_bit;
        }
    }
}

// 确保规则掩码数组有足够空间
static int ensure_rule_mask_capacity(sign_rule_mg_t* rule_mg, uint32_t rule_id) {
    if (rule_id < rule_mg->max_rules) {
        return 0;  // 空间足够
    }

    uint32_t new_size = rule_id + RULESETS_GROWTH_SIZE;  // 每次多分配一些空间
    rule_mask_array_t* new_masks = g_waf_rule_malloc(new_size * sizeof(rule_mask_array_t));
    if (!new_masks) {
        fprintf(stderr, "Failed to reallocate rule masks array\n");
        return -1;
    }

    memset(new_masks, 0, new_size * sizeof(rule_mask_array_t));
    memcpy(new_masks, rule_mg->rule_masks, rule_mg->max_rules * sizeof(rule_mask_array_t));

    // 初始化新分配空间的 method 为 0xFFFFFFFF
    for (uint32_t i = rule_mg->max_rules; i < new_size; i++) {
        for (uint32_t j = 0; j < MAX_SUB_RULES_NUM; j++) {
            new_masks[i].method[j] = 0xFFFFFFFF;
        }
    }

    g_waf_rule_free(rule_mg->rule_masks);
    rule_mg->rule_masks = new_masks;
    rule_mg->max_rules = new_size;
    fprintf(stderr, "successfully reallocated rule masks array to size %d\n", new_size);
    return 0;
}

// 查找或创建匹配上下文
static string_match_context_t* get_or_create_context(sign_rule_mg_t* rule_mg, http_var_type_t proto_var) {
    if (!rule_mg || !rule_mg->string_match_context_array || proto_var >= HTTP_VAR_MAX || proto_var <= HTTP_VAR_UNKNOWN) {
        fprintf(stderr, "Invalid arguments: rule_mg=%p, proto_var=%d\n", rule_mg, proto_var);
        return NULL;
    }

    string_match_context_t* ctx = rule_mg->string_match_context_array[proto_var];
    if (ctx) {
        if (!ctx->string_patterns_list) {
            fprintf(stderr, "Context at index %d has NULL string_patterns_list\n", proto_var);
            return NULL;
        }
        return ctx;
    }

    ctx = g_waf_rule_malloc(sizeof(string_match_context_t));
    if (!ctx) {
        fprintf(stderr, "Failed to allocate context\n");
        return NULL;
    }
    memset(ctx, 0, sizeof(string_match_context_t));

    // 初始分配256个模式的空间
    ctx->string_patterns_capacity = INITIAL_PATTERNS_CAPACITY;
    ctx->string_patterns_list = g_waf_rule_malloc(ctx->string_patterns_capacity * sizeof(string_pattern_t));
    if (!ctx->string_patterns_list) {
        fprintf(stderr, "Failed to allocate patterns list\n");
        g_waf_rule_free(ctx);
        return NULL;
    }

    ctx->string_patterns_num = 0;
    rule_mg->string_match_context_array[proto_var] = ctx;
    printf("Created new context at index %d\n", proto_var);
    return ctx;
}

static int ensure_patterns_capacity(string_match_context_t *ctx) {
    if (ctx->string_patterns_num < ctx->string_patterns_capacity) {
        return 0;  // 空间足够
    }

    uint32_t new_capacity = ctx->string_patterns_capacity + PATTERNS_GROWTH_SIZE;
    string_pattern_t *new_list = g_waf_rule_malloc(new_capacity * sizeof(string_pattern_t));
    if (!new_list) {
        fprintf(stderr, "Failed to reallocate patterns list\n");
        return -1;
    }

    memset(new_list, 0, new_capacity * sizeof(string_pattern_t));
    memcpy(new_list, ctx->string_patterns_list, ctx->string_patterns_num * sizeof(string_pattern_t));
    g_waf_rule_free(ctx->string_patterns_list);
    
    ctx->string_patterns_list = new_list;
    ctx->string_patterns_capacity = new_capacity;
    fprintf(stderr, "Successfully reallocated patterns list to size %d\n", new_capacity);
    return 0;
}

// 查找或创建模式条目
static string_pattern_t* get_or_create_pattern(string_match_context_t* ctx, char* pattern, uint32_t flags) {
    if (!ctx || !ctx->string_patterns_list || !pattern) {
        fprintf(stderr, "Invalid arguments: ctx=%p, pattern=%p\n", ctx, pattern);
        return NULL;
    }

    // 在添加新模式前确保有足够空间
    if (ensure_patterns_capacity(ctx) != 0) {
        return NULL;
    }

    // 查找现有模式
    for (uint32_t i = 0; i < ctx->string_patterns_num; i++) {
        if (ctx->string_patterns_list[i].string_pattern && 
            strcmp(ctx->string_patterns_list[i].string_pattern, pattern) == 0) {
            printf("Found existing pattern at index %d\n", i);
            return &ctx->string_patterns_list[i];
        }
    }

    string_pattern_t* pattern_entry = &ctx->string_patterns_list[ctx->string_patterns_num];

    // 分配并复制模式字符串
    pattern_entry->string_pattern = g_waf_rule_malloc(strlen(pattern) + 1);
    if (!pattern_entry->string_pattern) {
        fprintf(stderr, "Failed to allocate memory for pattern string\n");
        return NULL;
    }
    strcpy(pattern_entry->string_pattern, pattern);

    pattern_entry->relations = NULL;
    pattern_entry->relation_count = 0;
    pattern_entry->hs_flags = flags;
    ctx->string_patterns_num++;
    printf("Created new pattern at index %d\n", ctx->string_patterns_num - 1);
    return pattern_entry;
}

// 添加规则关系
static int add_rule_relation(string_pattern_t* pattern_entry, uint32_t rule_id, uint8_t sub_id, uint16_t and_bit) {
    rule_relation_t* new_relations = g_waf_rule_malloc((pattern_entry->relation_count + 1) * sizeof(rule_relation_t));
    if (!new_relations) {
        fprintf(stderr, "Failed to allocate relation\n");
        return -1;
    }

    if (pattern_entry->relations) {
        memcpy(new_relations, pattern_entry->relations, pattern_entry->relation_count * sizeof(rule_relation_t));
        g_waf_rule_free(pattern_entry->relations);
    }
    pattern_entry->relations = new_relations;

    // 添加新的relation
    pattern_entry->relations[pattern_entry->relation_count].threat_id = (rule_id << 8) | sub_id;
    pattern_entry->relations[pattern_entry->relation_count].pattern_id = pattern_entry->relation_count;
    pattern_entry->relations[pattern_entry->relation_count].and_bit = and_bit;
    pattern_entry->relation_count++;
    
    printf("Successfully added relation to pattern. Total relations: %d\n", pattern_entry->relation_count);
    return 0;
}

// 主函数：添加模式到上下文
static void add_pattern_to_context(http_var_type_t proto_var, char* pattern, uint32_t flags) {
    
    if (!current_rule_mg) {
        fprintf(stderr, "Failed to allocate rule_mg\n");
        return;
    }
    
    printf("Adding pattern: %s to %d (flags: 0x%x) for rule ID: %u (current_sub_id: %u, and_bit: 0x%x, not_mask: 0x%x)\n", 
           pattern, proto_var, flags, current_rule_id, current_sub_id, current_and_bit, current_not_mask);

    // 确保规则掩码数组容量足够
    if (ensure_rule_mask_capacity(current_rule_mg, current_rule_id) != 0) {
        return;
    }

    // 更新规则掩码
    rule_mask_array_t* rule_mask = &current_rule_mg->rule_masks[current_rule_id];
    rule_mask->and_masks[current_sub_id] |= current_and_bit;
    
    if (current_sub_id >= rule_mask->sub_rules_count) {
        rule_mask->sub_rules_count = current_sub_id + 1;
    }

    // 获取或创建上下文
    string_match_context_t* ctx = get_or_create_context(current_rule_mg, proto_var);
    if (!ctx) {
        fprintf(stderr, "Failed to get or create context for proto_var %d\n", proto_var);
        return;
    }

    // 获取或创建模式
    string_pattern_t* pattern_entry = get_or_create_pattern(ctx, pattern, flags);
    if (!pattern_entry) {
        fprintf(stderr, "Failed to get or create pattern for %s\n", pattern);
        return;
    }

    // 添加规则关系
    if (add_rule_relation(pattern_entry, current_rule_id, current_sub_id, current_and_bit) != 0) {
        fprintf(stderr, "Failed to add rule relation for rule %u current_sub_id %u\n", current_rule_id, current_sub_id);
        return;
    }
}

// 辅助函数：处理模式匹配表达式
static int handle_match_expr(http_var_type_t var_type, char* pattern_str, 
                           operator_type_t op_type, uint32_t flags, substr_range_t *range) {
    
    char* converted_pattern __attribute__((cleanup(clenaup_ptr))) = convert_to_hyperscan_pattern(pattern_str, op_type, range);
    if (!converted_pattern) {
        yyerror("Failed to convert pattern");
        return -1;
    }
    
    add_pattern_to_context(var_type, converted_pattern, flags);
    
    return 0;
}

static int handle_kvmatch_expr(hash_pattern_item_t **hash_item, char *param, char* pattern_str,
                            operator_type_t op_type, uint32_t flags ){
    if (!hash_item || !param || !pattern_str) {
        fprintf(stderr, "Invalid arguments to handle_kvmatch_expr\n");
        return -1;
    }

    // Look up the key in the hash table
    hash_pattern_item_t *item = NULL;
    HASH_FIND_STR(*hash_item, param, item);

    char* converted_pattern __attribute__((cleanup(clenaup_ptr))) = convert_to_hyperscan_pattern(pattern_str, op_type, NULL);
    if (!converted_pattern) {
        return -1;
    }
    
    if (item == NULL) {
        // Create new item if it doesn't exist
        item = g_waf_rule_malloc(sizeof(hash_pattern_item_t));
        if (!item) {
            yyerror("Failed to allocate hash pattern item");
            return -1;
        }
        memset(item, 0, sizeof(hash_pattern_item_t));
        
        item->key = my_strdup(param); // 复制param
        
        // 初始化context
        string_match_context_t *ctx = &item->context;
        ctx->string_patterns_capacity = INITIAL_PATTERNS_CAPACITY;
        ctx->string_patterns_num = 0;
        ctx->string_ids = NULL;
        ctx->db = NULL;
        
        ctx->string_patterns_list = g_waf_rule_malloc(ctx->string_patterns_capacity * sizeof(string_pattern_t));
        if (!ctx->string_patterns_list) {
            g_waf_rule_free(item->key);
            g_waf_rule_free(item);
            yyerror("Failed to allocate patterns list");
            return -1;
        }
        memset(ctx->string_patterns_list, 0, ctx->string_patterns_capacity * sizeof(string_pattern_t));
        
        // Add to hash table
        HASH_ADD_KEYPTR(hh, *hash_item, item->key, strlen(item->key), item);
    } 

    // 确保规则掩码数组容量足够
    if (ensure_rule_mask_capacity(current_rule_mg, current_rule_id) != 0) {
        return -1;
    }

    // 更新规则掩码
    rule_mask_array_t* rule_mask = &current_rule_mg->rule_masks[current_rule_id];
    rule_mask->and_masks[current_sub_id] |= current_and_bit;
    
    if (current_sub_id >= rule_mask->sub_rules_count) {
        rule_mask->sub_rules_count = current_sub_id + 1;
    }
    
    // 获取或创建模式
    string_pattern_t* pattern_entry = get_or_create_pattern(&item->context, converted_pattern, flags);
    if (!pattern_entry) {
        yyerror("Failed to get or create pattern");
        return -1;
    }

    // 添加规则关系
    if (add_rule_relation(pattern_entry, current_rule_id, current_sub_id, current_and_bit) != 0) {
        yyerror("Failed to add rule relation");
        return -1;
    }

    return 0;
}

static int handle_kv_string_list_expr(hash_pattern_item_t **hash_item, char *param, char** items, size_t count, uint32_t flags) {
    if (!items || count == 0 || !param) {
        fprintf(stderr, "Invalid string list or param\n");
        return -1;
    }

    int ret = 0;
    char *item_copy = NULL;

    // 为每个字符串创建一个模式并添加到上下文
    for (size_t i = 0; i < count; i++) {
        if (!items[i]) {
            fprintf(stderr, "Invalid string at index %zu\n", i);
            ret = -1;
            break;
        }

        item_copy = items[i];

        if (handle_kvmatch_expr(hash_item, param, item_copy, OP_EQUALS, flags) != 0) {
            ret = -1;
            break;
        }
    }

    return ret;
}

static int handle_string_list_expr(http_var_type_t var_type, char** items, 
                                    size_t count, uint32_t flags, substr_range_t *range) {
    if (!items || count == 0) {
        fprintf(stderr, "Invalid string list\n");
        return -1;
    }

    // 为每个字符串创建一个模式并添加到上下文
    for (size_t i = 0; i < count; i++) {
        if (handle_match_expr(var_type, items[i], OP_EQUALS, flags, range) != 0) {
            return -1;
        }
    }

    return 0;
}

// 辅助函数：处理模式匹配表达式
static int handle_kv_string_list_with_context(hash_pattern_item_t **context, char *param, 
                                            string_list_t *list, uint32_t flags) {
    return handle_kv_string_list_expr(context, param, list->items, list->count, flags);
}

%}

%union {
    char* string;
    int number;
    unsigned int flags;
    http_var_type_t var_type;
    http_var_info_t var_info;
    substr_range_t range;
    uint32_t method;
    int op_type;
    string_list_t* string_list;
}

%token <string> STRING
%token <number> NUMBER
%token <flags> FLAGS
%token <var_type> HTTP_VAR
%token <var_type> HTTP_GET_ARGS
%token <var_type> HTTP_HEADERS_ARGS
%token <string> IDENTIFIER

%token CONTAINS MATCHES STARTS_WITH ENDS_WITH EQUALS IN
%token AND OR NOT
%token RULE SEMICOLON
%token NOCASE MULTILINE DOTALL SINGLEMATCH

%token HTTP_METHOD
%token <method> METHOD
%type  <method> method_expr
%token EQ

%type <flags> pattern_flags
%type <flags> pattern_flag
%type <number> op_type

%type <string_list> string_list
%type <string_list> string_items

%type <var_info> http_var_with_substr
%type <range> substr_range

// 定义运算符优先级和结合性
%left OR
%left AND
%right NOT

%%

rules:
    /* empty */
    | rules rule
    ;

op_type
    : CONTAINS     { $$ = OP_CONTAINS; }
    | MATCHES      { $$ = OP_MATCHES; }
    | STARTS_WITH  { $$ = OP_STARTS_WITH; }
    | ENDS_WITH    { $$ = OP_ENDS_WITH; }
    | EQUALS       { $$ = OP_EQUALS; }
    | IN          { $$ = OP_IN; }
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
        current_rule_mg->rule_ids[current_rule_mg->rules_count] = current_rule_id;
        
        // 设置子规则数量和掩码
        rule_mask_array_t *masks = &current_rule_mg->rule_masks[current_rule_mg->rules_count];
        masks->sub_rules_count = current_sub_id + 1;  // 因为 current_sub_id 从 0 开始
        masks->and_masks[current_sub_id] = current_and_bit;
        masks->not_masks[current_sub_id] = current_not_mask;
        
        current_rule_mg->rules_count++;
        printf("Rule added: id=%u, sub_rules=%u, and_mask=0x%x, not_mask=0x%x\n",
               current_rule_id, masks->sub_rules_count,
               masks->and_masks[current_sub_id],
               masks->not_masks[current_sub_id]);
    }
    ;

method_expr:
    METHOD {
        $$ = $1;
    }
    | method_expr '|' METHOD {
        $$ = $1 | $3;
    }
    ;

rule_expr:
    match_expr {
        printf("Converting match_expr to rule_expr\n");
    }
    | HTTP_METHOD EQ method_expr {
        rule_mask_array_t* rule_mask = &current_rule_mg->rule_masks[current_rule_id];
        rule_mask->method[current_sub_id] = $3;
        printf("Setting HTTP method: %d\n", $3);
    }
    | NOT rule_expr {
        printf("NOT operation\n");
        printf("current_rule_id: %d subid: %d current_and_bit: 0x%x\n", current_rule_id, current_sub_id, current_and_bit);
        rule_mask_array_t* rule_mask = &current_rule_mg->rule_masks[current_rule_id];
        rule_mask->not_masks[current_sub_id] |= current_and_bit;
        printf("current_not_mask: 0x%x\n", rule_mask->not_masks[current_sub_id]);
    }
    | rule_expr AND rule_expr {
        printf("AND operation\n");
    }
    | rule_expr OR  {
        printf("OR operation\n");
        current_sub_id++;  // 为OR操作准备新的and_bit
    }rule_expr
    ;

match_expr:
    http_var_with_substr op_type STRING pattern_flags {
        set_new_andbit();
        char *pattern __attribute__((cleanup(clenaup_ptr))) = $3;

        if ($1.has_range) {
            size_t pattern_len = strlen($3);
            size_t start_pos = $1.range.start;
            size_t end_pos = $1.range.end;
            int range_len = end_pos - start_pos;
            
            // 检查不支持的操作符
            if ($2 != OP_CONTAINS) {
                yyerror("matches, starts_with, ends_with and equals operators do not support substring matching");
                YYERROR;
            }
            
            // 检查模式长度是否大于范围长度
            if (range_len <= 0 && pattern_len > range_len) {
                char error_msg[256];
                snprintf(error_msg, sizeof(error_msg), 
                        "Pattern length (%zu) is larger than the specified range length (%d)", 
                        pattern_len, range_len);
                yyerror(error_msg);
                YYERROR;
            }
        }

        if (handle_match_expr($1.var, pattern, $2, $4, &$1.range) != 0) {
            YYERROR;
        }
    }
    | http_var_with_substr IN string_list pattern_flags {
        set_new_andbit();
        string_list_t *list __attribute__((cleanup(cleanup_string_list))) = $3;

        if ($1.has_range) {
            yyerror("IN operator does not support substring matching");
            YYERROR;
        }
        if (handle_string_list_expr($1.var, list->items, list->count, $4, &$1.range) != 0) {
            YYERROR;
        }
    }
    | HTTP_GET_ARGS '[' STRING ']' op_type STRING pattern_flags {
        set_new_andbit();
        char *param __attribute__((cleanup(clenaup_ptr))) = $3;
        char *pattern __attribute__((cleanup(clenaup_ptr))) = $6;
        if (handle_kvmatch_expr(&current_rule_mg->get_match_context, param, pattern, $5, $7) != 0) {
            YYERROR;
        }
    }    
    | HTTP_GET_ARGS '[' STRING ']' IN string_list pattern_flags {
        set_new_andbit();
        string_list_t *list __attribute__((cleanup(cleanup_string_list))) = $6;
        char *param __attribute__((cleanup(clenaup_ptr))) = $3;
        if (handle_kv_string_list_with_context(&current_rule_mg->get_match_context, param, list, $7) != 0) {
            YYERROR;
        }
    }
    | HTTP_HEADERS_ARGS '[' STRING ']' op_type STRING pattern_flags {
        set_new_andbit();
        char *param __attribute__((cleanup(clenaup_ptr))) = $3;
        char *pattern __attribute__((cleanup(clenaup_ptr))) = $6;
        if (handle_kvmatch_expr(&current_rule_mg->headers_match_context, param, pattern, $5, $7) != 0) {
            YYERROR;
        }
    }
    | HTTP_HEADERS_ARGS '[' STRING ']' IN string_list pattern_flags {
        set_new_andbit();
        string_list_t *list __attribute__((cleanup(cleanup_string_list))) = $6;
        char *param __attribute__((cleanup(clenaup_ptr))) = $3;
        if (handle_kv_string_list_with_context(&current_rule_mg->headers_match_context, param, list, $7) != 0) {
            YYERROR;
        }
    }
    ;

http_var_with_substr: 
    HTTP_VAR {
        $$.var = $1;
        $$.has_range = false;
    }
    | HTTP_VAR substr_range {
        $$.var = $1;
        $$.range = $2;
        $$.has_range = true;
    }
    ;

substr_range:
    '[' NUMBER ',' NUMBER ']' {
        if ($2 < 0 || $4 < $2) {
            yyerror("Invalid substring range");
            YYERROR;
        }
        $$.start = $2;
        $$.end = $4;
    }
    | '[' NUMBER ']' {
        if ($2 < 0) {
            yyerror("Invalid position");
            YYERROR;
        }
        $$.start = $2;
        $$.end = 0;
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

string_list:
    '{' string_items '}' { $$ = $2; }
    ;

string_items:
    STRING { 
        $$ = create_string_list($1);
    }
    | string_items ',' STRING {
        $$ = append_to_string_list($1, $3);
    }
    ;

%%

void yyerror(const char* s) {
    fprintf(stderr, "Parse error near line %d: %s (at or near '%s')\n", 
            yylineno, s, yytext);
}

// 通用的规则解析函数
int parse_rule_input(const char* rule_str, const char* filename, sign_rule_mg_t* rule_mg) {
    if (!rule_mg) {
        fprintf(stderr, "Error: NULL rule_mg provided\n");
        return -1;
    }

    if (!rule_str && !filename) {
        fprintf(stderr, "Error: Both rule_str and filename are NULL\n");
        return -1;
    }

    // 设置全局变量
    current_rule_mg = rule_mg;
    current_rule_id = rule_mg->rules_count;  // 从当前规则数开始，这样可以追加新规则
    current_sub_id = 0;
    current_and_bit = 1;
    current_not_mask = 0;

    int result = -1;
    if (rule_str) {
        printf("Starting rule parsing from string\n");
        void* buffer = yy_scan_string(rule_str);
        if (!buffer) {
            fprintf(stderr, "Error: Failed to create scan buffer\n");
            goto cleanup;
        }
        result = yyparse();
        yy_delete_buffer(buffer);
    } else {
        printf("Starting rule parsing from file: %s\n", filename);
        FILE* file = fopen(filename, "r");
        if (!file) {
            fprintf(stderr, "Error: Cannot open file: %s\n", filename);
            goto cleanup;
        }
        yyin = file;
        result = yyparse();
        fclose(file);
    }

cleanup:
    // 重置全局变量
    current_rule_mg = NULL;
    
    if (result != 0) {
        fprintf(stderr, "Error: Parsing failed with code %d\n", result);
        return -1;
    }

    printf("Successfully parsed rules, total count: %u\n", rule_mg->rules_count);
    return 0;
}