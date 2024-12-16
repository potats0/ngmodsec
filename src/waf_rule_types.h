#ifndef __NEW_SIGN_PUB_H__
#define __NEW_SIGN_PUB_H__

#include <hs/hs_common.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#ifdef WAF
#include "ngx_proto_varid.h"
#include "vs_list.h"
#endif

/** 规则文件加载路径 **/
#define STR_FILE_PATH                                                          \
  "/usr/local/waf/conf/security_detect/sign_conf/parser_result/predef_rule/"   \
  "string_pattern_dir"
#define PCRE_FILE_PATH                                                         \
  "/usr/local/waf/conf/security_detect/sign_conf/parser_result/predef_rule/"   \
  "pcre_pattern_dir"
#define RELA_FILE_PATH                                                         \
  "/usr/local/waf/conf/security_detect/sign_conf/parser_result/predef_rule/"   \
  "relation_dir"
#define CONF1_NEW_SIGN_ENGINE 1

#define MAX_FILE_NAME_LEN 512
#define MAX_PROTOVAR_NAME_LEN 32
#define MAX_STRINGS_NUM 4096
#define MAX_STRING_LEN 1024
#define MAX_RULES_NUM 1024   // 最大规则数
#define MAX_SUB_RULES_NUM 16 // 每个规则的最大子规则数

/** 规则掩码存储结构 **/
typedef struct rule_mask_array_s {
  u_int16_t and_masks[MAX_SUB_RULES_NUM]; // 每个子规则的条件掩码
  u_int16_t not_masks[MAX_SUB_RULES_NUM]; // 每个子规则的NOT条件掩码
  u_int8_t sub_rules_count;               // 实际子规则数量
} rule_mask_array_t;

/** NGINX协议变量ID和字符串映射 **/
typedef struct proto_var_desc_s {
  char name[MAX_PROTOVAR_NAME_LEN]; // 对应字符串
  int type;                         // nginx协议变量类型
} proto_var_desc;

/** 规则命中子式的逻辑关系 **/
typedef struct rule_relation_s {
  u_int32_t threat_id;  // 规则子式id (rule_id<<8|sub_id)
  u_int32_t pattern_id; // 规则子式在string_patterns_list中的索引
  u_int16_t and_bit;    // 命中的子式条件
  u_int8_t operator_type;
} rule_relation_t;

/** 字符串类型规则子式结构 **/
typedef struct string_pattern_s {
  char *string_pattern;       // 匹配的字符串模式
  rule_relation_t *relations; // 引用这个模式的规则关系数组
  int relation_count;         // 引用这个模式的规则关系数量
} string_pattern_t;

/** 模式字符串规则匹配上下文，以每协议变量分配 **/
typedef struct string_match_context_s {
  char proto_var_name[32];                // 所属协议变量名
  string_pattern_t *string_patterns_list; // 模式字符串list
  int string_patterns_num;                // 模式字符串规则数量
  unsigned int *string_ids; // 编译hs用，对应string_patterns_list的索引
  hs_database_t *db;        // hs数据库
} string_match_context_t;

/** 全局规则管理结构mg, 目前只实现字符串 **/
typedef struct sign_rule_mg_s {
  string_match_context_t **string_match_context_array;
  rule_mask_array_t rule_masks[MAX_RULES_NUM]; // 规则掩码数组，索引为rule_id
  u_int32_t max_rule_id;                       // 最大规则ID
} sign_rule_mg_t;

typedef void *(*waf_rule_malloc_fn)(uint64_t size);
typedef void (*waf_rule_free_fn)(void *memp);

extern void sign_rule_set_alloc(waf_rule_malloc_fn f_malloc,
                                waf_rule_free_fn f_free);

#ifdef WAF
extern proto_var_desc g_pvar_desc[];

extern int32_t protovar_2_ngxid(char *vname);

// Function declarations
vs_proto_var_t *get_protovar(ngx_http_request_t *r, int proto_id);
vs_url_vars_t *get_url_vars(ngx_http_request_t *r);
#endif
#endif
