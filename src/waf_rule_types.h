#ifndef __NEW_SIGN_PUB_H__
#define __NEW_SIGN_PUB_H__

#include <hs/hs_common.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifdef WAF
#include "ngx_proto_varid.h"
#include "vs_list.h"
#endif

/** 规则文件加载路径 **/
#define RULE_FILE_PATH                                                         \
  "/usr/local/waf/conf/security_detect/sign_conf/parser_result/predef_rule/"   \
  "string_pattern_dir"
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
// 单个规则中允许的最大字符串模式数量，用于限制字符串匹配上下文数组和模式列表的大小
#define MAX_RULE_PATTERNS_LEN 4096
#define MAX_STRING_LEN 1024
#define MAX_SUB_RULES_NUM 8 // 每个规则的最大子规则数

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
  uint32_t hs_flags;          // Hyperscan标志位
  uint8_t is_pcre;            // 是否为PCRE模式
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
  string_match_context_t **string_match_context_array; // 字符串匹配上下文数组
  rule_mask_array_t *rule_masks; // 规则掩码数组（动态分配）
  uint32_t max_rules;            // 当前分配的最大规则数
  uint32_t rules_count;          // 实际规则数量
  uint32_t *rule_ids;            // 有效规则ID数组
} sign_rule_mg_t;

/**
 * @brief 初始化规则管理器
 * @param rule_mg 要初始化的规则管理器
 * @return 成功返回0，失败返回-1
 */
int init_rule_mg(sign_rule_mg_t *rule_mg);

/**
 * @brief 销毁规则管理器及其所有资源
 * @param rule_mg 要销毁的规则管理器
 */
void destroy_rule_mg(sign_rule_mg_t *rule_mg);

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

/**
 * @brief 解析规则文件，返回规则管理结构
 * @param filename 规则文件的路径
 * @param rule_mg 解析后的规则管理结构
 * @return 0表示成功，非0表示失败
 */
int parse_rule_file(const char *filename, sign_rule_mg_t *rule_mg);

/**
 * @brief 解析规则字符串，返回规则管理结构
 * @param rule_str 包含规则的字符串
 * @param rule_mg 解析后的规则管理结构
 * @return 0表示成功，非0表示失败
 */
int parse_rule_string(const char *rule_str, sign_rule_mg_t *rule_mg);

/**
 * @brief 编译指定上下文的 Hyperscan 数据库
 * @param ctx 要编译的字符串匹配上下文
 * @return 成功返回0，失败返回-1
 */
int compile_hyperscan_database(string_match_context_t *ctx);

/**
 * @brief 编译所有规则上下文的 Hyperscan 数据库
 * @param rule_mg 规则管理器
 * @return 成功返回0，失败返回-1
 */
int compile_all_hyperscan_databases(sign_rule_mg_t *rule_mg);

/** 规则掩码访问辅助函数 **/
static inline u_int16_t get_rule_and_mask(rule_mask_array_t *masks,
                                          int sub_rule_index) {
  return masks->and_masks[sub_rule_index];
}

static inline u_int16_t get_rule_not_mask(rule_mask_array_t *masks,
                                          int sub_rule_index) {
  return masks->not_masks[sub_rule_index];
}

static inline void set_rule_and_mask(rule_mask_array_t *masks,
                                     int sub_rule_index, u_int16_t value) {
  masks->and_masks[sub_rule_index] = value;
}

static inline void set_rule_not_mask(rule_mask_array_t *masks,
                                     int sub_rule_index, u_int16_t value) {
  masks->not_masks[sub_rule_index] = value;
}

#endif // __NEW_SIGN_PUB_H__
