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

/** 每协议变量hs最大编译字符串条目 **/
#define MAX_STRINGS_NUM 4096

#define MAX_STRING_LEN 1024

#define MAX_VALUE_CHECK_NUM 1024

/** NGINX协议变量ID和字符串映射 **/
typedef struct proto_var_desc_s {
  char name[MAX_PROTOVAR_NAME_LEN]; // 对应字符串
  int type;                         // nginx协议变量类型
} proto_var_desc;

/** 规则命中子式的逻辑关系 **/
typedef struct rule_relation_s {
#ifdef TODO
  struct list_head list;
#endif
  u_int32_t threat_id; // rule_id
  u_int16_t proto_var_id;
  u_int16_t line_num;          // hs编译时用到
  u_int32_t pattern_id;        // 规则子式id
  u_int32_t pattern_offset;    // 规则子式在规则文件中的偏移
  u_int32_t pattern_len;       // 规则子式长度
  u_int16_t and_bit;           // 命中的子式条件
  u_int16_t sum_and_bit;       // 告警所需子式条件
  u_int32_t attribute_bit;     // 命中的属性条件
  u_int32_t sum_attribute_bit; // 告警所需属性条件
  u_int8_t operator_type;
} rule_relation_t;

/** 字符串类型规则子式结构 **/
typedef struct string_pattern_s {
  char *string_pattern;
#ifdef TODO
  struct list_head relation_list; // 命中子式所涵盖的rule_relation_list
#endif
  int relation_count; // 命中子式所涵盖的relation条目总数
  unsigned int attribute_bit; // 如果该字符串为属性特征，所占属性的bit位
} string_pattern_t;

/** 模式字符串规则匹配上下文 ，以每协议变量分配 **/
typedef struct string_match_context_s {
  char proto_var_name[32];                // 所属协议变量名
  string_pattern_t *string_patterns_list; // 模式字符串list
  int string_patterns_num;                // 模式字符串规则数量

  unsigned int *string_ids; // 编译hs用
  hs_database_t *db;        // hs数据库
} string_match_context_t;

/** 全局规则管理结构mg, 目前只实现字符串 **/
typedef struct sign_rule_mg_s {
  string_match_context_t **string_match_context_array;
} sign_rule_mg_t;

typedef void *(*MALLOC_FUNC)(uint64_t size);
typedef void (*FREE_FUNC)(void *memp);

extern void sign_rule_set_alloc(MALLOC_FUNC f_malloc, FREE_FUNC f_free);

#ifdef WAF
extern proto_var_desc g_pvar_desc[];

extern int32_t protovar_2_ngxid(char *vname);

// Function declarations
vs_proto_var_t *get_protovar(ngx_http_request_t *r, int proto_id);
vs_url_vars_t *get_url_vars(ngx_http_request_t *r);
#endif
#endif
