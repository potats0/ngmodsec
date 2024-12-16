#ifndef RULE_PARSER_H
#define RULE_PARSER_H

#include "waf_rule_types.h"

// 从文件解析规则
sign_rule_mg_t* parse_rule_file(const char* filename);

// 从字符串解析规则
sign_rule_mg_t* parse_rule_string(const char* rule_str);

void cleanup_rule_mg(sign_rule_mg_t* rule_mg);
int parse_main(int argc, char *argv[]);

#endif // RULE_PARSER_H
