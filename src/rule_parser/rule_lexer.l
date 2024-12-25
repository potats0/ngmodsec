%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ruleset_types.h"
#include "rule_parser.tab.h"

extern int yylineno;
extern YYSTYPE yylval;
%}

%option noyywrap
%option yylineno
%option noinput
%option nounput

%%

[ \t\n]+        ; /* 忽略空白字符 */
#[^\n]*         ; /* 忽略以#开头的单行注释 */
"rule"          { return RULE; }
"http.uri"      { yylval.var_type = HTTP_VAR_URI; return HTTP_VAR; }
"http.header"   { yylval.var_type = HTTP_VAR_HEADER; return HTTP_VAR; }
"http.raw_req_body"     { yylval.var_type = HTTP_VAR_RAW_REQ_BODY; return HTTP_VAR; }
"http.host"     { yylval.var_type = HTTP_VAR_HOST; return HTTP_VAR; }
"http.unparsed_uri"     { yylval.var_type = HTTP_VAR_UNPARSED_URI; return HTTP_VAR; }
"http.exten"     { yylval.var_type = HTTP_VAR_EXTEN; return HTTP_VAR; }
"http.user-agent"   { yylval.var_type = HTTP_VAR_UA; return HTTP_VAR; }
"http.get_args"     { yylval.var_type = HTTP_VAR_GET_ARGS; return HTTP_GET_ARGS; }
"http.headers"   { yylval.var_type = HTTP_VAR_GET_ARGS; return HTTP_HEADERS_ARGS; }
"http.method"     { return HTTP_METHOD; }
"GET"             { yylval.method = 0x00000002; return METHOD; }
"HEAD"            { yylval.method = 0x00000004; return METHOD; }
"POST"            { yylval.method = 0x00000008; return METHOD; }
"PUT"             { yylval.method = 0x00000010; return METHOD; }
"DELETE"          { yylval.method = 0x00000020; return METHOD; }
"MKCOL"           { yylval.method = 0x00000040; return METHOD; }
"COPY"            { yylval.method = 0x00000080; return METHOD; }
"MOVE"            { yylval.method = 0x00000100; return METHOD; }
"OPTIONS"         { yylval.method = 0x00000200; return METHOD; }
"PROPFIND"        { yylval.method = 0x00000400; return METHOD; }
"PROPPATCH"       { yylval.method = 0x00000800; return METHOD; }
"LOCK"            { yylval.method = 0x00001000; return METHOD; }
"UNLOCK"          { yylval.method = 0x00002000; return METHOD; }
"PATCH"           { yylval.method = 0x00004000; return METHOD; }
"TRACE"           { yylval.method = 0x00008000; return METHOD; }
"CONNECT"         { yylval.method = 0x00010000; return METHOD; }
"="             { return EQ; }
"|"             { return '|'; }
"contains"      { return CONTAINS; }
"matches"       { return MATCHES; }
"starts_with"   { return STARTS_WITH; }
"ends_with"     { return ENDS_WITH; }
"equals"        { return EQUALS; }
"and"           { return AND; }
"or"            { return OR; }
"not"           { return NOT; }
";"             { return SEMICOLON; }
"["             { return '['; }
"]"             { return ']'; }
"/i"            { return NOCASE; }      /* 忽略大小写 */
"/m"            { return MULTILINE; }   /* 多行模式 */
"/s"            { return DOTALL; }      /* 点号匹配换行 */
"/f"            { return SINGLEMATCH; } /* 单次匹配 */
[0-9]+              { yylval.number = atoi(yytext); return NUMBER; }
\"[^\"]*\"          { yylval.string = strdup(yytext + 1);
                      yylval.string[strlen(yylval.string) - 1] = '\0';
                      return STRING; }
[a-zA-Z0-9_\-.]+       { yylval.string = strdup(yytext); return IDENTIFIER; }
.               { 
                    fprintf(stderr, "Error: Unexpected character '%s' at line %d\n", yytext, yylineno);
                    return YYUNDEF;  /* 返回一个未定义的 token，让 bison 处理错误 */
                }

%%
