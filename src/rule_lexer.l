%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "waf_rule_types.h"
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
"http.uri"      { return HTTP_URI; }
"http.header"   { return HTTP_HEADER; }
"http.body"     { return HTTP_BODY; }
"contains"      { return CONTAINS; }
"matches"       { return MATCHES; }
"and"           { return AND; }
"or"            { return OR; }
"not"           { return NOT; }
";"             { return SEMICOLON; }
"/i"            { return NOCASE; }      /* 忽略大小写 */
"/m"            { return MULTILINE; }   /* 多行模式 */
"/s"            { return DOTALL; }      /* 点号匹配换行 */
"/f"            { return SINGLEMATCH; } /* 单次匹配 */
[0-9]+          { 
                    yylval.number = atoi(yytext);
                    return NUMBER;
                }

\"[^\"]*\"      {
                    // 去掉引号并复制字符串
                    int len = strlen(yytext) - 2;  // 减去两个引号
                    char* str = malloc(len + 1);   // +1 用于 null 终止符
                    strncpy(str, yytext + 1, len);
                    str[len] = '\0';
                    yylval.string = str;
                    return STRING;
                }

.               { printf("Unexpected character: %s\n", yytext); }

%%
