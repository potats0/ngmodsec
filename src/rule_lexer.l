%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rule_parser.tab.h"

extern int yylineno;
%}

%option noyywrap
%option yylineno
%option noinput
%option nounput

%%

[ \t\n]+        ; /* 忽略空白字符 */
#[^\n]*         ; /* 忽略以#开头的单行注释 */
"rule"          { return RULE; }
"content"       { return CONTENT; }
"pcre"          { return PCRE; }
"http.uri"      { return HTTP_URI; }
"http.header"   { return HTTP_HEADER; }
"http.body"     { return HTTP_BODY; }
"and"           { return AND; }
"or"            { return OR; }
"not"           { return NOT; }  /* 添加NOT关键字支持 */
"("             { return LPAREN; }
")"             { return RPAREN; }
";"             { return SEMICOLON; }
"/i"            { return NOCASE; }      /* 忽略大小写 */
"/m"            { return MULTILINE; }   /* 多行模式 */
"/s"            { return DOTALL; }      /* 点号匹配换行 */
"/f"            { return SINGLEMATCH; } /* 单次匹配 */
[0-9]+          { yylval.number = atoi(yytext); return NUMBER; }
[a-zA-Z][a-zA-Z0-9_]*  { yylval.string = strdup(yytext); return IDENTIFIER; }
\"[^\"]*\"      { 
    yylval.string = strdup(yytext + 1);
    yylval.string[strlen(yylval.string)-1] = 0;
    return STRING;
}
.               { printf("Unknown character: %s\n", yytext); }

%%
