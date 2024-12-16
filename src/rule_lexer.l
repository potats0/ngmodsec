%{
#include <stdio.h>
#include <string.h>
#include "rule_parser.tab.h"

void yyerror(const char *s);
%}

%%

[ \t\n]+        ; /* 忽略空白字符 */
"rule"          { return RULE; }
"content"       { return CONTENT; }
"pcre"          { return PCRE; }
"http.uri"      { return HTTP_URI; }
"http.header"   { return HTTP_HEADER; }
"http.body"     { return HTTP_BODY; }
"and"           { return AND; }
"or"            { return OR; }
"("             { return LPAREN; }
")"             { return RPAREN; }
";"             { return SEMICOLON; }
[0-9]+          { yylval.number = atoi(yytext); return NUMBER; }
[a-zA-Z][a-zA-Z0-9_]*  { yylval.string = strdup(yytext); return IDENTIFIER; }
\"[^\"]*\"      { 
    yylval.string = strdup(yytext + 1);
    yylval.string[strlen(yylval.string)-1] = 0;
    return STRING;
}
.               { printf("Unknown character: %s\n", yytext); }

%%

int yywrap(void) {
    return 1;
}
