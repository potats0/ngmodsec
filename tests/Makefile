CC = gcc
CFLAGS = -I../src -g
LDFLAGS = -lhs

PARSER_SRC = ../src/rule_parser/rule_parser.tab.c \
             ../src/rule_parser/lex.yy.c \
             ../src/rule_parser/pattern_converter.c

test_parser: test_parser.c $(PARSER_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f test_parser *.o
