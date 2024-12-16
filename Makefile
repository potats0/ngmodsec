NGINX_PATH ?= $(shell pwd)/../nginx
MODULE_PATH = $(shell pwd)
MODULE_NAME = ngx_http_waf_rule_match_engine_module

CORE_INCS = -I$(NGINX_PATH)/src/core \
            -I$(NGINX_PATH)/src/event \
            -I$(NGINX_PATH)/src/http \
            -I$(NGINX_PATH)/src/os/unix

CC = cc
CFLAGS = -g -O0 -Wall $(CORE_INCS)

# 源文件和目标文件
PARSER_SRCS = src/rule_parser.tab.c src/lex.yy.c
PARSER_OBJS = src/rule_parser.tab.o src/lex.yy.o
MODULE_SRCS = $(wildcard src/*.c)
MODULE_OBJS = $(MODULE_SRCS:.c=.o)

# 主要目标
all: prepare build verify

# 解析器目标
rule_parser: $(PARSER_OBJS) src/main.o
	$(CC) $(CFLAGS) $(CORE_INCS) $^ -o $@

# 测试程序目标
test_parser: $(PARSER_OBJS) src/main_test.o tests/test_parser.o
	$(CC) $(CFLAGS) $^ -o $@

# 编译规则
src/rule_parser.tab.c src/rule_parser.tab.h: src/rule_parser.y
	cd src && bison -d rule_parser.y

src/lex.yy.c: src/rule_lexer.l src/rule_parser.tab.h
	cd src && flex rule_lexer.l

src/main.o: src/main.c
	$(CC) $(CFLAGS) $(CORE_INCS) -c $< -o $@

src/main_test.o: src/main.c
	$(CC) $(CFLAGS) $(CORE_INCS) -DTEST_PARSER -c $< -o $@

tests/test_parser.o: tests/test_parser.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(CORE_INCS) -c $< -o $@

# Nginx 模块相关目标
prepare:
	@if [ ! -f $(NGINX_PATH)/auto/configure ]; then \
		echo "Error: Nginx auto/configure not found at $(NGINX_PATH)/auto/configure"; \
		exit 1; \
	fi
	@if [ ! -f $(NGINX_PATH)/Makefile ]; then \
		cd $(NGINX_PATH) && \
		auto/configure --add-module=$(MODULE_PATH); \
	fi

check-source:
	@if [ -n "$$(find src -name '*.c' -newer $(NGINX_PATH)/objs/nginx 2>/dev/null)" ]; then \
		echo "Source files have changed, rebuilding..."; \
		$(MAKE) build; \
	fi

build:
	cd $(NGINX_PATH) && make

verify: build
	@echo "Starting nginx for testing..."
	-$(NGINX_PATH)/objs/nginx -t
	@echo "Test completed."

# 测试目标
test: test-parser test-nginx

test-parser: test_parser
	@echo "Running parser tests..."
	./test_parser

test-nginx: check-source
	@if [ ! -f $(NGINX_PATH)/objs/nginx ]; then \
		echo "Nginx binary not found, building first..."; \
		$(MAKE) build; \
	fi
	@echo "Running Test::Nginx tests..."
	TEST_NGINX_BINARY=$(NGINX_PATH)/objs/nginx \
	TEST_NGINX_VERBOSE=1 \
	prove -r t/

# 运行主程序
run: rule_parser
	./rule_parser test_rules.txt

# 清理目标
clean: clean-parser clean-module

clean-parser:
	rm -f $(PARSER_OBJS) src/main.o src/main_test.o tests/test_parser.o \
		rule_parser test_parser \
		src/rule_parser.tab.c src/rule_parser.tab.h src/lex.yy.c

clean-module:
	rm -f $(MODULE_OBJS)
	-cd $(NGINX_PATH) && make clean 2>/dev/null || true

clangd: prepare
	cd $(NGINX_PATH) && bear -- make 
	cp -f $(NGINX_PATH)/compile_commands.json $(MODULE_PATH)

.PHONY: all prepare build verify test clean clangd check-source \
        test-parser test-nginx clean-parser clean-module run
