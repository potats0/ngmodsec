NGINX_PATH ?= $(shell pwd)/../nginx
MODULE_PATH = $(shell pwd)
MODULE_NAME = ngx_http_waf_rule_match_engine_module

# 编译器和标志
CC = cc
CORE_INCS = -I$(NGINX_PATH)/src/core \
            -I$(NGINX_PATH)/src/event \
            -I$(NGINX_PATH)/src/http \
            -I$(NGINX_PATH)/src/os/unix \
            -I$(shell pwd)/src
INCLUDES = $(CORE_INCS) -D_GNU_SOURCE
CFLAGS = -g -O0 -Wall $(INCLUDES)
LDFLAGS = -lhs -lfl

# 构建目录
BUILD_DIR = build

# 确保构建目录存在
$(shell mkdir -p $(BUILD_DIR))

# 源文件和目标文件
PARSER_DIR = src/rule_parser
PARSER_SRCS = src/rule_parser/rule_parser.tab.c \
              src/rule_parser/lex.yy.c \
              src/rule_parser/main_test.c \
              src/rule_parser/pattern_converter.c
PARSER_OBJS = $(PARSER_SRCS:.c=.o)
MAIN_OBJS = $(PARSER_DIR)/main.o 
MODULE_SRCS = $(wildcard src/*.c)
MODULE_OBJS = $(MODULE_SRCS:.c=.o)

# 主要目标
all: prepare build verify

# 解析器目标
rule_parser: $(PARSER_OBJS) $(PARSER_DIR)/main.o
	$(CC) $(CFLAGS) $^ -o $@ -lhs -lfl

# 测试程序目标
test_parser: $(PARSER_OBJS) tests/test_parser.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# 编译规则
$(PARSER_DIR)/rule_parser.tab.c $(PARSER_DIR)/rule_parser.tab.h: $(PARSER_DIR)/rule_parser.y
	cd $(PARSER_DIR) && bison -d rule_parser.y

$(PARSER_DIR)/lex.yy.c: $(PARSER_DIR)/rule_lexer.l $(PARSER_DIR)/rule_parser.tab.h
	cd $(PARSER_DIR) && flex rule_lexer.l

$(PARSER_DIR)/main.o: $(PARSER_DIR)/main.c
	$(CC) $(CFLAGS) -c $< -o $@

$(PARSER_DIR)/main_test.o: $(PARSER_DIR)/main.c
	$(CC) $(CFLAGS) -DTEST_PARSER -c $< -o $@

$(PARSER_DIR)/%.o: $(PARSER_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

tests/test_parser.o: tests/test_parser.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

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

build: prepare
	cd $(NGINX_PATH) && make

verify: build
	@echo "Starting nginx for testing..."
	-$(NGINX_PATH)/objs/nginx -t
	@echo "Test completed."

# 测试目标
test: test-parser test-pattern-converter test-nginx

test-parser: test_parser
	@echo "Running parser tests..."
	./test_parser

test-pattern-converter: $(BUILD_DIR)/test_pattern_converter
	$(BUILD_DIR)/test_pattern_converter

$(BUILD_DIR)/test_pattern_converter: tests/test_pattern_converter.c src/rule_parser/pattern_converter.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

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
	rm -f $(BUILD_DIR)/*
	rm -f test_parser
	rm -f $(BUILD_DIR)/test_pattern_converter

clean-parser:
	rm -f $(PARSER_DIR)/*.o $(PARSER_DIR)/rule_parser.tab.* $(PARSER_DIR)/lex.yy.* test_parser

clean-module:
	cd $(NGINX_PATH) && make clean 2>/dev/null || true

.PHONY: all prepare build verify test clean \
        test-parser test-pattern-converter test-nginx clean-parser clean-module run
