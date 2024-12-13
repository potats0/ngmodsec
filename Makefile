NGINX_PATH ?= $(shell pwd)/../nginx
MODULE_PATH = $(shell pwd)
MODULE_NAME = ngx_http_waf_rule_match_engine_module

# 源文件和目标文件
SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)

# 编译标志
CFLAGS = -g -O0 -Wall
CORE_INCS = -I$(NGINX_PATH)/src/core \
            -I$(NGINX_PATH)/src/event \
            -I$(NGINX_PATH)/src/http \
            -I$(NGINX_PATH)/src/os/unix
			
all: prepare build verify

# 增量编译规则
%.o: %.c
	$(CC) $(CFLAGS) $(CORE_INCS) -c $< -o $@

prepare:
	@if [ ! -f $(NGINX_PATH)/auto/configure ]; then \
		echo "Error: Nginx auto/configure not found at $(NGINX_PATH)/auto/configure"; \
		exit 1; \
	fi
	@if [ ! -f $(NGINX_PATH)/Makefile ]; then \
		cd $(NGINX_PATH) && \
		auto/configure --add-module=$(MODULE_PATH); \
	fi

# 检查源文件是否有更新
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

test: check-source
	@if [ ! -f $(NGINX_PATH)/objs/nginx ]; then \
		echo "Nginx binary not found, building first..."; \
		$(MAKE) build; \
	fi
	@echo "Running Test::Nginx tests..."
	TEST_NGINX_BINARY=$(NGINX_PATH)/objs/nginx \
	TEST_NGINX_VERBOSE=1 \
	prove -r t/

clean:
	cd $(NGINX_PATH) && make clean
	rm -f $(OBJS)

clangd: prepare
	cd $(NGINX_PATH) && bear -- make 
	cp -f $(NGINX_PATH)/compile_commands.json $(MODULE_PATH)

.PHONY: all prepare build verify test clean clangd check-source
