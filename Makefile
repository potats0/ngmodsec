NGINX_PATH ?= $(shell pwd)/../nginx
MODULE_PATH = $(shell pwd)
MODULE_NAME = ngx_http_new_sign_module

# 源文件和目标文件
SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

# 编译标志
CFLAGS = -g -O0 -Wall
CORE_INCS = -I$(NGINX_PATH)/src/core \
            -I$(NGINX_PATH)/src/event \
            -I$(NGINX_PATH)/src/http \
            -I$(NGINX_PATH)/src/os/unix
			
all: prepare build test

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

build:
	cd $(NGINX_PATH) && make

test: build
	@echo "Starting nginx for testing..."
	-$(NGINX_PATH)/objs/nginx -t
	@echo "Test completed."

clean:
	cd $(NGINX_PATH) && make clean
	rm -f *.o

clangd: prepare
	cd $(NGINX_PATH) && bear -- make 
	cp -f $(NGINX_PATH)/compile_commands.json $(MODULE_PATH)

.PHONY: all prepare build test clean clangd
