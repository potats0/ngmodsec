use Test::Nginx::Socket 'no_plan';

# 设置测试环境
no_root_location();
no_shuffle();
run_tests();

__DATA__
=== TEST 1: 基础
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.all_get_args contains "php"  ;';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler.html?a=b%41&c=d&e=f&cmd=php
--- more_headers
user: TestAgent/2.0
User-Agent: TestAgent/1.0
host: www.baidu.com
--- error_log
compile_all_hyperscan_databases successfully
do check php HTTP_VAR_ALL_GET_ARGS
Matched rule ID: 0 (from: 0lu, to: 3lu)
Matched pattern: php
Matched relation count : 1
Matched Rule ID: 1000
Exiting precontent phase handler
--- no_error_log
[error]