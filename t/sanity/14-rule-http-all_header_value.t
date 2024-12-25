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
        rule 'rule 1000 http.all_header_value contains "cmd"  ;';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler.html
--- more_headers
user: TestAgent/2.0
User-Agent: cmd
host: www.baidu.com
--- error_log
compile_all_hyperscan_databases successfully
do check cmd HTTP_VAR_ALL_HEADER_VALUE
Matched rule ID: 0 (from: 0lu, to: 3lu)
Matched pattern: cmd
Matched Rule ID: 1000
Exiting precontent phase handler
--- no_error_log
[error]
