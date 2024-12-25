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
        rule 'rule 1000 http.exten contains "php" or http.exten contains "html" ;';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler.html?a=b%41&c=d&e=f&cmd=a
--- more_headers
user: TestAgent/2.0
User-Agent: TestAgent/1.0
host: www.baidu.com
--- error_log
compile_all_hyperscan_databases successfully
do check html HTTP_VAR_EXTEN
Matched rule ID: 1 (from: 0lu, to: 4lu)
Matched pattern: html
Matched Rule ID: 1000
Exiting precontent phase handler
--- no_error_log
[error]
=== TEST 2: 畸形
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.exten contains "php" or http.exten contains "html" ;';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler.html?a=b%41&c=d?c&e=f&cmd=a
--- more_headers
user: TestAgent/2.0
User-Agent: TestAgent/1.0
host: www.baidu.com
--- error_log
compile_all_hyperscan_databases successfully
Exiting precontent phase handler
--- no_error_log
[error]

=== TEST 3: 规则
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.query_string contains "php" ;';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler.html?a=php%41&c=d?c&e=f&cmd=a
--- more_headers
user: TestAgent/2.0
User-Agent: TestAgent/1.0
host: www.baidu.com
--- error_log
compile_all_hyperscan_databases successfully
do check a=php%41&c=d?c&e=f&cmd=a HTTP_VAR_QUERY_STRING
Matched rule ID: 0 (from: 2lu, to: 5lu)
Matched pattern: php
Matched relation count : 1
Matched threat_id: 1000 sub_id: 0 and_bit: 1
Exiting precontent phase handler
--- no_error_log
[error]
