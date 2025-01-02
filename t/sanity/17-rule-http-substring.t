use Test::Nginx::Socket 'no_plan';

# 设置测试环境
no_root_location();
no_shuffle();

run_tests();


__DATA__
=== TEST 1: 测试substring   
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.all_get_value[2,5] contains "a";';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler?cmd=12abc
--- more_headers
user: TestAgent/2.0
User-Agent: Tesaagent/1.0
--- error_log
compile_all_hyperscan_databases successfully
Entering precontent phase handler
Exiting precontent phase handler
Matched Rule ID: 1000
entering modsecurity header filter
entering modsecurity body filter
--- no_error_log
[error]

=== TEST 12: 测试substring   
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.all_get_value[2,5] contains "a";';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler?cmd=abc
--- more_headers
user: TestAgent/2.0
User-Agent: Tesaagent/1.0
--- error_log
compile_all_hyperscan_databases successfully
Entering precontent phase handler
Exiting precontent phase handler
entering modsecurity header filter
entering modsecurity body filter
--- no_error_log
[error]

=== TEST 3: 测试指定下标开始匹配   
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.all_get_value[2] contains "a";';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler?cmd=12abc
--- more_headers
user: TestAgent/2.0
User-Agent: Tesaagent/1.0
--- error_log
compile_all_hyperscan_databases successfully
Entering precontent phase handler
Exiting precontent phase handler
Matched Rule ID: 1000
entering modsecurity header filter
entering modsecurity body filter
--- no_error_log
[error]

=== TEST 4: 测试指定下标开始匹配1   
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.all_get_value[2] contains "a";';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler?cmd=abc
--- more_headers
user: TestAgent/2.0
User-Agent: Tesaagent/1.0
--- error_log
compile_all_hyperscan_databases successfully
Entering precontent phase handler
Exiting precontent phase handler
entering modsecurity header filter
entering modsecurity body filter
--- no_error_log
[error]