use Test::Nginx::Socket 'no_plan';

# 设置测试环境
no_root_location();
no_shuffle();

# 测试HTTP GET参数在规则中的处理：
# 1. 测试用例1：验证规则中同时包含URI匹配和GET参数匹配的情况，确保能正确解析和匹配URL查询字符串中的参数

run_tests();

__DATA__
=== TEST 1: Rule matching with HTTP GET parameter condition
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.uri contains "a" and http.get_args["cmd"] contains "a";';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler?a=b&c=d&e=f&cmd=a
--- more_headers
User-Agent: TestAgent/2.0
User-Agent: TestAgent/1.0
--- error_log
compile_all_hyperscan_databases successfully
Matched Rule ID: 1000
Exiting precontent phase handler
--- no_error_log
[error]

=== TEST 2: GET parameter without value
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.uri contains "a" and http.get_args["cmd"] contains "a";';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler?a=&c=d
--- more_headers
User-Agent: TestAgent/2.0
User-Agent: TestAgent/1.0
--- error_log
compile_all_hyperscan_databases successfully
param key:a, value:
Exiting precontent phase handler
--- no_error_log
[error]

=== TEST 3: GET parameter without name
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.uri contains "a" and http.get_args["cmd"] contains "a";';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler?=b&c=d
--- more_headers
User-Agent: TestAgent/2.0
User-Agent: TestAgent/1.0
--- error_log
compile_all_hyperscan_databases successfully
Exiting precontent phase handler
--- no_error_log
[error]

=== TEST 4: GET parameter without =
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.uri contains "a" and http.get_args["cmd"] contains "a";';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler?b&c=d
--- more_headers
User-Agent: TestAgent/2.0
User-Agent: TestAgent/1.0
--- error_log
compile_all_hyperscan_databases successfully
param key:b, value:
Invalid GET parameter
Exiting precontent phase handler
--- no_error_log
[error]

=== TEST 5: 连续分隔符 ?a&&b=c
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.uri contains "a" and http.get_args["cmd"] contains "a";';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler?a&&b=c
--- more_headers
User-Agent: TestAgent/2.0
User-Agent: TestAgent/1.0
--- error_log
compile_all_hyperscan_databases successfully
param key:a, value:
Checking parameter b=c
Exiting precontent phase handler
--- no_error_log
[error]