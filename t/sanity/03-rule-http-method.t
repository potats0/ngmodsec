use Test::Nginx::Socket 'no_plan';

# 设置测试环境
no_root_location();
no_shuffle();

# 测试HTTP方法在规则中的处理：
# 1. 测试用例1：验证规则中同时包含URI匹配和HTTP方法匹配的情况
# 2. 测试用例2：验证规则中未设置HTTP方法时的默认行为

run_tests();

__DATA__
=== TEST 1: Rule matching with HTTP method condition
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.uri contains "a" and http.method = GET;';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler
--- error_log
compile_all_hyperscan_databases successfully
Matched Rule ID: 1000
Exiting precontent phase handler
--- no_error_log
[error]

=== TEST 2: Rule matching without HTTP method condition (default behavior)
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.uri contains "a";';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler
--- error_log
compile_all_hyperscan_databases successfully
Matched Rule ID: 1000
Exiting precontent phase handler
--- no_error_log
[error]