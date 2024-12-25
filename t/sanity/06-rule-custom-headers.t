use Test::Nginx::Socket 'no_plan';

# 设置测试环境
no_root_location();
no_shuffle();

# 测试自定义HTTP请求头部在规则中的处理：
# 1. 测试用例1：验证规则中同时包含URI匹配和自定义头部匹配的情况，确保能正确处理非标准HTTP头部字段

run_tests();

__DATA__
=== TEST 1: Rule matching with custom HTTP header condition
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.uri contains "a" and http.headers["user"] contains "TestAgent";';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler?a=b&c=d&e=f&cmd=a
--- more_headers
user: TestAgent/2.0
User-Agent: TestAgent/1.0
--- error_log
compile_all_hyperscan_databases successfully
Matched Rule ID: 1000
Exiting precontent phase handler
--- no_error_log
[error]