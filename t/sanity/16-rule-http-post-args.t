use Test::Nginx::Socket 'no_plan';

# 设置测试环境
no_root_location();
no_shuffle();

# 测试HTTP GET参数在规则中的处理：
# 1. 测试用例1：验证规则中同时包含URI匹配和GET参数匹配的情况，确保能正确解析和匹配URL查询字符串中的参数

run_tests();

__DATA__
=== TEST 1: POST请求体读取测试
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.uri contains "test" ;';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
POST /test_handler
username=test&password=123456
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_log
Found application/x-www-form-urlencoded content type
--- no_error_log
[error]
=== TEST 2: POST请求体读取测试
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.uri contains "test" ;';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
POST /test_handler
username=test&password=123456
--- more_headers
Content-Type: application/x-www-form-urlencoded; charset=utf-8
--- error_log
Found application/x-www-form-urlencoded content type
--- no_error_log
[error]

=== TEST 3: Rule matching with HTTP post parameter condition
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
POST /test_handler
username=test&password=123456a&cmd=a
--- more_headers
Content-Type: application/x-www-form-urlencoded; charset=utf-8
--- error_log
Found application/x-www-form-urlencoded content type
Matched Rule ID: 1000

=== TEST 4: 空指针测试
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.uri contains "a" ;';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
POST /test_handler
username=test&password=123456a&cmd=a
--- more_headers
Content-Type: application/x-www-form-urlencoded; charset=utf-8
--- error_log
Found application/x-www-form-urlencoded content type
Matched Rule ID: 1000