use Test::Nginx::Socket 'no_plan';

# 设置测试环境
no_root_location();
no_shuffle();

# 测试说明：
# 本测试用例验证规则引擎对HTTP请求体的处理能力
# 主要测试以下功能点：
# 1. POST请求体的读取和处理
# 2. 请求体内容的完整性验证
# 3. 大小写敏感性测试
# 4. 特殊字符处理能力

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
# --- error_log
# body content: username=test&password=123456
--- no_error_log
[error]

=== TEST 2: 超大body测试
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

--- request eval
"POST /test_handler
" . 'a' x 8192 . 'end';
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- no_error_log
[error]

=== TEST 3: body为空
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
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- no_error_log
[error]

=== TEST 4: body规则
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.raw_req_body contains "a" ;';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }

--- request
POST /test_handler
aaaa
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_log
Matched pattern: a
Matched Rule ID: 1000
--- no_error_log
[error]

=== TEST 5: bug
--- http_config
    error_log logs/error.log debug;
--- config
        # 精确匹配 /echo 并返回固定响应
        location = /echo {
            return 200 "echo";
        }

        # 处理其他所有请求
        location / {
            error_log logs/error.log debug;

            # 检查是否为内部代理请求
            if ($http_x_internal_proxy = "true") {
                return 200 "echo";
            }

            # 应用自定义规则
            rule 'rule 1001 http.uri contains "index.php/oqrs/request_form" and http.method = POST;';

            # 设置自定义请求头标识内部代理请求
            proxy_set_header X-Internal-Proxy true;

            # 代理请求到 /echo
            proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
        }

--- request
POST /index.php/oqrs/request_form
station_id=1 AND (SELECT 2469 FROM(SELECT COUNT(*),CONCAT(0x7162716b71,(SELECT (ELT(2469=2469,1))),0x7162716b71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)
--- more_headers
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36

--- error_log
Matched Rule ID: 1001
--- no_error_log
[error]