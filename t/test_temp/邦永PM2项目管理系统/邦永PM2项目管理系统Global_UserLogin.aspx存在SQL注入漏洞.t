use Test::Nginx::Socket 'no_plan';

# 设置测试环境
no_root_location();
no_shuffle();

run_tests();

__DATA__
=== TEST 1: 测试1
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
            rule 'rule 1027 http.uri contains "Global/Global_UserLogin.aspx" and http.method = GET;';

            # 设置自定义请求头标识内部代理请求
            proxy_set_header X-Internal-Proxy true;

            # 代理请求到 /echo
            proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
        }
--- request
GET /Global/Global_UserLogin.aspx?accId=1%27%3BWAITFOR+DELAY+%270%3A0%3A5%27--&loginCode=&password=&type= 
--- more_headers

--- error_log
Matched Rule ID: 1027

--- no_error_log
[error]