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
            rule 'rule 1021 http.uri contains "Home/newLogin" and http.method = POST;';

            # 设置自定义请求头标识内部代理请求
            proxy_set_header X-Internal-Proxy true;

            # 代理请求到 /echo
            proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
        }
--- request
POST /Home/newLogin
data=AmILgROn2omEYq%2Bd8Urox8DW%2F8rRQwsBzOEz00K3cyMY1DhHq6oDzKni9uNo6p7VIuEZBk0edl%2Blr8MukZeYaoj5ogyFWf1wJQ6iDSwIHOKSdk2%2BRRo%2FbhB70T5AlQ3PB6Ca1I6PvvVefK%2BuEF6b%2BqnvUH5y0gix7tq3yw1WJdc%3D
--- more_headers

--- error_log
Matched Rule ID: 1021

--- no_error_log
[error]