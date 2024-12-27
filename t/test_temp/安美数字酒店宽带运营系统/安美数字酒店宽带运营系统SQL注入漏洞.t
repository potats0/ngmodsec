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
            rule 'rule 1038 http.uri contains "language.php" and http.method = POST;';

            # 设置自定义请求头标识内部代理请求
            proxy_set_header X-Internal-Proxy true;

            # 代理请求到 /echo
            proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
        }
--- request
POST /language.php
EditStatus=1&LangEName=pHqghUme&LangID=1&LangName=pHqghUme&LangType=0000%E7%B3%BB%E7%BB%9F%E5%9F%BA%E6%9C%AC%E4%BF%A1%E6%81%AF&Lately=555-666-0606&Search=the&SerialID=1&Type=0'XOR(if(now()=sysdate()%2Csleep(5)%2C0))XOR'Z&UID=add&submit=%20%E6%B7%BB%20%E5
--- more_headers

--- error_log
Matched Rule ID: 1038

--- no_error_log
[error]