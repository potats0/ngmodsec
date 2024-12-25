use Test::Nginx::Socket 'no_plan';

# 设置测试环境
no_root_location();
no_shuffle();

# 测试说明：
# 本测试用例验证WebLogic控制台未授权访问漏洞检测规则
# 主要测试以下功能点：
# 1. 对URL中的路径穿越攻击模式的检测
# 2. 对双重编码的路径穿越的识别（%252e%252e%252f）
# 3. 对特定WebLogic控制台路径模式的匹配
# 4. 规则匹配的准确性和日志记录完整性

run_tests();

__DATA__
=== TEST 1: WebLogic控制台路径穿越未授权访问检测
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
            rule 'rule 1000 http.uri starts_with "console" and http.uri ends_with "console.portal" and http.uri contains "%252e%252e%252f";';

            # 设置自定义请求头标识内部代理请求
            proxy_set_header X-Internal-Proxy true;

            # 代理请求到 /echo
            proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
        }
--- request
GET /console/..;/css/%252e%252e%252fconsole.portal
--- more_headers
user: TestAgent/2.0
User-Agent: TestAgent/1.0
host: www.baidu.com
--- error_log
compile_all_hyperscan_databases successfully
Exiting precontent phase handler
--- no_error_log
[error]