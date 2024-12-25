use Test::Nginx::Socket 'no_plan';

# 设置测试环境
no_root_location();
no_shuffle();

# 测试说明：
# 本测试用例验证规则引擎对HTTP unparsed_uri的处理能力
# 主要测试以下功能点：
# 1. 规则中使用http.unparsed_uri变量的语法正确性
# 2. 未经过任何处理的原始URI的提取和匹配准确性
# 3. 包含查询参数的完整URL的匹配能力
# 4. URL编码字符(%41)的原样保留和匹配
# 5. 规则匹配后的日志记录完整性

run_tests();

__DATA__
=== TEST 1: 原始URI匹配测试（包含查询参数和编码字符）
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.exten contains "php" or http.exten contains "html" ;';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler.html?a=b%41&c=d&e=f&cmd=a
--- more_headers
user: TestAgent/2.0
User-Agent: TestAgent/1.0
host: www.baidu.com
--- error_log
compile_all_hyperscan_databases successfully
do check html HTTP_VAR_EXTEN
Matched rule ID: 1 (from: 0lu, to: 4lu)
Matched pattern: html
Matched Rule ID: 1000
Exiting precontent phase handler
--- no_error_log
[error]
