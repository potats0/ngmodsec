use Test::Nginx::Socket 'no_plan';

# 设置测试环境
no_root_location();
no_shuffle();

# 测试说明：
# 本测试用例验证规则引擎对HTTP Host头部的处理能力
# 主要测试以下功能点：
# 1. 规则中使用http.host变量的语法正确性
# 2. Host头部值的提取和匹配准确性
# 3. 多条件组合（URI和Host）的逻辑处理
# 4. 规则匹配后的日志记录完整性

run_tests();

__DATA__
=== TEST 1: Host头部规则匹配测试
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.uri contains "a" and http.host contains "baidu";';
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
host: www.baidu.com
--- error_log
compile_all_hyperscan_databases successfully
do check www.baidu.com 
Matched rule ID: 0 (from: 4lu, to: 9lu)
Matched pattern: baidu
Matched Rule ID: 1000
Exiting precontent phase handler
--- no_error_log
[error]