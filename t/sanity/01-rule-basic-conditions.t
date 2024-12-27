use Test::Nginx::Socket 'no_plan';

# 设置测试环境
no_root_location();
no_shuffle();

run_tests();

# 测试基本的规则匹配功能：
# 1. 测试用例1：验证基本的规则匹配和处理流程 - 测试单个条件的匹配和处理器执行流程
# 2. 测试用例2：验证OR条件规则 - 测试多个条件之间的OR关系，以及红黑树记录的创建
# 3. 测试用例3：验证AND条件规则 - 测试多个条件之间的AND关系，验证位掩码的累积过程

__DATA__
=== TEST 1: Basic rule matching and handler execution flow
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.uri contains "a";';
        rule 'rule 1002 http.uri contains "b";';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler
--- error_log
compile_all_hyperscan_databases successfully
Entering precontent phase handler
Exiting precontent phase handler
Matched Rule ID: 1000
entering modsecurity header filter
entering modsecurity body filter
--- no_error_log
[error]
=== TEST 2: Rule matching with OR conditions and rbtree record creation
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.uri contains "t66y" or http.uri contains "a";';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler
--- error_log
compile_all_hyperscan_databases successfully
Matched threat_id: 1000 sub_id: 1 and_bit: 1
current request method: 2
recoed isn't exist, rule ID: 1000, Sub ID: 1  created new record
success insert new record, rbtee key: 256001
tree Rule ID: 1000, Sub ID: 1, BitMask: 0x1, CombinedMask: 0x1, not_mask: 0x0, rule_method: -1, req method: 2
Matched Rule ID: 1000
--- no_error_log
[error]
=== TEST 3: Rule matching with AND conditions and bitmask accumulation
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.uri contains "test" and http.uri contains "a";';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler
--- error_log
compile_all_hyperscan_databases successfully
Matched rule ID: 0 (from: 1lu, to: 5lu)
Matched pattern: test
Matched relation count : 1
Matched threat_id: 1000 sub_id: 0 and_bit: 1
current request method: 2
recoed isn't exist, rule ID: 1000, Sub ID: 0  created new record
success insert new record, rbtee key: 256000
Matched rule ID: 1 (from: 7lu, to: 8lu)
Matched pattern: a
Matched relation count : 1
Matched threat_id: 1000 sub_id: 0 and_bit: 2
current request method: 2
finded exisesting record, rule ID: 1000, Sub ID: 0, BitMask: 0x3, not_mask: 0x0
Traversing rule hits:
tree Rule ID: 1000, Sub ID: 0, BitMask: 0x3, CombinedMask: 0x3, not_mask: 0x0, rule_method: -1, req method: 2
Matched Rule ID: 1000
--- no_error_log
[error]