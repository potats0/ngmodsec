use Test::Nginx::Socket 'no_plan';

# 设置测试环境
no_root_location();
no_shuffle();
# 测试规则中NOT条件的处理逻辑：
# 1. 测试用例1：验证正向匹配 - 当URL中包含"a"但不包含"b"时应该匹配成功
# 2. 测试用例2：验证反向匹配 - 当URL中同时包含"a"和"b"时应该匹配失败

run_tests();

__DATA__
=== TEST 1: NOT condition rule matching - positive case (match when negated pattern absent)
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.uri contains "a" and not http.uri contains "b";';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler
--- error_log
compile_all_hyperscan_databases successfully
Matched rule ID: 0 (from: 7lu, to: 8lu)
Matched pattern: a
Matched relation count : 1
Matched threat_id: 1000 sub_id: 0 and_bit: 1
recoed isn't exist, rule ID: 1000, Sub ID: 0  created new record
Traversing rule hits:
tree Rule ID: 1000, Sub ID: 0, BitMask: 0x1, CombinedMask: 0x3
Matched Rule ID: 1000
Exiting precontent phase handler
--- no_error_log
[error]

=== TEST 2: NOT condition rule matching - negative case (no match when negated pattern present)
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handlerb {
        error_log logs/error.log debug;
        rule 'rule 1000 http.uri contains "a" and not http.uri contains "b";';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handlerb
--- error_log
compile_all_hyperscan_databases successfully
Matched rule ID: 0 (from: 7lu, to: 8lu)
Matched pattern: a
Matched relation count : 1
Matched threat_id: 1000 sub_id: 0 and_bit: 1
recoed isn't exist, rule ID: 1000, Sub ID: 0  created new record
Traversing rule hits:
tree Rule ID: 1000, Sub ID: 0, BitMask: 0x3, CombinedMask: 0x3
Exiting precontent phase handler
--- no_error_log
[error]