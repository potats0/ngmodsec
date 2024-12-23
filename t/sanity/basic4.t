use Test::Nginx::Socket 'no_plan';

# 设置测试环境
no_root_location();
no_shuffle();

run_tests();

__DATA__
=== TEST 1: handler execution
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
alloc scratch 0u failed, field is NULL
alloc scratch 1u success
alloc scratch 2u failed, field is NULL
alloc scratch 3u failed, field is NULL
Matched rule ID: 0 (from: 7lu, to: 8lu)
Matched pattern: a
Matched relation count : 1
Matched threat_id: 1000 sub_id: 0 and_bit: 1
recoed isn't exist, rule ID: 1000, Sub ID: 0 combined BitMask: 0x3, not_mask: 0x2, created new record
Traversing rule hits:
tree Rule ID: 1000, Sub ID: 0, BitMask: 0x1, CombinedMask: 0x3
Matched Rule ID: 1000
Exiting precontent phase handler
--- no_error_log
[error]

=== TEST 2: match not
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
alloc scratch 0u failed, field is NULL
alloc scratch 1u success
alloc scratch 2u failed, field is NULL
alloc scratch 3u failed, field is NULL
Matched rule ID: 0 (from: 7lu, to: 8lu)
Matched pattern: a
Matched relation count : 1
Matched threat_id: 1000 sub_id: 0 and_bit: 1
recoed isn't exist, rule ID: 1000, Sub ID: 0 combined BitMask: 0x3, not_mask: 0x2, created new record
Traversing rule hits:
tree Rule ID: 1000, Sub ID: 0, BitMask: 0x3, CombinedMask: 0x3
Exiting precontent phase handler
--- no_error_log
[error]