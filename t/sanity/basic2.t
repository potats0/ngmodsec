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
alloc scratch 0u failed, field is NULL
alloc scratch 1u success
alloc scratch 2u failed, field is NULL
alloc scratch 3u failed, field is NULL
Entering precontent phase handler
Exiting precontent phase handler
entering modsecurity header filter
entering modsecurity body filter
--- no_error_log
[error]
=== TEST 2: or cond rule 
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
recoed isn't exist, rule ID: 1000, Sub ID: 1 combined BitMask: 0x1, not_mask: 0x0 method: -1, created new record
success insert new record, rbtee key: 256001
tree Rule ID: 1000, Sub ID: 1, BitMask: 0x1, CombinedMask: 0x1, not_mask: 0x0, rule_method: -1, req method: 2
Matched Rule ID: 1000
--- no_error_log
[error]