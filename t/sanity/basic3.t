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
    location /test_handlerb {
        error_log logs/error.log debug;
        rule 'rule 1000 http.uri contains "a" and http.uri contains "b";';
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
--- no_error_log
[error]
