use Test::Nginx::Socket 'no_plan';

# 设置测试环境
no_root_location();
no_shuffle();

run_tests();

__DATA__
=== TEST 1: http-useragent
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.uri contains "a" and http.user-agent contains "TestAgent";';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler
--- more_headers
User-Agent: TestAgent/2.0
User-Agent: TestAgent/1.0
--- error_log
compile_all_hyperscan_databases successfully
Matched Rule ID: 1000
Exiting precontent phase handler
--- no_error_log
[error]