use Test::Nginx::Socket 'no_plan';

# 设置测试环境
no_root_location();
no_shuffle();

run_tests();

__DATA__
=== TEST 1: user data context creation
--- config
    location /test_ctx {
        rule 'rule 1000 http.uri contains "a";';
        rule 'rule 1002 http.uri contains "b";';
        return 200 "test context";
    }
--- request
GET /test_ctx
--- error_log
Attempting to get user data from request context
User data not found in context, creating new one
Successfully created and set new user data in context
--- no_error_log
Failed to allocate memory for user data
[error]

