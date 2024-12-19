use Test::Nginx::Socket 'no_plan';

# 设置测试环境
no_root_location();
no_shuffle();

run_tests();

__DATA__

=== TEST 1: module initialization
--- config
    location /test {
        return 200 "ok";
    }
--- request
GET /test
--- error_log
enter ngx_http_waf_rule_match_engine_module_init
--- no_error_log
[error]

=== TEST 2: user data context creation
--- config
    location /test_ctx {
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

=== TEST 3: user data context reuse
--- config
    location /test_ctx_reuse {
        return 200 "test context reuse";
    }
--- request eval
["GET /test_ctx_reuse", "GET /test_ctx_reuse"]
--- error_log
Attempting to get user data from request context
User data not found in context, creating new one
Successfully created and set new user data in context
--- no_error_log
Failed to allocate memory for user data
[error]
