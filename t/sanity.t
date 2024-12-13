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
--- response_body
ok
--- error_log
enter ngx_new_sign_module_init