use Test::Nginx::Socket 'no_plan';

# 设置测试环境
repeat_each(2);

run_tests();

__DATA__

=== TEST 1: module initialization without rules
--- config
    location /test {
        return 200 "ok";
    }
--- request
GET /test
--- error_code: 200

=== TEST 2: module initialization with rules
--- config
    location /test {
        rule 'rule 1000 http.uri contains "a";';
        return 200 "ok";
    }
--- request
GET /test
--error
rule parsed successfully
compile_all_hyperscan_databases successfully
--- error_code: 200