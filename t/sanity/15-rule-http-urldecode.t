use Test::Nginx::Socket 'no_plan';

# 设置测试环境
no_root_location();
no_shuffle();
run_tests();

__DATA__
=== TEST 1: 基础
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.all_header_value contains "cmd"  ;';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler?id=%27)%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CCONCAT(IFNULL(CAST(CURRENT_USER()%20AS%20NCHAR)%2C0x20))%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20-
--- error_log
do check ') UNION ALL SELECT NULL,NULL,CONCAT(IFNULL(CAST(CURRENT_USER() AS NCHAR),0x20)),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- - HTTP_VAR_ALL_GET_VALUE
--- no_error_log
[error]
=== TEST 2: malformed
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.all_header_value contains "cmd"  ;';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler?id=%27)%2sa
--- error_log
do check ')a
--- no_error_log
[error]
=== TEST 3: malformed2
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.all_header_value contains "cmd"  ;';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler?id=%27)%%GG
--- error_log
do check ')%GG
--- no_error_log
[error]
=== TEST 4: malformed3
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.all_header_value contains "cmd"  ;';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler?id=%27)%%41
--- error_log
do check ')%41
--- no_error_log
[error]
=== TEST 5: url解码包含NULL的情况
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.get_args["id"] contains "cmd"  ;';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler?id=aaa%00aacmd
--- error_log
Matched pattern: cmd
--- no_error_log
[error]
=== TEST 6: url不存在编码，自动跳过
--- http_config
    error_log logs/error.log debug;
--- config
    location /test_handler {
        error_log logs/error.log debug;
        rule 'rule 1000 http.get_args["id"] contains "cmd"  ;';
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
    }
    
    location /echo {
        return 200 "echo";
    }
--- request
GET /test_handler?id=aaaaacmd
--- error_log
could not detect url encoding param: id = aaaaacmd (no URL encoding)
Matched pattern: cmd
--- no_error_log
[error]