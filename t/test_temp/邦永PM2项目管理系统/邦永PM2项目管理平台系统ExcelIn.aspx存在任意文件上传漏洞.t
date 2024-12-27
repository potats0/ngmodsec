use Test::Nginx::Socket 'no_plan';

# 设置测试环境
no_root_location();
no_shuffle();

run_tests();

__DATA__
=== TEST 1: 测试1
--- http_config
    error_log logs/error.log debug;
--- config
        # 精确匹配 /echo 并返回固定响应
        location = /echo {
            return 200 "echo";
        }

        # 处理其他所有请求
        location / {
            error_log logs/error.log debug;

            # 检查是否为内部代理请求
            if ($http_x_internal_proxy = "true") {
                return 200 "echo";
            }

            # 应用自定义规则
            rule 'rule 1028 http.uri contains "FlowChartDefine/ExcelIn.aspx" and http.method = POST;';

            # 设置自定义请求头标识内部代理请求
            proxy_set_header X-Internal-Proxy true;

            # 代理请求到 /echo
            proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/echo;
        }
--- request
POST /FlowChartDefine/ExcelIn.aspx
模块导入
------WebKitFormBoundaryAU4uQKbpWhA7eME3--


--- more_headers
------WebKitFormBoundaryAU4uQKbpWhA7eME3
Content-Disposition: form-data; name="__VIEWSTATE"

U6iRl9SqWWlhjIPJXIeFrsinqYAmYxenxFiyfWFMfWgnw3OtkceDLcdfRvB8pmUNGk44PvjZ6LlzPwDbJGmilsmhuX9LvOiuKadYa9iDdSipLW5JvUHjS89aGzKqr9fhih+p+/Mm+q2vrknhfEJJnQ==
------WebKitFormBoundaryAU4uQKbpWhA7eME3
Content-Disposition: form-data; name="__VIEWSTATEGENERATOR"

FD259C0F
------WebKitFormBoundaryAU4uQKbpWhA7eME3
Content-Disposition: form-data; name="__EVENTVALIDATION"

/pKblUYGQ+ibKtw4CCS2wzX+lmZIOB+x5ezYw0qJFbaUifUKlxNNRMKceZYgY/eAUUTaxe0gSvyv/oA8lUS7G7jPVqqrMEzYBVBl8dRkFWFwMqqjv1G9gXM/ZnIpnVSL
------WebKitFormBoundaryAU4uQKbpWhA7eME3
Content-Disposition: form-data; name="FileUpload1"; filename="1234.zip"
Content-Type: application/x-zip-compressed

{{unquote("PK\x03\x04\x14\x00\x01\x00\x00\x00\xefl\xfaX\x1c:\xf5\xcb\x11\x00\x00\x00\x05\x00\x00\x00\x08\x00\x00\x001234.txt\xb0\x0c\x01\x08\xd1!\xd1Uv \xfal\x9b\xf4Q\xfd\xf8PK\x01\x02?\x00\x14\x00\x01\x00\x00\x00\xefl\xfaX\x1c:\xf5\xcb\x11\x00\x00\x00\x05\x00\x00\x00\x08\x00$\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00\x001234.txt\x0a\x00 \x00\x00\x00\x00\x00\x01\x00\x18\x00\x05\x8d\x9d.\x1e\xdf\xda\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00Z\x00\x00\x007\x00\x00\x00\x00\x00")}}
------WebKitFormBoundaryAU4uQKbpWhA7eME3
Content-Disposition: form-data; name="Button1"
--- error_log
Matched Rule ID: 1028

--- no_error_log
[error]