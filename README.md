
## 目前新引擎支持的协议变量

| 协议变量 | Nginx变量 | 说明 |
|---------|-----------|------|
| http.uri | ngx.uri | 会经过一次url解码和url规范化，不包含url参数部分 |
| http.unparsed_uri | ngx.unparsed_uri | 不经过任何处理，包含url参数部分 |
| http.exten | ngx.exten | url中文件扩展名部分，例如 /test.html 中的 html |
| http.method | ngx.method | method必须是GET,POST,PUT,DELETE,HEAD,OPTIONS,TRACE,CONNECT,PROPFIND,PROPPATCH,LOCK,UNLOCK,PATCH,TRACE,CONNECT，不同的method之间可以用\|分隔 |
| http.get_args["cmd"] | - | 把get参数的cmd送检 |
| http.headers["cmd"] | - | 把header的cmd送检 |
| http.host | ngx.host | 送检请求的host（可能产生双写bug，建议使用http.headers["host"]） |
| http.raw_req_body | - | 送检请求的body，未解码 |
| http.query_string | ngx.args | 送检参数部分，从url中第一次出现?后面的部分 |
| http.all_get_args | - | 把get参数中每一个解析后的value都送检 |
| http.all_get_name | - | 把get参数中每一个解析后的key都送检 |

其中在get的参数解析中，有可能会出现以下几种情况
1. 正常参数 ?b=c
   * key: "b", value: "c"
2. 空值参数 ?a=
   * key: "a", value: "" (空字符串)  这样会跳过送检value，但是可以用http.all_get_name解决，参考13-rule-http-all_get_name.t
3. 无值参数 ?param
   * key: "param", value: "" (空字符串) 无法被送检到get参数中，需要使用http.query_string或http.all_get_name解决，参考13-rule-http-all_get_name.t
4. 连续分隔符 ?a&&b=c
   * 跳过空参数，只处理有效的key-value对
5. a=x&a=y&b=z http参数污染
   * 每一个name对应的value都会送检对应的参数的正则匹配中
6. a=x&a=y?a&b=z 
   * ?会正确的出现在value中

# Nginx WAF Rule Match Engine Module

这是一个基于 Nginx 的 WAF 规则匹配引擎模块，支持复杂的规则解析和匹配功能。

## 功能特性

- 支持复杂的逻辑表达式（AND、OR）
- 支持多个子规则组合
- 支持正则表达式匹配
- 支持 HTTP 协议变量匹配

## 依赖项

### 系统要求
- Ubuntu 22.04 LTS
- 足够的磁盘空间（至少 1GB 用于依赖安装）

### 核心依赖
- Nginx 源码
- C 编译器（gcc/clang）
- GNU Make
- Flex（用于词法分析）
- Bison（用于语法分析）
- Hyperscan（用于高性能正则匹配）
- Clang-format (用于代码格式化)

### 开发工具
- Git（版本控制）
- Bear（生成编译数据库）
- Clangd（代码补全和导航）
- GDB（调试器）
- Valgrind（内存检查）

### 测试依赖
- Perl
- Test::Nginx::Socket（Nginx 模块测试框架）

## 快速开始

### 1. 安装依赖

我们提供了自动安装脚本，它会自动安装所有必需的依赖：

```bash
# 克隆仓库
git clone https://github.com/your-username/ngx_http_new_sign_module.git
cd ngx_http_new_sign_module

# 运行依赖安装脚本
sudo ./dependencies.sh
```

如果你想手动安装依赖，可以参考 `dependencies.sh` 脚本中的内容。

### 2. 获取 Nginx 源码

```bash
git clone https://github.com/nginx/nginx.git
export NGINX_PATH=/path/to/nginx  # 替换为你的 Nginx 源码路径
```

### 3. 构建模块

在项目根目录下执行：
```bash
make
```

## 构建系统

项目使用 GNU Make 作为构建系统，支持以下主要目标：

### 编译目标

- `make all`：构建完整的 Nginx 模块（默认目标）
- `make rule_parser`：只构建规则解析器
- `make test_parser`：构建规则解析器的测试程序

### 测试目标

- `make test`：运行所有测试（包括解析器测试和 Nginx 模块测试）
- `make test-parser`：只运行规则解析器测试
- `make test-nginx`：只运行 Nginx 模块测试

### 清理目标

- `make clean`：清理所有生成的文件
- `make clean-parser`：只清理规则解析器相关的文件
- `make clean-module`：只清理 Nginx 模块相关的文件

### 其他目标

- `make run`：运行规则解析器（用于测试规则文件）
- `make clangd`：生成 clangd 配置文件（用于代码补全和导航）

## 开发工具支持

推荐使用 VS Code + clangd 进行开发：

1. 首先生成 clangd 配置：
   ```bash
   make clangd
   ```

2. 安装 VS Code clangd 扩展

3. 现在你可以享受代码补全和跳转功能了

## 测试

项目包含两种类型的测试：

1. 规则解析器测试：
   - 位于 `tests/test_parser.c`
   - 使用自定义的基于宏的测试框架
   - 通过 `make test-parser` 运行

2. Nginx 模块测试：
   - 位于 `t/` 目录
   - 使用 Test::Nginx::Socket 框架
   - 通过 `make test-nginx` 运行

要运行所有测试：
```bash
make test
```

## 规则语法说明

本模块支持灵活的规则语法来定义 WAF 规则。以下是详细说明：

### 基本规则格式

注意: 目前规则支持八个or条件 每个条件支持32个子式

```
rule <规则ID>: <匹配表达式>;
```

- `规则ID`：规则的唯一数字标识符
- `匹配表达式`：一个或多个通过逻辑运算符组合的匹配条件

### 匹配类型

1. 包含匹配（字符串部分匹配）：
```
http.uri contains "匹配内容"
```

2. 正则表达式匹配：
```
http.uri matches "正则表达式"
```

3. 完全相等匹配：
```
http.uri equals "完整内容"
```

4. 前缀匹配：
```
http.uri starts_with "前缀"
```

5. 后缀匹配：
```
http.uri ends_with "后缀"
```

### Hyperscan 标志位

所有匹配类型都支持以下 Hyperscan 标志位：

- `/i`：不区分大小写匹配
- `/m`：多行匹配模式
- `/s`：点号匹配所有字符（包括换行符）
- `/f`：单次匹配模式

示例：
```
http.uri contains "pattern"/i
http.uri matches "pattern"/m/s
```

### 操作符使用说明

WAF 规则支持三种逻辑操作符：`and`、`or` 和 `not`。下面详细说明每种操作符的使用方法。

#### 重要说明
- 本模块不支持括号表达式，所有的逻辑组合必须通过 `and`、`or` 和 `not` 操作符直接组合。

#### AND 操作符的使用

AND 操作符用于表示所有条件都必须满足。

1. 基本语法：
```
rule 10001: http.uri contains "admin" and http.method equals "POST";
```

2. 多条件组合：
```
rule 10002: http.uri contains "login" and 
            http.method equals "POST" and 
            http.args contains "debug";
```

#### OR 操作符的使用

OR 操作符用于表示满足任一条件即可。

1. 基本语法：
```
rule 20001: http.uri contains "admin" or http.uri contains "manager";
```

2. 多条件组合：
```
rule 20002: http.method equals "POST" or 
            http.method equals "PUT" or 
            http.method equals "DELETE";
```

#### NOT 操作符的使用

NOT 操作符用于表示条件的否定。

1. 基本语法：
```
rule 40001: not http.uri contains "public";
```

2. 与其他操作符组合：
```
rule 40002: not http.method equals "GET" and http.uri contains "api";
```

注意：规则表达式中不支持单独的not条件。例如not http.uri contains "public"； 是不允许的。

### 规则示例

1. 基本的包含匹配：
```
# 检测 URI 中是否包含 "admin"
rule 10001: http.uri contains "admin";
```

2. 不区分大小写的正则匹配：
```
# 检测以 /admin 开头的任意 URI
rule 10002: http.uri matches "^/admin.*"/i;
```

3. 精确匹配：
```
# 检测是否精确匹配 /login.php
rule 10003: http.uri equals "/login.php";
```

4. 前缀和后缀匹配：
```
# 检测以 .php 结尾的 URI
rule 10004: http.uri ends_with ".php";

# 检测以 /api 开头的 URI
rule 10005: http.uri starts_with "/api";
```

5. 复杂条件组合：
```
# 检测登录页面的敏感操作
rule 10006: http.uri contains "login"/i and (http.uri matches "password.*" or http.uri contains "auth");

# 检测特定文件类型的访问
rule 10007: http.uri ends_with ".php" and (http.uri starts_with "/admin" or http.uri starts_with "/manager");
```

6. 多个标志位组合：
```
# 不区分大小写且支持多行的 API 路径匹配
rule 10008: http.uri matches "^/api/v[0-9]+/.*"/i/m;
```

7. 安全检测示例：
```
# SQL 注入检测
rule 20001: http.uri contains "select"/i or http.uri contains "union"/i;

# XSS 检测
rule 20002: http.uri matches "<script.*>.*</script>"/i;

# 路径遍历检测
rule 20003: http.uri contains "../" or http.uri matches "\.\.%2f"/i;
```

8. 组合规则示例：
```
# 检测后台敏感操作
rule 30001: http.uri starts_with "/admin" and 
           (http.uri contains "delete" or 
            http.uri contains "modify" or 
            http.uri ends_with ".php");

# API 访问控制
rule 30002: http.uri starts_with "/api" and
           (http.uri matches "v[0-9]+/users/.*" or
            http.uri matches "v[0-9]+/admin/.*");
```

### 注意事项

- 所有规则必须以分号(;)结尾
- 字符串内容需要用双引号包围
- 标志位可以按任意顺序组合
- 逻辑运算符具有相同的优先级，从左到右计算
- 使用逻辑运算符来控制运算优先级
- 规则ID必须是唯一的数字
- 建议根据规则用途划分规则ID范围，如：
  - 10000-19999：基本功能性规则
  - 20000-29999：安全防护规则
  - 30000-39999：访问控制规则

## 常见问题

1. 编译报错？
   - 请先执行 `make clangd` 生成依赖文件，然后再执行 `make`
   - 确保所有依赖都已正确安装
   - 检查 `NGINX_PATH` 环境变量是否正确设置

2. 测试失败？
   - 确保已安装所有依赖
   - 检查 Nginx 源码路径是否正确
   - 查看测试日志获取详细信息

3. 找不到 Hyperscan 库？
   - 确保已通过 `dependencies.sh` 安装了 Hyperscan
   - 如果手动安装，确保安装了 `libhyperscan5` 和 `libhyperscan-dev`

更多问题请参考：https://blog.csdn.net/zzhongcy/article/details/133175929

## 参考资料

- [Nginx $request_uri和$uri详解](https://blog.csdn.net/weixin_42905245/article/details/106424144)
- [Hyperscan 文档](https://intel.github.io/hyperscan/dev-reference/)
