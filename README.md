# 7090 Fields 与nginx内置变量对应关系

   
| 7090        | Nginx        | 序号                | 说明                                    |
|-------------|-------------|--------------------|-----------------------------------------|
| method_name | method_name | NGX_VAR_METHOD    | http请求方法                             |
| http_url （建议改名）   | unparsed_uri| NGX_VAR_UNPARSED_URI | 带有query参数且未经url解码的原始url，很像7085中的http_url，在某些自定义规则场景中很有用          |
| http_uri    | uri|  |      暂定     | 经过解码和规范化的路径部分，经常在自定义规则中做访问控制中使用          |
| http_args   | args| 暂定 | query string原始部分          |
                                      |

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

#### AND 操作符的使用

AND 操作符用于表示所有条件都必须满足。

1. 基本语法：
   ```
   <expression1> and <expression2>
   (<expression1> and <expression2>) and <expression3>
   ```

2. 支持的用法：
   - 简单组合：`http.uri contains "login" and http.uri contains "admin"`
   - 多重组合：`http.uri contains "api" and http.uri contains "v1" and http.uri contains "user"`
   - 与括号组合：`(http.uri contains "login" and http.uri contains "admin") and http.header contains "json"`
   - 与其他操作符组合：`http.uri contains "admin" and not http.uri contains "test"`

3. 示例：
   ```
   # 有效的用法
   rule 1000 http.uri contains "login" and http.uri contains "admin";
   rule 1001 (http.uri contains "api" and http.uri contains "v1") and http.header contains "json";
   rule 1002 http.uri contains "user" and http.uri contains "profile" and http.uri contains "edit";
   rule 1003 http.uri contains "admin" and not http.uri contains "test";
   ```

#### OR 操作符的使用

OR 操作符用于表示满足任一条件即可。

1. 基本语法：
   ```
   <expression1> or <expression2>
   (<expression1> and <expression2>) or <expression3>
   ```

2. 支持的用法：
   - 简单组合：`http.uri contains "admin" or http.uri contains "manager"`
   - 多重组合：`http.uri contains "login" or http.uri contains "signin" or http.uri contains "signup"`
   - 与括号组合：`(http.uri contains "admin" and http.uri contains "login") or http.uri contains "superuser"`
   - 与其他操作符组合：`http.uri contains "admin" or not http.uri contains "public"`

3. 示例：
   ```
   # 有效的用法
   rule 1000 http.uri contains "admin" or http.uri contains "manager";
   rule 1001 (http.uri contains "login" and http.header contains "mobile") or http.uri contains "app";
   rule 1002 http.uri contains "delete" or http.uri contains "remove" or http.uri contains "drop";
   rule 1003 (http.uri contains "api" and http.uri contains "v1") or (http.uri contains "api" and http.uri contains "v2");
   ```

#### NOT 操作符的使用

NOT 操作符用于表示否定条件。

1. 基本语法：
   ```
   not <match_expression>
   not (<expression>)
   ```

2. 支持的用法：
   - 简单否定：`not http.uri contains "admin"`
   - 与 AND 组合：`http.uri contains "login" and not http.uri contains "logout"`
   - 与 OR 组合：`http.uri contains "admin" or not http.uri contains "public"`
   - 对括号内的表达式使用 NOT：`not (http.uri contains "admin" and http.uri contains "login")`

3. 限制条件：
   - 不支持嵌套的 NOT 操作，例如：`not (a and not b)` 是不允许的
   - 一个 NOT 操作符只能作用于一个表达式或一个括号内的表达式组

4. 示例：
   ```
   # 有效的用法
   rule 1000 http.uri contains "login" and not http.uri contains "public";
   rule 1001 not http.uri contains "admin" and http.uri contains "index";
   rule 1002 http.uri contains "api" or not http.uri contains "test";
   rule 1003 not (http.uri contains "admin" and http.uri contains "login");

   # 无效的用法
   rule 1004 not (http.uri contains "a" and not http.uri contains "b");  # 不支持嵌套的 NOT
   rule 1005 not (not http.uri contains "admin");                        # 不支持嵌套的 NOT
   ```

#### 括号表达式的使用

括号用于分组和改变表达式的优先级。

1. 基本语法：
   ```
   (<expression>)
   (<expression1> and <expression2>)
   (<expression1> or <expression2>)
   not (<expression>)
   ```

2. 支持的用法：
   - 简单分组：`(http.uri contains "admin")`
   - 逻辑组合：`(http.uri contains "admin" and http.uri contains "login")`
   - 多重嵌套：`(http.uri contains "api" and (http.uri contains "v1" or http.uri contains "v2"))`
   - 与 NOT 组合：`not (http.uri contains "admin" and http.uri contains "login")`
   - 与 OR 组合：`(http.uri contains "admin" and http.header contains "json") or http.uri contains "api"`

3. 使用场景：
   - 改变操作符优先级：
     ```
     # 不使用括号：a and b or c 等价于 (a and b) or c
     rule 1000 http.uri contains "admin" and http.uri contains "login" or http.uri contains "root";

     # 使用括号：a and (b or c)
     rule 1001 http.uri contains "admin" and (http.uri contains "login" or http.uri contains "root");
     ```

   - 分组复杂条件：
     ```
     # 对多个条件进行分组
     rule 1002 (http.uri contains "api" and http.uri contains "v1") or (http.uri contains "api" and http.uri contains "v2");

     # 嵌套使用括号
     rule 1003 (http.uri contains "admin" and (http.header contains "json" or http.header contains "xml")) and not http.uri contains "test";
     ```

4. 注意事项：
   - 括号可以嵌套使用，嵌套层数不限
   - 括号内的表达式会被优先计算
   - 括号可以与所有操作符（and、or、not）组合使用
   - 使用括号可以提高规则的可读性

#### 操作符优先级

WAF 规则中的操作符优先级从高到低为：
1. `not`（最高优先级）
2. `and`
3. `or`（最低优先级）

使用括号可以改变操作符的优先级。例如：
```
# 以下两个规则的效果不同：
rule 1000 http.uri contains "a" and http.uri contains "b" or http.uri contains "c";  # (a and b) or c
rule 1001 http.uri contains "a" and (http.uri contains "b" or http.uri contains "c");  # a and (b or c)
```

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
- 使用括号来控制运算优先级
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
