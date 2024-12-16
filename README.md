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

## 7090 Fields 与 nginx 内置变量对应关系

| 7090        | Nginx        | 序号                | 说明                                    |
|-------------|-------------|--------------------|-----------------------------------------|
| method_name | method_name | NGX_VAR_METHOD    | http请求方法                             |
| http_url    | unparsed_uri| NGX_VAR_UNPARSED_URI | 带有query参数且未经url解码的原始url    |
| http_uri    | uri         | 暂定              | 经过解码和规范化的路径部分                  |
| http_args   | args        | 暂定              | query string原始部分                     |

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
