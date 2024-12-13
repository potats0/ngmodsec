# 7090 Fields 与nginx内置变量对应关系

   
| 7090        | Nginx        | 序号                | 说明                                    |
|-------------|-------------|--------------------|-----------------------------------------|
| method_name | method_name | NGX_VAR_METHOD    | http请求方法                             |
| http_url （建议改名）   | unparsed_uri| NGX_VAR_UNPARSED_URI | 带有query参数且未经url解码的原始url，很像7085中的http_url，在某些自定义规则场景中很有用          |
| http_uri    | uri|  |      暂定     | 经过解码和规范化的路径部分，经常在自定义规则中做访问控制中使用          |
| http_args   | args| 暂定 | query string原始部分          |
                                      |

# depencises
1. 执行`./depencises.sh` 自动在ubuntu上安装依赖
2. 去github上拉Nginx的源码，并执行`git clone https://github.com/nginx/nginx.git`

设置nginx 源代码的路径，你可以去git上下载。并执行
export NGINX_PATH=你的nginx源码路径

在本项目的根路径中直接执行make即可构建模块

请使用clangd + vscode支持代码跳转。

在该项目执行make clangd即可生成依赖文件

# Unit Test
1. 安装`Test::Nginx::Socket`，自行搜索安装方式
2. 执行`make test`即可，在执行的过程中如果源码变动则自动执行重新编译。否则不会重新编译

# FAQ
https://blog.csdn.net/zzhongcy/article/details/133175929

1. 请首先使用`make clangd`命令生成依赖文件，然后再使用`make`命令进行编译，不然会报错



# Nginx 参考
https://blog.csdn.net/weixin_42905245/article/details/106424144 Nginx $request_uri和$uri详解
