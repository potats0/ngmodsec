# 7090 Fields 与nginx内置变量对应关系

   
| 7090 | Nginx | 序号 | 说明 |
|------|-------|------|
| http_url | request_uri | 带有query参数且未经url解码的原始url |
| method_name | method_name | description2 |description2 |
| row3 | cell3 | description3 |
NGX_VAR_METHOD
# depencises
sudo apt install libhyperscan5 libhyperscan-dev

设置nginx 源代码的路径，你可以去git上下载。并执行
export NGINX_PATH=/home/liangzhibang/CTM/nginx

在本项目的根路径中直接执行make即可构建模块

请使用clangd + vscode支持代码跳转。1. 安装bear 2. 在该项目执行make clangd即可生成依赖文件

# FAQ
https://blog.csdn.net/zzhongcy/article/details/133175929

1. 请首先使用`make clangd`命令生成依赖文件，然后再使用`make`命令进行编译，不然会报错
