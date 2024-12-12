# 7090 Fields 与nginx内置变量对应关系

   
| 7090 | Nginx | 说明 |
|------|-------|------|
| http_url | request_uri | 带有query参数且未经url解码的原始url |
| row2 | cell2 | description2 |
| row3 | cell3 | description3 |

# depencises
sudo apt install libhyperscan5 libhyperscan-dev

设置nginx 源代码的路径，你可以去git上下载。并执行
export NGINX_PATH=/home/liangzhibang/CTM/nginx

在本项目的根路径中直接执行make即可构建模块

请使用clangd + vscode支持代码跳转。1. 安装bear 2. 在该项目执行make clangd即可生成依赖文件

# FAQ
https://blog.csdn.net/zzhongcy/article/details/133175929

clangd 代码跳转
