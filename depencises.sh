#!/bin/bash

# 设置错误时退出
set -e

# 检查是否为 root 用户
if [ "$EUID" -ne 0 ]; then 
    echo "请使用 sudo 运行此脚本"
    exit 1
fi

# 检查系统版本
if ! grep -q "Ubuntu 22" /etc/os-release; then
    echo "错误: 此脚本仅支持 Ubuntu 22.04/10"
    echo "当前系统信息:"
    cat /etc/os-release
    exit 1
fi

echo "开始安装依赖..."

# 更新包列表
apt update

# 基本构建工具
echo "安装基本构建工具..."
apt install -y \
    build-essential \
    git \
    make \
    gcc \
    g++ \
    pkg-config \
    clang\
    clang-format

# 开发工具
echo "安装开发工具..."
apt install -y \
    bear \
    clangd \
    clang-format \
    gdb \
    valgrind

# Flex 和 Bison
echo "安装 Flex 和 Bison..."
apt install -y \
    flex \
    bison

# Nginx 模块开发依赖
echo "安装 Nginx 模块开发依赖..."
apt install -y \
    libpcre3 \
    libpcre3-dev \
    zlib1g \
    zlib1g-dev \
    openssl \
    libssl-dev

# Hyperscan 依赖
echo "安装 Hyperscan..."
apt install -y \
    libhyperscan5 \
    libhyperscan-dev

# Perl 和测试框架
echo "安装 Perl 和测试依赖..."
apt install -y \
    perl \
    cpanminus

# 安装 Test::Nginx
echo "安装 Test::Nginx..."
cpanm --notest Test::Nginx::Socket

echo "所有依赖安装完成！"
echo "请确保设置 NGINX_PATH 环境变量指向 Nginx 源码目录。"
echo "例如: export NGINX_PATH=/path/to/nginx"