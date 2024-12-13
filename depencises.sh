#!/bin/bash
sudo apt update
sudo apt install -y perl build-essential curl cpanminus git bear clangd
sudo apt install -y libhyperscan5 libhyperscan-dev
sudo cpanm Test::Nginx