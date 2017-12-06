# V2Ray_ws-tls_bash_onekey

V2ray ws+tls 一键安装脚本（Centos7+ / Debian 8+ /Ubuntu 16.04 +）

## 目前仅支持 Debian 8+ / Ubuntu 16.04+ 

## 2017-12-06

### V1.02（beta）

1.增加系统判定，目前打算仅支持带systemd的较新主流开发版系统

2.本机 IP 获取方式重构

## 2017-12-05

### V1.01（beta）

1.完善支持 Debian9

2.修复 由于 Debian9 默认未安装 net-tools 导致的本机ip判定错误

3.修复 bc 安装问题

4.增加 ip 判定不一致时继续安装的选项（由于某些vps情况比较特殊，判定到内网IP或本身网卡信息，或公网ip与服务期内信息不一致等情况）

### V1.0（beta）

1.目前仅支持 Debian 8+ / Ubuntu 16.04+ 

2.逐渐完善中
