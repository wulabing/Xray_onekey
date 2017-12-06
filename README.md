# V2Ray vmess+ws+tls 一键安装脚本

* V2Ray是一个优秀的开源网络代理工具，可以帮助你畅爽体验互联网，目前已经全平台支持Windows、Mac、Android、IOS、Linux等操作系统的使用。

## 本脚本目前支持 Centos7 + / Debian 8+ / Ubuntu 16.04+ 

## 注意事项
* 推荐在纯净环境下使用本脚本，如果你是新手，请不要使用Centos系统。
* 在尝试本脚本确实可用之前，请不要将本程序应用于生产环境中。
* 该程序依赖 Nginx 实现相关功能，请使用 [LNMP](https://lnmp.org) 或其他类似携带 Nginx 脚本安装过 Nginx 的用户特别留意，使用本脚本可能会导致无法预知的错误（未测试，若存在，后续版本可能会处理本问题）。
* V2Ray 的部分功能依赖于系统时间，请确保您使用V2RAY程序的系统 UTC 时间误差在三分钟之内，时区无关。
* 本 bash 依赖于 [V2ray 官方安装脚本](https://install.direct/go.sh) 及 [acme.sh](https://github.com/Neilpang/acme.sh) 工作。
* Centos 系统用户请预先在防火墙中放行程序相关端口（默认：80，443）
## 准备工作
* 准备一个域名，并将A记录添加好。
* 阅读[V2ray官方说明](https://www.v2ray.com/)，了解 TLS WebSocket 及 V2ray 相关信息
* 安装好 git
## 安装方式
```
git clone https://github.com/wulabing/V2Ray_ws-tls_bash_onekey.git temp

cd temp

bash install.sh | tee v2log.txt
```
### 测试说明
* 该测试为 V2.0 版本在 Vultr 测试机使用官方模板进行的测试
* 理论上支持所有具备 Systemd 特性的开发版系统

| NO | Status| Platform|
|----|-------|---------|
|1|PASS|Centos 7|
|2|PASS|Debian 8|
|3|PASS|Debian 9|
|4|PASS|Ubuntu 16.04|
|5|PASS|Ubuntu 17.04|
### 问题反馈
* 请携带 v2log.txt 文件内容进行反馈
### 更新说明
## 2017-12-06
### V2.0 （stable）
* 1.增加 Centos7 系统支持
* 2.增加 自定义端口 和 自定义alterID
* 3.完善 安装所需依赖
* 4.修复 Ubuntu 系列系统版本判断异常导致的安装中断问题
* 5.修复 bug

V1.02（beta）
* 1.增加 系统判定，目前打算仅支持带systemd的较新主流开发版系统
* 2.本机 IP 获取方式重构

## 2017-12-05

V1.01（beta）
* 1.完善 支持 Debian9
* 2.修复 由于 Debian9 默认未安装 net-tools 导致的本机ip判定错误
* 3.修复 bc 安装问题
* 4.增加 ip 判定不一致时继续安装的选项（由于某些vps情况比较特殊，判定到内网IP或本身网卡信息，或公网ip与服务期内信息不一致等情况）

V1.0（beta）
* 1.目前仅支持 Debian 8+ / Ubuntu 16.04+ 
* 2.逐渐完善中
