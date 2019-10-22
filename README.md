# V2Ray 基于 Nginx 的 vmess+ws+tls 一键安装脚本 （Use Path）

> 感谢 JetBrains 提供的非商业开源软件开发授权

> Thanks for non-commercial open source development authorization by JetBrains

#### 如果你遇到 PC 端可用，手机不可用的情况，请将手机调至飞行模式后再取消飞行模式，然后尝试连接
### 2019-10-17

> 建议遇到问题的用户重置系统后重新安装


* 变更 添加 Nginx systemd serverfile
* 修复 又双叒叕尝试修复 Nginx 开机自启动问题

### 2019-10-16

* 适配 Centos8 Debian10 Ubuntu19.04
* 修复 部分系统下 计划任务不生效的问题
* 修复 时间同步服务 在 Centos8 下无法安装的错误
* 修复 部分系统下 证书不会自动更新的问题
* 修复 部分系统下 Nginx 开机自启配置失效的问题
* 变更 重复安装时，将不对相同的域名进行重复的证书申请，防止出现 Let's encrypt API 次数限制
* 变更 默认 alterID 64 -> 4 ，减少资源占用
* 变更 nginx 安装方式从源获取 变更为 编译安装，并使用新版Openssl，支持tls1.3
* 变更 nginx 配置文件 ssl_protocols ssl_ciphers，适配 tls1.3
* 变更 取消对Debian8 Ubuntu 16.04 的适配工作（本版本可能依旧可用）
* 变更 默认页面伪装为 html5 小游戏
* 新增 安装完成，节点配置信息留档
* 新增 使用自定义证书
* 新增 链接方式导入导入
* 新增 二维码方式导入

### 使用自定义证书
将crt和key文件命名为v2ray.crt v2ray.key 放在 /data 目录下（若目录不存在请先建目录）

### 查看客户端配置
放在执行脚本所在目录下的 v2ray_info.txt

推荐使用 `cat v2ray_info.txt` 查看

### V2ray 简介

* V2Ray是一个优秀的开源网络代理工具，可以帮助你畅爽体验互联网，目前已经全平台支持Windows、Mac、Android、IOS、Linux等操作系统的使用。
* 本脚本的另一个分支版本（Use Host）地址： https://github.com/dylanbai8/V2Ray_ws-tls_Website_onekey 请根据需求进行选择， 感谢作者 dylanbai8 的改进与维护
* 本脚本为一键完全配置脚本，在所有流程正常运行完毕后，直接按照输出结果设置客户端即可使用
* 已安装的用户，当出现无法连接的情况时，请用户根据该文档更新 V2ray core 
* 请注意：我们依然强烈建议你全方面的了解整个程序的工作流程及原理


### 目前支持Debian 9+ / Ubuntu 18.04+ / Centos7+
### 如果你选择使用 V2ray，强烈建议你关闭并删除所有的 shadowsocksR 服务端，仅使用标准的 V2ray 三件套（原因请查看 Wiki ）
* 本脚本默认安装最新版本的V2ray core
* V2ray core 目前最新版本为 4.20（同时请注意客户端 core 的同步更新，需要保证客户端内核版本 >= 服务端内核版本）
* 由于新版本增加了 web 伪装，因此强烈建议使用默认的443端口作为连接端口
* 伪装内容是随便找的，内容与作者无关，可自行替换。
## V2ray core 更新方式
执行：
`bash <(curl -L -s https://install.direct/go.sh)`

（ 来源参考 ：[V2ray官方说明](https://www.v2ray.com/chapter_00/install.html)）
* 如果为最新版本，会输出提示并停止安装。否则会自动更新
* 未来会将相关内容集成到本脚本中并进行交互式操作更新

## 注意事项
* 推荐在纯净环境下使用本脚本，如果你是新手，请不要使用Centos系统。
* 在尝试本脚本确实可用之前，请不要将本程序应用于生产环境中。
* 该程序依赖 Nginx 实现相关功能，请使用 [LNMP](https://lnmp.org) 或其他类似携带 Nginx 脚本安装过 Nginx 的用户特别留意，使用本脚本可能会导致无法预知的错误（未测试，若存在，后续版本可能会处理本问题）。
* V2Ray 的部分功能依赖于系统时间，请确保您使用V2RAY程序的系统 UTC 时间误差在三分钟之内，时区无关。
* 本 bash 依赖于 [V2ray 官方安装脚本](https://install.direct/go.sh) 及 [acme.sh](https://github.com/Neilpang/acme.sh) 工作。
* Centos 系统用户请预先在防火墙中放行程序相关端口（默认：80，443）
## 准备工作
* 准备一个域名，并将A记录添加好。
* [V2ray官方说明](https://www.v2ray.com/)，了解 TLS WebSocket 及 V2ray 相关信息
* 安装好 curl
## 安装方式（不兼容，二选一）
Vmess+websocket+TLS+Nginx+Website
```
bash <(curl -L -s https://raw.githubusercontent.com/wulabing/V2Ray_ws-tls_bash_onekey/master/install.sh) | tee v2ray_ins.log
```
Vmess + HTTP2 over TLS
```
bash <(curl -L -s https://raw.githubusercontent.com/wulabing/V2Ray_ws-tls_bash_onekey/master/install_h2.sh) | tee v2ray_ins_h2.log
```
### 启动方式

启动 V2ray：`systemctl start v2ray`

停止 V2ray：`systemctl stop v2ray`

启动 Nginx：`systemctl start nginx`

停止 Nginx：`systemctl stop nginx`


（其他的应该不用我多说了吧 嘿嘿嘿）
### 相关目录

Web 目录：`/home/wwwroot/levis`

V2ray 服务端配置：`/etc/v2ray/config.json`

V2ray 客户端配置: `执行安装时所在目录下的 v2ray_info.txt`

Nginx 目录： `/etc/nginx`

证书目录: `/data/v2ray.key 和 /data/v2ray.crt`

### 更新说明

...

## 2018-04-10
* vmess+http2 over tls 脚本更新
## 2018-04-08
v3.3.1（Beta）
* 安装依赖小幅调整
* Readme内容调整
## 2018-04-06
v3.3(Beta)
* 修复 Ubuntu 16.04/17.10 安装后的Nginx启动失败
* 修复 由于重复执行脚本导致的 Nginx 安装源的重复添加问题
* 修复 由于重复执行脚本导致的 Nginx 配置文件异常，从而导致 Nginx 启动失败的问题
* 修复 Nginx Ubuntu 源错误添加导致的 Nginx 版本问题
## 2018-04-03
V3.2(Beta)
* Nginx 版本更新至mainline版本
* Nginx 配置中添加 TLS1.3 http2
## 2018-03-26
V3.1(Beta)
* 1.去除无关的依赖
* 2.安装顺序变更，SSL生成放在程序末尾
* 3.NGINX 安装版本统一为最新 stable 版本（为将来可能进行的 http2 及 tls1.3 适配做好准备,debian 源默认 NGINX 版本过低不支持 http2）
## 2018-03-18
V3.0(Stable)
* 1.修复 Path 分流时访问特定的伪装 Path 时出现的 Bad Request 问题 （统一为404 Not Found）
## 2018-03-10
V3.0(beta)
* 1.部分功能进行代码重构
* 2.添加了 301 重定向，即 http 强制跳转 https 
* 3.添加了 页面伪装（一个计算器程序）
* 4.伪装path 从原来的/ray/ 变为 随机生成
## 2018-03-05
V2.1.1(stable)
* 1.变更 检测到端口占用后，尝试自动kill相关进程
* 2.尝试修复 GCE 默认纯净模板80端口占用问题（等待更多反馈）
## 2018-02-04
V2.1.1(stable)
* 1.变更 local_ip 判断方式，从 本地网卡获取 变更至 命令获取 公网IP。
* 1.修复 域名dns解析IP 与 本机IP 不匹配 误报问题
## 2018-01-28
v2.1.1(stable)
* 1.修复 缺乏 lsof 依赖导致的端口占用判断异常问题
## 2018-01-27
v2.1.1(stable）
* 1.修复 部分机型因缺乏 crontab （计划任务）依赖导致的安装失败问题
* 2.完善 端口占用 判断
## 2017-12-06
V2.1（stable）
* 1.修复 Centos7 找不到 Nginx 安装包的问题
* 2.完善 SElinux 配置过程提醒标识

V2.0（stable）
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


