
## اسکریپت نصب VLESS + XTLS مبتنی بر Xray Nginx با یک کلیک <img src="https://raw.githubusercontent.com/wulabing/Xray_onekey/main/image/project_xray.jpg" alt="Project_Xray" width="122" height="30" align="bottom" />


> Thanks to JetBrains for the non-commercial open source software development license!

> Thanks for non-commercial open source development authorization by JetBrains!

### Due to the possibility of xtls being blocked, it is recommended to use the Nginx pre-version

### Telegram Group
* Telegram communication group: https://t.me/wulabing_v2ray 
* Telegram update announcement channel:https://t.me/wulabing_channel

### Preparation
* Prepare a domain name and add the A record;
* Installed wget.

### import link specification
https://github.com/XTLS/Xray-core/issues/91

> As of 2021-2-24, only V2RayN 4.12+ and V2RayNG 1.5.8+ support link and QR code import. For other clients, please fill in the configuration information manually.


### Installation/update method (Nginx front)

Support configuration


- VLESS + TCP + TLS + Nginx + WebSocket

```
wget -N --no-check-certificate -q -O install.sh "https://raw.githubusercontent.com/wulabing/Xray_onekey/nginx_forward/install.sh" && chmod +x install.sh && bash install.sh
```

### Installation/update method (Xray front)

Support configuration

- VLESS + TCP + XTLS / TLS  + Nginx

- VLESS + TCP + XTLS / TLS  + Nginx 及 VLESS + TCP + TLS + Nginx + WebSocket 回落并存模式

```
wget -N --no-check-certificate -q -O install.sh "https://raw.githubusercontent.com/wulabing/Xray_onekey/main/install.sh" && chmod +x install.sh && bash install.sh
```


### Precautions
* If you don't understand the specific meaning of each setting in the script, except the domain name, please use the default value provided by the script;
* To use this script, you need to have Linux foundation and experience, some knowledge of computer networks, and basic computer operations;
* Currently supports Debian 9+ / Ubuntu 18.04+ / Centos7+ / Oracle Linux 7+;
* The group owner only provides extremely limited support, if you have any questions, you can ask the group members.

### 鸣谢

* 本脚本中 README Project_Xray 项目图片由 Blitzcrank Telegram:@Blitz_crank 提供 在此感谢Blitzcrank
* 本脚本中 MTProxyTLS 基于 https://github.com/sunpma/mtp 二次修改 在此感谢 sunpma；
* 本脚本中 锐速 4 合 1 脚本原项目引用 https://www.94ish.me/1635.html 在此感谢；
* 本脚本中 锐速 4 合 1 脚本修改版项目引用 https://github.com/ylx2016/Linux-NetSpeed 在此感谢 ylx2016；
* 本脚本中 配置文件及部分逻辑参考 https://github.com/jiuqi9997/xray-yes 在此感谢 玖柒；
* 本脚本中 二维码 API 部分参考 https://github.com/mack-a/v2ray-agent  在此感谢 mack-a。

### 启动方式

启动 Xray：`systemctl start xray`

停止 Xray：`systemctl stop xray`

启动 Nginx：`systemctl start nginx`

停止 Nginx：`systemctl stop nginx`

### 相关目录

Web 目录：`/www/xray_web`

Xray 服务端配置：`/usr/local/etc/xray/config.json`

Nginx 目录： `/etc/nginx`

证书文件： `/ssl/xray.key`（私钥）和 `/ssl/xray.crt`（证书公钥）

### 捐赠

您可以使用我的 搬瓦工 AFF 购买 VPS

https://bandwagonhost.com/aff.php?aff=63939

您可以使用我的 JustMySocks AFF 购买搬瓦工提供的代理

https://justmysocks.net/members/aff.php?aff=17621

您可以使用我的 DMIT AFF 购买 VPS

https://www.dmit.io/aff.php?aff=3957

您可以使用我的 Vultr AFF 创建新的 Vultr 账号并使用

https://www.vultr.com/?ref=6881279

您可以通过 USDT 支持我，感谢您的支持
TRC20:TFannfnajNGYsMTuVDcXfZXXPbcaxAEffa


## Stargazers over time

[![Stargazers over time](https://starchart.cc/wulabing/Xray_onekey.svg)](https://starchart.cc/wulabing/Xray_onekey)

