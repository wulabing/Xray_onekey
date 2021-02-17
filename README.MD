## xray 基于 Nginx 的 vless + xtls 一键安装脚本
> 感谢 JetBrains 提供的非商业开源软件开发授权

> Thanks for non-commercial open source development authorization by JetBrains

### Telegram 群组
* telegram 交流群:https://t.me/wulabing_v2ray 
* telegram 更新公告频道：https://t.me/wulabing_channel

### 准备工作
* 准备一个域名，并将A记录添加好。
* 安装好 wget

### 安装/更新方式（xray）
vless + xtls + nginx + web

```
wget -N --no-check-certificate -q -O install.sh "https://raw.githubusercontent.com/wulabing/V2Ray_ws-tls_bash_onekey/xray/install.sh" && chmod +x install.sh && bash install.sh
```

### 注意事项
* 如果你不了解脚本中各项设置的具体含义，除域名外，请使用脚本提供的默认值
* 使用本脚本需要你拥有 Linux 基础及使用经验，了解计算机网络部分知识，计算机基础操作
* 目前支持Debian 9+ / Ubuntu 18.04+ / Centos7+
* 群主仅提供极其有限的支持，如有问题可以询问群友

### 鸣谢

* 本脚本中 MTProxy-go TLS 版本项目引用 https://github.com/whunt1/onekeymakemtg 在此感谢 whunt1
* 本脚本中 锐速4合1脚本原项目引用 https://www.94ish.me/1635.html 在此感谢
* 本脚本中 锐速4合1脚本修改版项目引用 https://github.com/ylx2016/Linux-NetSpeed 在此感谢 ylx2016
* 本脚本中 配置文件及部分逻辑参考 https://github.com/jiuqi9997/xray-yes 在此感谢 玖柒
* 本脚本中 二维码API部分参考 https://github.com/mack-a/v2ray-agent  在此感谢 mack-a

### 启动方式

启动 xray：systemctl start xray

停止 xray：systemctl stop xray

启动 Nginx：systemctl start nginx

停止 Nginx：systemctl stop nginx

### 相关目录

Web 目录：/www/xray_web

xray 服务端配置：/usr/local/etc/xray/config.json

Nginx 目录： /etc/nginx

证书文件: /ssl/v2ray.key 和 /ssl/v2ray.crt

### 捐赠

目前支持通过 MugglePay 接受虚拟货币捐赠

您可以通过Telegram向我匿名捐赠：发送 /pay @wulabing xxx 到 @MugglePayBot 即可 默认货币为 USDT

如需要通过支付宝/微信捐赠，请Telegram私聊 @wulabing 感谢您的支持

## Stargazers over time

[![Stargazers over time](https://starchart.cc/wulabing/V2Ray_ws-tls_bash_onekey.svg)](https://starchart.cc/wulabing/V2Ray_ws-tls_bash_onekey)