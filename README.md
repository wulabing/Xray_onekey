## V2Ray vmess + ws + tls one-click installation script based on Nginx

> Thank you JetBrains for the non-commercial open source software development license

> Thanks for non-commercial open source development authorization by JetBrains
### Telegram group
* telegram communication group: https://t.me/wulabing_v2ray 
* telegram update announcement channel: https://t.me/wulabing_channel

### Ready to work
* Prepare a domain name and add the A record.
* [V2ray official instructions](https://www.v2ray.com/) understand TLS WebSocket and V2ray related information
* Install wget

### Installation / update method (h2 and ws versions have been merged)
Vmess+websocket+TLS+Nginx+Website
```
wget -N --no-check-certificate -q -O install.sh "https://raw.githubusercontent.com/Chifth/V2Ray_ws-tls_bash_onekey/master/install.sh" && chmod +x install.sh && bash install.sh
```

### Precautions
* If you don't understand the meaning of each setting in the script, except the domain name, please use the default value provided by the script
* The use of this script requires you to have Linux basics and experience, understand some computer network knowledge, basic computer operations
* Currently supports Debian 9+ / Ubuntu 18.04+ / Centos7 +, some Centos templates may have difficult compilation problems. It is recommended that you replace the template with other system templates when you encounter compilation problems
* The group owner only provides extremely limited support, if you have any questions, you can ask the group friends
* At 3 am every Sunday, Nginx will automatically restart to cooperate with the scheduled task of issuing certificates. During this period, nodes cannot connect normally, and the estimated duration is several seconds to two minutes

### Change log
> Please check CHANGELOG.md

### Thanks
* Address of another branch version (Use Host) of this script: https://github.com/dylanbai8/V2Ray_ws-tls_Website_onekey Please choose according to your needs The author may have stopped maintaining
* MTProxy-go TLS version project reference in this script https://github.com/whunt1/onekeymakemtg Thank you for whunt1
* The original project of Rui 4 in 1 script in this script refers to https://www.94ish.me/1635.html Thank you
* This script sharp-speed 4-in-1 script modified version of the project references https://github.com/ylx2016/Linux-NetSpeed thank ylx2016

### certificate
> If you already have the certificate file of the domain name you use, you can name the crt and key files as v2ray.crt v2ray.key in the / data directory (if the directory does not exist, please create a directory first), please note the certificate file permissions and Certificate validity period, please renew the certificate yourself after the validity period of the custom certificate expires

The script supports automatic generation of let's encrypted certificate, which is valid for 3 months. In theory, the automatically generated certificate supports automatic renewal.

### View client configuration
`cat ~/v2ray_info.txt`

### V2ray Introduction

* V2Ray is an excellent open source network proxy tool that can help you experience the Internet smoothly. At present, the entire platform supports the use of Windows, Mac, Android, IOS, Linux and other operating systems.
* This script is a one-click full configuration script. After all processes are running normally, you can use the client by setting the client directly according to the output results.
* Please note: We still strongly recommend that you fully understand the workflow and principle of the entire program

### It is recommended that a single server only build a single agent
* This script installs the latest version of V2ray core by default
* The latest version of V2ray core is 4.22.1 (At the same time please pay attention to the synchronous update of the client core, you need to ensure that the client kernel version> = server kernel version)
* It is recommended to use the default port 443 as the connection port
* The disguised content can be replaced on its own.

### Precautions
* It is recommended to use this script in a pure environment. If you are new, please do not use Centos system.
* Do not use this program in a production environment until you have tried that the script is indeed available.
* This program relies on Nginx to implement related functions. Please use LNMP https://lnmp.org/ or other similar users who have installed Nginx scripts to pay special attention to the use of this script may cause unpredictable errors (not tested, if it exists, subsequent versions may deal with this problem) .
* Some functions of V2Ray depend on the system time. Please make sure that the UTC time error of your system using V2RAY program is within three minutes, and the time zone is irrelevant.
* This bash relies on the official V2ray installation script (https://install.direct/go.sh) and [acme.sh](https://github.com/Neilpang/acme.sh) to work
* Centos users, please pass the program related ports in the firewall in advance (default: 80, 443)


### Start way

Start V2ray：`systemctl start v2ray`

Stop V2ray：`systemctl stop v2ray`

Start Nginx：`systemctl start nginx`

Stop Nginx：`systemctl stop nginx`

### Related directories

Web directory：`/home/wwwroot/3DCEList`

V2ray server configuration：`/etc/v2ray/config.json`

V2ray client configuration: `~/v2ray_info.txt`

Nginx directory： `/etc/nginx`

Certificate file: `/data/v2ray.key and /data/v2ray.crt` Please note the certificate authority setting

### Donate

Currently accepting virtual currency donations via MugglePay

𝒘𝒖𝒍𝒂𝒃𝒊𝒏𝒈 Invite you to use Muggle treasure, Telegram-based e-wallet, anonymously pay 0 transaction fee to the account in seconds. https://telegram.me/MugglePayBot?start=T3Y78AZ3

You can donate to me anonymously via Telegram: Send / pay @wulabing xxx to @MugglePayBot and the default currency is USDT

If you need to donate through Alipay / WeChat, please Telegram private chat @wulabing Thank you for your support
