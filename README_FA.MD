
## اسکریپت نصب Xray مبتنی بر Nginx برای ساختار VLESS + XTLS با یک کلیک <img src="https://raw.githubusercontent.com/wulabing/Xray_onekey/main/image/project_xray.jpg" alt="Project_Xray" width="122" height="30" align="bottom" />


> با تشکر از JetBrains برای مجوز توسعه نرم افزار منبع باز غیر تجاری!


>از مجوز توسعه منبع باز غیر تجاری توسط JetBrains سپاسگزاریم!

### با توجه به احتمال مسدود شدن xtls، پیشنهاد می شود از نسخه پیشین Nginx استفاده کنید 


### گروه تلگرام
* گروه ارتباطی تلگرام: https://t.me/wulabing_v2ray 
* کانال اطلاعیه آپدیت تلگرام:https://t.me/wulabing_channel

### آماده سازی
* یک نام دامنه آماده کنید و رکورد A را اضافه کنید

* نصب کردن wget

### مشخصات لینک وارد کردن
https://github.com/XTLS/Xray-core/issues/91

> As of 2021-2-24, only V2RayN 4.12+ and V2RayNG 1.5.8+ support link and QR code import. For other clients, please fill in the configuration information manually.


### روش نصب و بروزرسانی (Nginx front)

پیکربندی قابل پشتیبان

- VLESS + TCP + TLS + Nginx + WebSocket

```
wget -N --no-check-certificate -q -O install.sh "https://raw.githubusercontent.com/wulabing/Xray_onekey/nginx_forward/install.sh" && chmod +x install.sh && bash install.sh
```

### روش نصب و بروزرسانی (Xray front)

پیکربندی قابل پشتیبانی
- VLESS + TCP + XTLS / TLS  + Nginx

- VLESS + TCP + XTLS / TLS  + Nginx 及 VLESS + TCP + TLS + Nginx + WebSocket 回落并存模式

```
wget -N --no-check-certificate -q -O install.sh "https://raw.githubusercontent.com/wulabing/Xray_onekey/main/install.sh" && chmod +x install.sh && bash install.sh
```


### موارد احتیاط
* اگر معنای خاص هر یک از تنظیمات در اسکریپت را نمی‌دانید، به جز نام دامنه، لطفاً از مقدار پیش‌فرض ارائه شده توسط اسکریپت استفاده کنید.
* برای استفاده از این اسکریپت، باید پایه و تجربه لینوکس، مقداری دانش در مورد شبکه های کامپیوتری و عملیات اولیه کامپیوتر داشته باشید.
* در حال حاضر از Debian 9+ / Ubuntu 18.04+ / Centos7+ / Oracle Linux 7+ پشتیبانی می کند.
* مالک گروه فقط پشتیبانی بسیار محدودی را ارائه می دهد، اگر سؤالی دارید، می توانید از اعضای گروه بپرسید.

### با تشکر

* 本脚本中 README Project_Xray 项目图片由 Blitzcrank Telegram:@Blitz_crank 提供 在此感谢Blitzcrank
* 本脚本中 MTProxyTLS 基于 https://github.com/sunpma/mtp 二次修改 在此感谢 sunpma；
* 本脚本中 锐速 4 合 1 脚本原项目引用 https://www.94ish.me/1635.html 在此感谢；
* 本脚本中 锐速 4 合 1 脚本修改版项目引用 https://github.com/ylx2016/Linux-NetSpeed 在此感谢 ylx2016；
* 本脚本中 配置文件及部分逻辑参考 https://github.com/jiuqi9997/xray-yes 在此感谢 玖柒；
* 本脚本中 二维码 API 部分参考 https://github.com/mack-a/v2ray-agent  在此感谢 mack-a。

### روش شروع و توقف سرویس

start Xray：`systemctl start xray`

stop Xray：`systemctl stop xray`

start Nginx：`systemctl start nginx`

stop Nginx：`systemctl stop nginx`

### قسمت های که پروژه استفاده می کند

Web دایرکتوری：`/www/xray_web`

Xray پیکربندی سرور：`/usr/local/etc/xray/config.json`

Nginx دایرکتوری： `/etc/nginx`

certs： `/ssl/xray.key`（私钥）和 `/ssl/xray.crt`（证书公钥）

### حمایت کردن

با خرید vps

https://bandwagonhost.com/aff.php?aff=63939

با خرید پروکسی

https://justmysocks.net/members/aff.php?aff=17621

با خرید vps

https://www.dmit.io/aff.php?aff=3957

با ایجاد حساب در vultr

https://www.vultr.com/?ref=6881279

حمایت با رمزارز

TRC20:TFannfnajNGYsMTuVDcXfZXXPbcaxAEffa


## Stargazers over time

[![Stargazers over time](https://starchart.cc/wulabing/Xray_onekey.svg)](https://starchart.cc/wulabing/Xray_onekey)

