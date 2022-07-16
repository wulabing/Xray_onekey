## ss-openresty 白名单

> 请注意该内容依然属于测试内容，相关的技术框架已经全部说明，具体内容可以查阅相关文档

这是一个 ss 的基于 openresty（nginx) 的白名单实现
* 使用 `docker-compose` 启动
* 利用 `ngx_http_auth_basic_module` 进行访问验证
* 利用 `ngx_http_access_module` 实现IP白名单控制
* 利用 `ngx_stream_proxy_module` 实现四层反向代理 
* 利用 `lua` 进行配置调整及应用 

通过浏览器访问代理的IP地址，并通过用户名密码验证，即可添加当前访问IP至白名单
不需要签发证书，ss 使用 `ss-libev` 版本

无教程，具体需要的内容可以查看 docker-compose.yml 中的 volume 部分，包括 nginx 配置文件，模板也在 ss_whitelist 文件夹中，在对应文件夹需要创建一个 allow.list 空文件
## 优势
* 不再需要 tls / tls 隧道，TCP直连。
* 没有签发证书的繁琐流程
* 应该大概也许可能 能够最大程度上保证 端口/IP 不被封禁

## 原理

目前对 ss 类协议的主要探测方式为大量IP进行主动探测，并对端口进行封禁

经过 **少量** 测试发现，使用白名单限制ss端口访问来源可以很大程度上规避端口封禁

> 我们相信防火墙可以通过伪造来源IP的方式来访问服务端，并进行重放攻击，ss-AEAD 本身的抗重放应该足以应对这种情况

大部分代理使用场景都是在固定场所，在一定时间内有相对固定的 IP，因此在大部分情况下，通过白名单限制访问 ss 的 IP 来源方式相对可行

## 使用方法

* 访问 IP/auth (eg: http://1.1.1.1/auth) 输入鉴权信息，添加当前 IP 地址进入白名单
* 访问 /purge 清空白名单信息
* 务必将 allow.list 的权限设置为 666 及以上
* 适配 ARM 架构机器，可以在 Oracle ARM 上使用