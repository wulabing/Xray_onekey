#!/usr/bin/env bash

#====================================================
#	System Request:Debian 9+/Ubuntu 18.04+/Centos 7+
#	Author:	wulabing
#	Dscription: Xray onekey Management
#	email: admin@wulabing.com
#====================================================

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
stty erase ^?

cd "$(
  cd "$(dirname "$0")" || exit
  pwd
)" || exit

# 字体颜色配置
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
Blue="\033[36m"
Font="\033[0m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
OK="${Green}[OK]${Font}"
ERROR="${Red}[ERROR]${Font}"

# 变量
shell_version="1.2.6"
github_branch="main"
xray_conf_dir="/usr/local/etc/xray"
website_dir="/www/xray_web/"
xray_access_log="/var/log/xray/access.log"
xray_error_log="/var/log/xray/error.log"
cert_dir="/usr/local/etc/xray"
domain_tmp_dir="/usr/local/etc/xray"
cert_group="nobody"
random_num=$((RANDOM % 12 + 4))

VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')
WS_PATH="/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})/"

function shell_mode_check() {
  if [ -f ${xray_conf_dir}/config.json ]; then
    if [ "$(grep -c "wsSettings" ${xray_conf_dir}/config.json)" -ge 1 ]; then
      shell_mode="ws"
    else
      shell_mode="tcp"
    fi
  else
    shell_mode="None"
  fi
}
function print_ok() {
  echo -e "${OK} ${Blue} $1 ${Font}"
}

function print_error() {
  echo -e "${ERROR} ${RedBG} $1 ${Font}"
}

function is_root() {
  if [[ 0 == "$UID" ]]; then
    print_ok "当前用户是 root 用户，开始安装流程"
  else
    print_error "当前用户不是 root 用户，请切换到 root 用户后重新执行脚本"
    exit 1
  fi
}

judge() {
  if [[ 0 -eq $? ]]; then
    print_ok "$1 完成"
    sleep 1
  else
    print_error "$1 失败"
    exit 1
  fi
}

function system_check() {
  source '/etc/os-release'

  if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
    print_ok "当前系统为 Centos ${VERSION_ID} ${VERSION}"
    INS="yum install -y"
    wget -N -P /etc/yum.repos.d/ https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/basic/nginx.repo
  elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 9 ]]; then
    print_ok "当前系统为 Debian ${VERSION_ID} ${VERSION}"
    INS="apt install -y"
    # 清除可能的遗留问题
    rm -f /etc/apt/sources.list.d/nginx.list
    $INS lsb-release gnupg2

    echo "deb http://nginx.org/packages/debian $(lsb_release -cs) nginx" >/etc/apt/sources.list.d/nginx.list
    curl -fsSL https://nginx.org/keys/nginx_signing.key | sudo apt-key add -

    apt update
  elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 18 ]]; then
    print_ok "当前系统为 Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME}"
    INS="apt install -y"
    # 清除可能的遗留问题
    rm -f /etc/apt/sources.list.d/nginx.list
    $INS lsb-release gnupg2

    echo "deb http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" >/etc/apt/sources.list.d/nginx.list
    curl -fsSL https://nginx.org/keys/nginx_signing.key | sudo apt-key add -
    apt update
  else
    print_error "当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内"
    exit 1
  fi

  if [[ $(grep "nogroup" /etc/group) ]]; then
    cert_group="nogroup"
  fi

  $INS dbus

  # 关闭各类防火墙
  systemctl stop firewalld
  systemctl disable firewalld
  systemctl stop nftables
  systemctl disable nftables
  systemctl stop ufw
  systemctl disable ufw
}

function nginx_install() {
  if ! command -v nginx >/dev/null 2>&1; then
    ${INS} nginx
    judge "Nginx 安装"
  else
    print_ok "Nginx 已存在"
  fi
}
function dependency_install() {
  ${INS} wget lsof tar
  judge "安装 wget lsof tar"

  if [[ "${ID}" == "centos" ]]; then
    ${INS} crontabs
  else
    ${INS} cron
  fi
  judge "安装 crontab"

  if [[ "${ID}" == "centos" ]]; then
    touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
    systemctl start crond && systemctl enable crond
  else
    touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
    systemctl start cron && systemctl enable cron

  fi
  judge "crontab 自启动配置 "

  ${INS} unzip
  judge "安装 unzip"

  ${INS} curl
  judge "安装 curl"

  # upgrade systemd
  ${INS} systemd
  judge "安装/升级 systemd"

  # Nginx 后置 无需编译 不再需要
  #  if [[ "${ID}" == "centos" ]]; then
  #    yum -y groupinstall "Development tools"
  #  else
  #    ${INS} build-essential
  #  fi
  #  judge "编译工具包 安装"

  if [[ "${ID}" == "centos" ]]; then
    ${INS} pcre pcre-devel zlib-devel epel-release openssl openssl-devel
  else
    ${INS} libpcre3 libpcre3-dev zlib1g-dev openssl libssl-dev
  fi

  ${INS} jq

  if ! command -v jq; then
    wget -P /usr/bin https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/binary/jq && chmod +x /usr/bin/jq
    judge "安装 jq"
  fi
}

function basic_optimization() {
  # 最大文件打开数
  sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  echo '* soft nofile 65536' >>/etc/security/limits.conf
  echo '* hard nofile 65536' >>/etc/security/limits.conf

  # 关闭 Selinux
  if [[ "${ID}" == "centos" ]]; then
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    setenforce 0
  fi
}
function domain_check() {
  read -rp "请输入你的域名信息(eg: www.wulabing.com):" domain
  domain_ip=$(ping "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
  print_ok "正在获取 IP 地址信息，请耐心等待"
  local_ip=$(curl https://api-ipv4.ip.sb/ip)
  echo -e "域名通过 DNS 解析的 IP 地址：${domain_ip}"
  echo -e "本机公网 IP 地址： ${local_ip}"
  sleep 2
  if [[ ${domain_ip} == "${local_ip}" ]]; then
    print_ok "域名通过 DNS 解析的 IP 地址与 本机 IP 地址匹配"
    sleep 2
  else
    print_error "请确保域名添加了正确的 A 记录，否则将无法正常使用 xray"
    print_error "域名通过 DNS 解析的 IP 地址与 本机 IP 地址不匹配，是否继续安装？（y/n）" && read -r install
    case $install in
    [yY][eE][sS] | [yY])
      print_ok "继续安装"
      sleep 2
      ;;
    *)
      print_error "安装终止"
      exit 2
      ;;
    esac
  fi
}

function port_exist_check() {
  if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
    print_ok "$1 端口未被占用"
    sleep 1
  else
    print_error "检测到 $1 端口被占用，以下为 $1 端口占用信息"
    lsof -i:"$1"
    print_error "5s 后将尝试自动 kill 占用进程"
    sleep 5
    lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
    print_ok "kill 完成"
    sleep 1
  fi
}
function update_sh() {
  ol_version=$(curl -L -s https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/install.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
  if [[ "$shell_version" != "$(echo -e "$shell_version\n$ol_version" | sort -rV | head -1)" ]]; then
    print_ok "存在新版本，是否更新 [Y/N]?"
    read -r update_confirm
    case $update_confirm in
    [yY][eE][sS] | [yY])
      wget -N --no-check-certificate https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/install.sh
      print_ok "更新完成"
      print_ok "您可以通过 bash $0 执行本程序"
      exit 0
      ;;
    *) ;;

    esac
  else
    print_ok "当前版本为最新版本"
    print_ok "您可以通过 bash $0 执行本程序"
  fi
}

function xray_tmp_config_file_check_and_use() {
  if [[ -s ${xray_conf_dir}/config_tmp.json ]]; then
    mv -f ${xray_conf_dir}/config_tmp.json ${xray_conf_dir}/config.json
  else
    print_error "xray 配置文件修改异常"
  fi
}

function modify_UUID() {
  [ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"settings","clients",0,"id"];"'${UUID}'")' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray TCP UUID 修改"
}

function modify_UUID_ws() {
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",1,"settings","clients",0,"id"];"'${UUID}'")' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray ws UUID 修改"
}

function modify_fallback_ws() {
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"settings","fallbacks",2,"path"];"'${WS_PATH}'")' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray fallback_ws 修改"
}

function modify_ws() {
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",1,"streamSettings","wsSettings","path"];"'${WS_PATH}'")' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray ws 修改"
}
function modify_tls_version() {
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"streamSettings","xtlsSettings","minVersion"];"'$1'")' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray TLS_version 修改"
}

function configure_nginx() {
  nginx_conf="/etc/nginx/conf.d/${domain}.conf"
  cd /etc/nginx/conf.d/ && rm -f ${domain}.conf && wget -O ${domain}.conf https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/config/web.conf
  sed -i "/server_name/c \\\tserver_name ${domain};" ${nginx_conf}
  judge "Nginx config modify"

  systemctl restart nginx
}

function tls_type() {
  echo "请选择支持的 TLS 版本（默认：TLS1.3 only）:"
  echo "1: TLS1.1, TLS1.2 and TLS1.3（兼容模式）"
  echo "2: TLS1.2 and TLS1.3 (兼容模式)"
  echo "3: TLS1.3 only"
  read -rp "请输入：" tls_version
  [[ -z ${tls_version} ]] && tls_version=3
  if [[ $tls_version == 3 ]]; then
    modify_tls_version "1.3"
  elif [[ $tls_version == 2 ]]; then
    modify_tls_version "1.2"
  else
    modify_tls_version "1.1"
  fi
}

function modify_port() {
  read -rp "请输入端口号(默认：443)：" PORT
  [ -z "$PORT" ] && PORT="443"
  if [[ $PORT -le 0 ]] || [[ $PORT -gt 65535 ]]; then
    print_error "请输入 0-65535 之间的值"
    exit 1
  fi
  port_exist_check $PORT
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"port"];'${PORT}')' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray 端口 修改"
}

function configure_xray() {
  cd /usr/local/etc/xray && rm -f config.json && wget -O config.json https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/config/xray_xtls-rprx-direct.json
  modify_UUID
  modify_port
  tls_type
}

function configure_xray_ws() {
  cd /usr/local/etc/xray && rm -f config.json && wget -O config.json https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/config/xray_tls_ws_mix-rprx-direct.json
  modify_UUID
  modify_UUID_ws
  modify_port
  modify_fallback_ws
  modify_ws
  tls_type
}

function xray_install() {
  print_ok "安装 Xray"
  curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install
  judge "Xray 安装"

  # 用于生成 Xray 的导入链接
  echo $domain >$domain_tmp_dir/domain
  judge "域名记录"
}

function ssl_install() {
  #  使用 Nginx 配合签发 无需安装相关依赖
  #  if [[ "${ID}" == "centos" ]]; then
  #    ${INS} socat nc
  #  else
  #    ${INS} socat netcat
  #  fi
  #  judge "安装 SSL 证书生成脚本依赖"

  curl https://get.acme.sh | sh
  judge "安装 SSL 证书生成脚本"
}

function acme() {

  sed -i "6s/^/#/" "$nginx_conf"

  # 启动 Nginx Xray 并使用 Nginx 配合 acme 进行证书签发
  systemctl restart nginx
  systemctl restart xray

  if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --nginx -k ec-256 --force; then
    print_ok "SSL 证书生成成功"
    sleep 2
    if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /ssl/xray.crt --keypath /ssl/xray.key --reloadcmd "systemctl restart xray" --ecc --force; then
      print_ok "SSL 证书配置成功"
      sleep 2
    fi
  else
    print_error "SSL 证书生成失败"
    rm -rf "$HOME/.acme.sh/${domain}_ecc"
    exit 1
  fi

  sed -i "6s/#//" "$nginx_conf"
}

function ssl_judge_and_install() {

  mkdir -p /ssl
  if [[ -f "/ssl/xray.key" || -f "/ssl/xray.crt" ]]; then
    echo "/ssl 目录下证书文件已存在"
    print_ok "是否删除 [Y/N]?"
    read -r ssl_delete
    case $ssl_delete in
    [yY][eE][sS] | [yY])
      rm -rf /ssl/*
      print_ok "已删除"
      ;;
    *) ;;

    esac
  fi

  if [[ -f "/ssl/xray.key" || -f "/ssl/xray.crt" ]]; then
    echo "证书文件已存在"
  elif [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
    echo "证书文件已存在"
    "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /ssl/xray.crt --keypath /ssl/xray.key --ecc
    judge "证书应用"
  else
    mkdir /ssl
    cp -a $cert_dir/self_signed_cert.pem /ssl/xray.crt
    cp -a $cert_dir/self_signed_key.pem /ssl/xray.key
    ssl_install
    acme
  fi

  # Xray 默认以 nobody 用户运行，证书权限适配
  chown -R nobody.$cert_group /ssl/*
}

function generate_certificate() {
  signedcert=$(xray tls cert -domain="$local_ip" -name="$local_ip" -org="$local_ip" -expire=87600h)
  echo $signedcert | jq '.certificate[]' | sed 's/\"//g' | tee $cert_dir/self_signed_cert.pem
  echo $signedcert | jq '.key[]' | sed 's/\"//g' > $cert_dir/self_signed_key.pem
  openssl x509 -in $cert_dir/self_signed_cert.pem -noout || print_error "生成自签名证书失败"
  print_ok "生成自签名证书成功"
  chown nobody.$cert_group $cert_dir/self_signed_cert.pem
  chown nobody.$cert_group $cert_dir/self_signed_key.pem
}

function configure_web() {
  rm -rf /www/xray_web
  mkdir -p /www/xray_web
  # 该处保留引用源
  wget -O web.tar.gz https://github.com/jiuqi9997/Xray-yes/raw/main/web.tar.gz
  tar xzf web.tar.gz -C /www/xray_web
  judge "站点伪装"
  rm -f web.tar.gz
}

function xray_uninstall() {
  curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- remove --purge
  systemctl stop nginx
  rm -rf $website_dir
  print_ok "卸载完成"
  exit 0
}

function restart_all() {
  systemctl restart nginx
  judge "Nginx 启动"
  systemctl restart xray
  judge "Xray 启动"
}

function vless_xtls-rprx-direct_link() {
  UUID=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
  PORT=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].port)
  FLOW=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].flow | tr -d '"')
  DOMAIN=$(cat ${domain_tmp_dir}/domain)

  print_ok "URL 链接（VLESS + TCP +  TLS）"
  print_ok "vless://$UUID@$DOMAIN:$PORT?security=tls&flow=$FLOW#TLS_wulabing-$DOMAIN"

  print_ok "URL 链接（VLESS + TCP +  XTLS）"
  print_ok "vless://$UUID@$DOMAIN:$PORT?security=xtls&flow=$FLOW#XTLS_wulabing-$DOMAIN"
  print_ok "-------------------------------------------------"
  print_ok "URL 二维码（VLESS + TCP + TLS）（请在浏览器中访问）"
  print_ok "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$UUID@$DOMAIN:$PORT?security=tls%26flow=$FLOW%23TLS_wulabing-$DOMAIN"

  print_ok "URL 二维码（VLESS + TCP + XTLS）（请在浏览器中访问）"
  print_ok "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$UUID@$DOMAIN:$PORT?security=xtls%26flow=$FLOW%23XTLS_wulabing-$DOMAIN"
}

function vless_xtls-rprx-direct_information() {
  UUID=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
  PORT=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].port)
  FLOW=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].flow | tr -d '"')
  DOMAIN=$(cat ${domain_tmp_dir}/domain)

  echo -e "${Red} Xray 配置信息 ${Font}"
  echo -e "${Red} 地址（address）:${Font}  $DOMAIN"
  echo -e "${Red} 端口（port）：${Font}  $PORT"
  echo -e "${Red} 用户 ID（UUID）：${Font} $UUID"
  echo -e "${Red} 流控（flow）：${Font} $FLOW"
  echo -e "${Red} 加密方式（security）：${Font} none "
  echo -e "${Red} 传输协议（network）：${Font} tcp "
  echo -e "${Red} 伪装类型（type）：${Font} none "
  echo -e "${Red} 底层传输安全：${Font} xtls 或 tls"
}

function ws_information() {
  UUID=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
  PORT=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].port)
  FLOW=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].flow | tr -d '"')
  WS_PATH=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.fallbacks[2].path | tr -d '"')
  DOMAIN=$(cat ${domain_tmp_dir}/domain)

  echo -e "${Red} Xray 配置信息 ${Font}"
  echo -e "${Red} 地址（address）:${Font}  $DOMAIN"
  echo -e "${Red} 端口（port）：${Font}  $PORT"
  echo -e "${Red} 用户 ID（UUID）：${Font} $UUID"
  echo -e "${Red} 加密方式（security）：${Font} none "
  echo -e "${Red} 传输协议（network）：${Font} ws "
  echo -e "${Red} 伪装类型（type）：${Font} none "
  echo -e "${Red} 路径（path）：${Font} $WS_PATH "
  echo -e "${Red} 底层传输安全：${Font} tls "
}

function ws_link() {
  UUID=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
  PORT=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].port)
  FLOW=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].flow | tr -d '"')
  WS_PATH=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.fallbacks[2].path | tr -d '"')
  WS_PATH_WITHOUT_SLASH=$(echo $WS_PATH | tr -d '/')
  DOMAIN=$(cat ${domain_tmp_dir}/domain)

  print_ok "URL 链接（VLESS + TCP + TLS）"
  print_ok "vless://$UUID@$DOMAIN:$PORT?security=tls#TLS_wulabing-$DOMAIN"

  print_ok "URL 链接（VLESS + TCP + XTLS）"
  print_ok "vless://$UUID@$DOMAIN:$PORT?security=xtls&flow=$FLOW#XTLS_wulabing-$DOMAIN"

  print_ok "URL 链接（VLESS + WebSocket + TLS）"
  print_ok "vless://$UUID@$DOMAIN:$PORT?type=ws&security=tls&path=%2f${WS_PATH_WITHOUT_SLASH}%2f#WS_TLS_wulabing-$DOMAIN"
  print_ok "-------------------------------------------------"
  print_ok "URL 二维码（VLESS + TCP + TLS）（请在浏览器中访问）"
  print_ok "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$UUID@$DOMAIN:$PORT?security=tls%23TLS_wulabing-$DOMAIN"

  print_ok "URL 二维码（VLESS + TCP + XTLS）（请在浏览器中访问）"
  print_ok "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$UUID@$DOMAIN:$PORT?security=xtls%26flow=$FLOW%23XTLS_wulabing-$DOMAIN"

  print_ok "URL 二维码（VLESS + WebSocket + TLS）（请在浏览器中访问）"
  print_ok "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$UUID@$DOMAIN:$PORT?type=ws%26security=tls%26path=%2f${WS_PATH_WITHOUT_SLASH}%2f%23WS_TLS_wulabing-$DOMAIN"
}

function basic_information() {
  print_ok "VLESS+TCP+XTLS+Nginx 安装成功"
  vless_xtls-rprx-direct_information
  vless_xtls-rprx-direct_link
}

function basic_ws_information() {
  print_ok "VLESS+TCP+TLS+Nginx with WebSocket 混合模式 安装成功"
  ws_information
  print_ok "————————————————————————"
  vless_xtls-rprx-direct_information
  ws_link
}

function show_access_log() {
  [ -f ${xray_access_log} ] && tail -f ${xray_access_log} || echo -e "${RedBG}log文件不存在${Font}"
}

function show_error_log() {
  [ -f ${xray_error_log} ] && tail -f ${xray_error_log} || echo -e "${RedBG}log文件不存在${Font}"
}

function bbr_boost_sh() {
  [ -f "tcp.sh" ] && rm -rf ./tcp.sh
  wget -N --no-check-certificate "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
}

function mtproxy_sh() {
  wget -N --no-check-certificate "https://github.com/wulabing/mtp/raw/master/mtproxy.sh" && chmod +x mtproxy.sh && bash mtproxy.sh
}

function install_xray() {
  is_root
  system_check
  dependency_install
  basic_optimization
  domain_check
  port_exist_check 80
  xray_install
  configure_xray
  nginx_install
  configure_nginx
  configure_web
  generate_certificate
  ssl_judge_and_install
  restart_all
  basic_information
}
function install_xray_ws() {
  is_root
  system_check
  dependency_install
  basic_optimization
  domain_check
  port_exist_check 80
  xray_install
  configure_xray_ws
  nginx_install
  configure_nginx
  configure_web
  generate_certificate
  ssl_judge_and_install
  restart_all
  basic_ws_information
}
menu() {
  update_sh
  shell_mode_check
  echo -e "\t Xray 安装管理脚本 ${Red}[${shell_version}]${Font}"
  echo -e "\t---authored by wulabing---"
  echo -e "\thttps://github.com/wulabing\n"

  echo -e "当前已安装版本：${shell_mode}"
  echo -e "—————————————— 安装向导 ——————————————"""
  echo -e "${Green}0.${Font}  升级 脚本"
  echo -e "${Green}1.${Font}  安装 Xray (VLESS + TCP + XTLS / TLS + Nginx)"
  echo -e "${Green}2.${Font}  安装 Xray (VLESS + TCP + XTLS / TLS + Nginx 及 VLESS + TCP + TLS + Nginx + WebSocket 回落并存模式)"
  echo -e "—————————————— 配置变更 ——————————————"
  echo -e "${Green}11.${Font} 变更 UUID"
  echo -e "${Green}12.${Font} 变更 TLS 最低适配版本"
  echo -e "${Green}13.${Font} 变更 连接端口"
  echo -e "${Green}14.${Font} 变更 WebSocket PATH"
  echo -e "—————————————— 查看信息 ——————————————"
  echo -e "${Green}21.${Font} 查看 实时访问日志"
  echo -e "${Green}22.${Font} 查看 实时错误日志"
  echo -e "${Green}23.${Font} 查看 Xray 配置链接"
  #    echo -e "${Green}23.${Font}  查看 V2Ray 配置信息"
  echo -e "—————————————— 其他选项 ——————————————"
  echo -e "${Green}31.${Font} 安装 4 合 1 BBR、锐速安装脚本"
  echo -e "${Yellow}32.${Font} 安装 MTproxy(不推荐使用,请相关用户关闭或卸载)"
  echo -e "${Green}33.${Font} 卸载 Xray"
  echo -e "${Green}34.${Font} 更新 Xray-core"
  echo -e "${Green}35.${Font} 安装 Xray-core 测试版(Pre)"
  echo -e "${Green}40.${Font} 退出"
  read -rp "请输入数字：" menu_num
  case $menu_num in
  0)
    update_sh
    ;;
  1)
    install_xray
    ;;
  2)
    install_xray_ws
    ;;
  11)
    read -rp "请输入UUID:" UUID
    if [[ ${shell_mode} == "tcp" ]]; then
      modify_UUID
    elif [[ ${shell_mode} == "ws" ]]; then
      modify_UUID
      modify_UUID_ws
    fi
    restart_all
    ;;
  12)
    tls_type
    restart_all
    ;;
  13)
    modify_port
    restart_all
    ;;
  14)
    if [[ ${shell_mode} == "ws" ]]; then
      read -rp "请输入路径(示例：/wulabing/ 要求两侧都包含/):" WS_PATH
      modify_fallback_ws
      modify_ws
      restart_all
    else
      print_error "当前模式不是Websocket模式"
    fi
    ;;
  21)
    tail -f $xray_access_log
    ;;
  22)
    tail -f $xray_error_log
    ;;
  23)
    if [[ -f $xray_conf_dir/config.json ]]; then
      if [[ ${shell_mode} == "tcp" ]]; then
        basic_information
      elif [[ ${shell_mode} == "ws" ]]; then
        basic_ws_information
      fi
    else
      print_error "xray 配置文件不存在"
    fi
    ;;
  31)
    bbr_boost_sh
    ;;
  32)
    mtproxy_sh
    ;;
  33)
    xray_uninstall
    ;;
  34)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install
    restart_all
    ;;
  35)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install --beta
    restart_all
    ;;
  40)
    exit 0
    ;;
  *)
    print_error "请输入正确的数字"
    ;;
  esac
}
menu "$@"
