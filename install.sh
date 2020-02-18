#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

cd $(cd "$(dirname "$0")"; pwd)
#====================================================
#	System Request:Debian 9+/Ubuntu 18.04+/Centos 7+
#	Author:	wulabing
#	Dscription: V2ray ws+tls onekey Management
#	Version: 1.0
#	email:admin@wulabing.com
#	Official document: www.v2ray.com
#====================================================

#fonts color
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"

#notification information
Info="${Green}[Information]${Font}"
OK="${Green}[OK]${Font}"
Error="${Red}[Error]${Font}"

# Version
shell_version="1.1.0"
shell_mode="None"
github_branch="master"
version_cmp="/tmp/version_cmp.tmp"
v2ray_conf_dir="/etc/v2ray"
nginx_conf_dir="/etc/nginx/conf/conf.d"
v2ray_conf="${v2ray_conf_dir}/config.json"
nginx_conf="${nginx_conf_dir}/v2ray.conf"
nginx_dir="/etc/nginx"
web_dir="/home/wwwroot"
nginx_openssl_src="/usr/local/src"
v2ray_bin_file="/usr/bin/v2ray"
v2ray_info_file="$HOME/v2ray_info.inf"
v2ray_qr_config_file="/usr/local/vmess_qr.json"
nginx_systemd_file="/etc/systemd/system/nginx.service"
v2ray_systemd_file="/etc/systemd/system/v2ray.service"
v2ray_access_log="/var/log/v2ray/access.log"
v2ray_error_log="/var/log/v2ray/error.log"
amce_sh_file="/root/.acme.sh/acme.sh"
ssl_update_file="/usr/bin/ssl_update.sh"
nginx_version="1.16.1"
openssl_version="1.1.1d"
jemalloc_version="5.2.1"
old_config_status="off"
v2ray_plugin_version="$(wget -qO- "https://github.com/shadowsocks/v2ray-plugin/tags" |grep -E "/shadowsocks/v2ray-plugin/releases/tag/" |head -1|sed -r 's/.*tag\/v(.+)\">.*/\1/')"

# Mobile version of the configuration information for less than the old version 1.1.0 adapter
[[ -f "/etc/v2ray/vmess_qr.json" ]] && mv /etc/v2ray/vmess_qr.json $v2ray_qr_config_file

# Faked path
camouflage="/`cat /dev/urandom | head -n 10 | md5sum | head -c 8`/"

source /etc/os-release

# Extract English name from VERSION release system, in order to add the corresponding source Nginx apt in debian / ubuntu
VERSION=`echo ${VERSION} | awk -F "[()]" '{print $2}'`

check_system(){
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]];then
        echo -e "${OK} ${GreenBG} The current system is Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum"
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]];then
        echo -e "${OK} ${GreenBG} The current system is Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt"
        $INS update
        ## Add Nginx apt source
    elif [[ "${ID}" == "ubuntu" && `echo "${VERSION_ID}" | cut -d '.' -f1` -ge 16 ]];then
        echo -e "${OK} ${GreenBG} The current system is Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS="apt"
        $INS update
    else
        echo -e "${Error} ${RedBG} The current system is ${ID} ${VERSION_ID} is not on the list of supported systems, the installation was interrupted ${Font}"
        exit 1
    fi

    $INS install dbus

    systemctl stop firewalld
    systemctl disable firewalld
    echo -e "${OK} ${GreenBG} firewalld is closed ${Font}"

    systemctl stop ufw
    systemctl disable ufw
    echo -e "${OK} ${GreenBG} ufw closed ${Font}"
}

is_root(){
    if [ `id -u` == 0 ]
        then echo -e "${OK} ${GreenBG} The current user is root and enters the installation process ${Font}"
        sleep 3
    else
        echo -e "${Error} ${RedBG} The current user is not the root user, please switch to the root user and re-execute the script ${Font}"
        exit 1
    fi
}
judge(){
    if [[ $? -eq 0 ]];then
        echo -e "${OK} ${GreenBG} $1 completed ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} $1 failed ${Font}"
        exit 1
    fi
}
chrony_install(){
    ${INS} -y install chrony
    judge "Install chrony time synchronization service"

    timedatectl set-ntp true

    if [[ "${ID}" == "centos" ]];then
       systemctl enable chronyd && systemctl restart chronyd
    else
       systemctl enable chrony && systemctl restart chrony
    fi

    judge "chronyd start"

    timedatectl set-timezone Europe/Kiev

    echo -e "${OK} ${GreenBG} wait time synchronization ${Font}"
    sleep 10

    chronyc sourcestats -v
    chronyc tracking -v
    date
    read -p "Please confirm whether the time is accurate, the error range is ± 3 minutes (Y / N):" chrony_install
    [[ -z ${chrony_install} ]] && chrony_install="Y"
    case $chrony_install in
        [yY][eE][sS]|[yY])
            echo -e "${GreenBG} continue to install ${Font}"
            sleep 2
            ;;
        *)
            echo -e "${RedBG} installation terminated ${Font}"
            exit 2
            ;;
    esac
}

dependency_install(){
    ${INS} install wget git lsof -y

    if [[ "${ID}" == "centos" ]];then
       ${INS} -y install crontabs
    else
       ${INS} -y install cron
    fi
    judge "Install crontab"

    if [[ "${ID}" == "centos" ]];then
       touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
       systemctl start crond && systemctl enable crond
    else
       touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
       systemctl start cron && systemctl enable cron

    fi
    judge "crontab self-startup configuration"



    ${INS} -y install bc
    judge "install  bc"

    ${INS} -y install unzip
    judge "install  unzip"

    ${INS} -y install qrencode
    judge "install  qrencode"

    ${INS} -y install curl
    judge "install  crul"

    if [[ "${ID}" == "centos" ]];then
       ${INS} -y groupinstall "Development tools"
    else
       ${INS} -y install build-essential
    fi
    judge "Compilation Toolkit Installation"

    if [[ "${ID}" == "centos" ]];then
       ${INS} -y install pcre pcre-devel zlib-devel epel-release
    else
       ${INS} -y install libpcre3 libpcre3-dev zlib1g-dev dbus
    fi

#    ${INS} -y install rng-tools
#    judge "rng-tools installation"

    ${INS} -y install haveged
#    judge "haveged installation"

#    sed -i -r '/^HRNGDEVICE/d;/#HRNGDEVICE=\/dev\/null/a HRNGDEVICE=/dev/urandom' /etc/default/rng-tools

    if [[ "${ID}" == "centos" ]];then
#       systemctl start rngd && systemctl enable rngd
#       judge "rng-tools startup"
       systemctl start haveged && systemctl enable haveged
#       judge "haveged startup"
    else
#       systemctl start rng-tools && systemctl enable rng-tools
#       judge "rng-tools startup"
       systemctl start haveged && systemctl enable haveged
#       judge "haveged startup"
    fi
}
basic_optimization(){
    # The maximum number of open files
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >> /etc/security/limits.conf
    echo '* hard nofile 65536' >> /etc/security/limits.conf

    # Close Selinux
    if [[ "${ID}" == "centos" ]];then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        setenforce 0
    fi

}
port_alterid_set(){
    if [[ "on" != "$old_config_status" ]]
    then
        read -p "Please enter the connection port (default: 443): " port
        [[ -z ${port} ]] && port="443"
        read -p "Please enter alterID (default: 2 only numbers are allowed): " alterID
        [[ -z ${alterID} ]] && alterID="2"
    fi
}
modify_path(){
    if [[ "on" == "$old_config_status" ]]
    then
        camouflage="$(cat $v2ray_qr_config_file | grep '\"path\"' | awk -F '"' '{print $4}')"
    fi
    sed -i "/\"path\"/c \\\t  \"path\":\"${camouflage}\"" ${v2ray_conf}
    judge "V2ray camouflage path modification"
}
modify_alterid(){
    if [[ "on" == "$old_config_status" ]]
    then
        alterID="$(cat $v2ray_qr_config_file | grep '\"aid\"' | awk -F '"' '{print $4}')"
    fi
    sed -i "/\"alterId\"/c \\\t  \"alterId\":${alterID}" ${v2ray_conf}
    judge "V2ray alterid modified "
    [ -f ${v2ray_qr_config_file} ] && sed -i "/\"aid\"/c \\  \"aid\": \"${alterID}\"," ${v2ray_qr_config_file}
    echo -e "${GreenBG} alterID:${alterID} ${Font}"
}
modify_inbound_port(){
    if [[ "on" == "$old_config_status" ]]
    then
        port="$(info_extraction '\"port\"')"
    fi
    if [[ "$shell_mode" != "h2" ]]
    then
        let PORT=$RANDOM+10000
        sed -i "/\"port\"/c  \    \"port\":${PORT}," ${v2ray_conf}
    else
        sed -i "/\"port\"/c  \    \"port\":${port}," ${v2ray_conf}
    fi
    judge "V2ray inbound_port modified "
}
modify_UUID(){
    [ -z $UUID ] && UUID=$(cat /proc/sys/kernel/random/uuid)
    if [[ "on" == "$old_config_status" ]]
    then
        UUID="$(info_extraction '\"id\"')"
    fi
    sed -i "/\"id\"/c \\\t  \"id\":\"${UUID}\"," ${v2ray_conf}
    judge "V2ray UUID modified "
    [ -f ${v2ray_qr_config_file} ] && sed -i "/\"id\"/c \\  \"id\": \"${UUID}\"," ${v2ray_qr_config_file}
    echo -e "${GreenBG} UUID:${UUID} ${Font}"
}
modify_nginx_port(){
    if [[ "on" == "$old_config_status" ]]
    then
        port="$(info_extraction '\"port\"')"
    fi
    sed -i "/ssl http2;$/c \\\tlisten ${port} ssl http2;" ${nginx_conf}
    judge "V2ray port modified "
    [ -f ${v2ray_qr_config_file} ] && sed -i "/\"port\"/c \\  \"port\": \"${port}\"," ${v2ray_qr_config_file}
    echo -e "${GreenBG} port number: ${port} ${Font}"
}
modify_nginx_other(){
    sed -i "/server_name/c \\\tserver_name ${domain};" ${nginx_conf}
    sed -i "/location/c \\\tlocation ${camouflage}" ${nginx_conf}
    sed -i "/proxy_pass/c \\\tproxy_pass http://127.0.0.1:${PORT};" ${nginx_conf}
    sed -i "/return/c \\\treturn 301 https://${domain}\$request_uri;" ${nginx_conf}
    #sed -i "27i \\\tproxy_intercept_errors on;"  ${nginx_dir}/conf/nginx.conf
}
web_camouflage(){
    ##Please note that the default path conflicts with the LNMP script. Do not use this script in the environment where LNMP is installed, otherwise you will bear the consequences.
    rm -rf /home/wwwroot && mkdir -p /home/wwwroot && cd /home/wwwroot
    git clone https://github.com/wulabing/3DCEList.git
    judge "web site masquerade"
}
v2ray_install(){
    if [[ -d /root/v2ray ]];then
        rm -rf /root/v2ray
    fi
    if [[ -d /etc/v2ray ]];then
        rm -rf /etc/v2ray
    fi
    mkdir -p /root/v2ray && cd /root/v2ray
    wget -N --no-check-certificate https://install.direct/go.sh

    ## wget http://install.direct/go.sh

    if [[ -f go.sh ]];then
        rm -rf $v2ray_systemd_file
        systemctl daemon-reload
        bash go.sh --force
        judge "Install V2ray"
    else
        echo -e "${Error} ${RedBG} V2ray installation file download failed, please check if the download address is available ${Font}"
        exit 4
    fi
    # Remove temporary files
    rm -rf /root/v2ray
}
nginx_exist_check(){
    if [[ -f "/etc/nginx/sbin/nginx" ]];then
        echo -e "${OK} ${GreenBG} Nginx already exists, skip the compilation and installation process ${Font}"
        sleep 2
    elif [[ -d "/usr/local/nginx/" ]]
    then
        echo -e "${OK} ${GreenBG} detected Nginx installed by other packages. Continuing the installation will cause conflicts. Please install it after processing ${Font}"
        exit 1
    else
        nginx_install
    fi
}
nginx_install(){
#    if [[ -d "/etc/nginx" ]];then
#        rm -rf /etc/nginx
#    fi

    wget -nc --no-check-certificate http://nginx.org/download/nginx-${nginx_version}.tar.gz -P ${nginx_openssl_src}
    judge "Nginx Download "
    wget -nc --no-check-certificate https://www.openssl.org/source/openssl-${openssl_version}.tar.gz -P ${nginx_openssl_src}
    judge "openssl Download "
    wget -nc --no-check-certificate https://github.com/jemalloc/jemalloc/releases/download/${jemalloc_version}/jemalloc-${jemalloc_version}.tar.bz2 -P ${nginx_openssl_src}
    judge "jemalloc Download "

    cd ${nginx_openssl_src}

    [[ -d nginx-"$nginx_version" ]] && rm -rf nginx-"$nginx_version"
    tar -zxvf nginx-"$nginx_version".tar.gz

    [[ -d openssl-"$openssl_version" ]] && rm -rf openssl-"$openssl_version"
    tar -zxvf openssl-"$openssl_version".tar.gz

    [[ -d jemalloc-"${jemalloc_version}" ]] && rm -rf jemalloc-"${jemalloc_version}"
    tar -xvf jemalloc-"${jemalloc_version}".tar.bz2

    [[ -d "$nginx_dir" ]] && rm -rf ${nginx_dir}


    echo -e "${OK} ${GreenBG} is about to start compiling and installing jemalloc ${Font}"
    sleep 2

    cd jemalloc-${jemalloc_version}
    ./configure
    judge "Compile check"
    make && make install
    judge "jemalloc build and install"
    echo '/usr/local/lib' > /etc/ld.so.conf.d/local.conf
    ldconfig

    echo -e "${OK} ${GreenBG} is about to start compiling and installing Nginx, the process is a little longer, please wait patiently for ${Font}"
    sleep 4

    cd ../nginx-${nginx_version}

    ./configure --prefix="${nginx_dir}"                         \
            --with-http_ssl_module                              \
            --with-http_gzip_static_module                      \
            --with-http_stub_status_module                      \
            --with-pcre                                         \
            --with-http_realip_module                           \
            --with-http_flv_module                              \
            --with-http_mp4_module                              \
            --with-http_secure_link_module                      \
            --with-http_v2_module                               \
            --with-cc-opt='-O3'                                 \
            --with-ld-opt="-ljemalloc"                          \
            --with-openssl=../openssl-"$openssl_version"
    judge "Compile check"
    make && make install
    judge "Nginx build and install"

    # Modify the basic configuration
    sed -i 's/#user  nobody;/user  root;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/worker_processes  1;/worker_processes  3;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/    worker_connections  1024;/    worker_connections  4096;/' ${nginx_dir}/conf/nginx.conf
    sed -i '$i include conf.d/*.conf;' ${nginx_dir}/conf/nginx.conf



    # Delete temporary files
    rm -rf ../nginx-"${nginx_version}"
    rm -rf ../openssl-"${openssl_version}"
    rm -rf ../nginx-"${nginx_version}".tar.gz
    rm -rf ../openssl-"${openssl_version}".tar.gz

    # Add configuration folder to adapt the old script
    mkdir ${nginx_dir}/conf/conf.d
}
ssl_install(){
    if [[ "${ID}" == "centos" ]];then
        ${INS} install socat nc -y
    else
        ${INS} install socat netcat -y
    fi
    judge "Install SSL certificate generation script dependency"

    curl  https://get.acme.sh | sh
    judge "Install SSL Certificate Generation Script"
}
domain_check(){
    read -p "Please enter your domain information (eg: www.wulabing.com): " domain
    domain_ip=`ping ${domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
    echo -e "${OK} ${GreenBG} is getting public IP address , please wait patiently ${Font}"
    local_ip=`curl -4 ip.sb`
    echo -e "Domain Name DNS Resolution IP: ${domain_ip}"
    echo -e "Local IP: ${local_ip}"
    sleep 2
    if [[ $(echo ${local_ip}|tr '.' '+'|bc) -eq $(echo ${domain_ip}|tr '.' '+'|bc) ]];then
        echo -e "${OK} ${GreenBG} The domain name dns resolution IP matches the local IP ${Font}"
        sleep 2
    else
        echo -e "${Error} ${RedBG} Please make sure that the correct A record is added to the domain name, otherwise V2ray will not work properly"
        echo -e "${Error} ${RedBG} The domain name dns resolution IP does not match the local IP. Do you want to continue with the installation? (y / n) ${Font}" && read install
        case $install in
        [yY][eE][sS]|[yY])
            echo -e "${GreenBG} continue to install ${Font}"
            sleep 2
            ;;
        *)
            echo -e "${RedBG} installation terminated ${Font}"
            exit 2
            ;;
        esac
    fi
}

port_exist_check(){
    if [[ 0 -eq `lsof -i:"$1" | grep -i "listen" | wc -l` ]];then
        echo -e "${OK} ${GreenBG} $1 port is not occupied ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} detected $1 port is occupied, the following is $ 1 port occupation information ${Font}"
        lsof -i:"$1"
        echo -e "${OK} ${GreenBG} will try to kill the process automatically after 5s ${Font}"
        sleep 5
        lsof -i:"$1" | awk '{print $2}'| grep -v "PID" | xargs kill -9
        echo -e "${OK} ${GreenBG} kill process ${Font}"
        sleep 1
    fi
}
acme(){
    $HOME/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --force --test
    if [[ $? -eq 0 ]];then
        echo -e "${OK} ${GreenBG} The SSL certificate test was successfully issued, and the official issuance of ${Font}"
        sleep 2
    else
        echo -e "${Error} ${RedBG} SSL certificate test failed to issue ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && rm -rf "$HOME/.acme.sh/${domain}_ecc/${domain}.cer"
        exit 1
    fi

    $HOME/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --force
    if [[ $? -eq 0 ]];then
        echo -e "${OK} ${GreenBG} SSL certificate generation succeeded ${Font}"
        sleep 2
        mkdir /data
        $HOME/.acme.sh/acme.sh --installcert -d ${domain} --fullchainpath /data/v2ray.crt --keypath /data/v2ray.key --ecc
        if [[ $? -eq 0 ]];then
        echo -e "${OK} ${GreenBG} Certificate configuration succeeded ${Font}"
        sleep 2
        fi
    else
        echo -e "${Error} ${RedBG} SSL certificate generation failed ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && rm -rf "$HOME/.acme.sh/${domain}_ecc/${domain}.cer"
        exit 1
    fi
}
v2ray_conf_add_tls(){
    cd /etc/v2ray
    wget --no-check-certificate https://raw.githubusercontent.com/wulabing/V2Ray_ws-tls_bash_onekey/${github_branch}/tls/config.json -O config.json
    modify_path
    modify_alterid
    modify_inbound_port
    modify_UUID
}
v2ray_conf_add_h2(){
    cd /etc/v2ray
    wget --no-check-certificate https://raw.githubusercontent.com/wulabing/V2Ray_ws-tls_bash_onekey/${github_branch}/http2/config.json -O config.json
    modify_path
    modify_alterid
    modify_inbound_port
    modify_UUID
}
old_config_exist_check(){
    if [[ -f $v2ray_qr_config_file ]]
    then
        echo -e "${OK} ${Green} detected the old configuration file, read the old file configuration [Y / N]? ${Font}"
        read -r ssl_delete
        case $ssl_delete in
            [yY][eE][sS]|[yY])
                echo -e "${OK} ${Green} has retained the old configuration ${Font}"
                old_config_status="on"
                port=$(info_extraction '\"port\"')
                ;;
            *)
                rm -rf $v2ray_qr_config_file
                echo -e "${OK} ${Green} has deleted the old configuration ${Font}"
                ;;
        esac
    fi
}
nginx_conf_add(){
    touch ${nginx_conf_dir}/v2ray.conf
    cat>${nginx_conf_dir}/v2ray.conf<<EOF
    server {
        listen 443 ssl http2;
        ssl_certificate       /data/v2ray.crt;
        ssl_certificate_key   /data/v2ray.key;
        ssl_protocols         TLSv1.3;
        ssl_ciphers           TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-128-CCM-8-SHA256:TLS13-AES-128-CCM-SHA256:EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
        server_name           serveraddr.com;
        index index.html index.htm;
        root  /home/wwwroot/3DCEList;
        error_page 400 = /400.html;
        location /ray/
        {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        }
}
    server {
        listen 80;
        server_name serveraddr.com;
        return 301 https://use.shadowsocksr.win\$request_uri;
    }
EOF

modify_nginx_port
modify_nginx_other
judge "Nginx configuration changes"

}

start_process_systemd(){
    systemctl daemon-reload
    if [[ "$shell_mode" != "h2" ]]
    then
        systemctl restart nginx
        judge "Nginx startup "
    fi
    systemctl restart v2ray
    judge "V2ray startup "
}

enable_process_systemd(){
    systemctl enable v2ray
    judge "Set v2ray to start automatically"
    if [[ "$shell_mode" != "h2" ]]
    then
        systemctl enable nginx
        judge "Set Nginx to start automatically"
    fi

}

stop_process_systemd(){
    if [[ "$shell_mode" != "h2" ]]
    then
        systemctl stop nginx
    fi
    systemctl stop v2ray
}
nginx_process_disabled(){
    [ -f $nginx_systemd_file ] && systemctl stop nginx && systemctl disable nginx
}

#debian series 9 10 adapt
#rc_local_initialization(){
#    if [[ -f /etc/rc.local ]];then
#        chmod +x /etc/rc.local
#    else
#        touch /etc/rc.local && chmod +x /etc/rc.local
#        echo "#!/bin/bash" >> /etc/rc.local
#        systemctl start rc-local
#    fi
#
#    judge "rc.local configuration"
#}
acme_cron_update(){
    wget -N -P /usr/bin --no-check-certificate "https://raw.githubusercontent.com/wulabing/V2Ray_ws-tls_bash_onekey/dev/ssl_update.sh"
    if [[ "${ID}" == "centos" ]];then
#        sed -i "/acme.sh/c 0 3 * * 0 \"/root/.acme.sh\"/acme.sh --cron --home \"/root/.acme.sh\" \
#        &> /dev/null" /var/spool/cron/root
        sed -i "/acme.sh/c 0 3 * * 0 bash ${ssl_update_file}" /var/spool/cron/root
    else
#        sed -i "/acme.sh/c 0 3 * * 0 \"/root/.acme.sh\"/acme.sh --cron --home \"/root/.acme.sh\" \
#        &> /dev/null" /var/spool/cron/crontabs/root
        sed -i "/acme.sh/c 0 3 * * 0 bash ${ssl_update_file}" /var/spool/cron/crontabs/root
    fi
    judge "cron scheduled task update"
}

vmess_qr_config_tls_ws(){
    cat > $v2ray_qr_config_file <<-EOF
{
  "v": "2",
  "ps": "wulabing_${domain}",
  "add": "${domain}",
  "port": "${port}",
  "id": "${UUID}",
  "aid": "${alterID}",
  "net": "ws",
  "type": "none",
  "host": "${domain}",
  "path": "${camouflage}",
  "tls": "tls"
}
EOF
}

vmess_qr_config_h2(){
    cat > $v2ray_qr_config_file <<-EOF
{
  "v": "2",
  "ps": "wulabing_${domain}",
  "add": "${domain}",
  "port": "${port}",
  "id": "${UUID}",
  "aid": "${alterID}",
  "net": "h2",
  "type": "none",
  "path": "${camouflage}",
  "tls": "tls"
}
EOF
}

vmess_qr_link_image(){
    vmess_link="vmess://$(cat $v2ray_qr_config_file | base64 -w 0)"
    echo -e "${Red} QR code: ${Font}" >> ${v2ray_info_file}
    echo -n "${vmess_link}"| qrencode -o - -t utf8 >> ${v2ray_info_file}
    echo -e "${Red} URL import link: ${vmess_link} ${Font}" >> ${v2ray_info_file}
}

info_extraction(){
    grep $1 $v2ray_qr_config_file | awk -F '"' '{print $4}'
}
basic_information(){
    echo -e "${OK} ${Green} V2ray + ws + tls installed successfully" > ${v2ray_info_file}
    echo -e "${Red} V2ray configuration information ${Font}" >> ${v2ray_info_file}
    echo -e "${Red} Address（address）:${Font} $(info_extraction '\"add\"') " >> ${v2ray_info_file}
    echo -e "${Red} Port（port）：${Font} $(info_extraction '\"port\"') " >> ${v2ray_info_file}
    echo -e "${Red} UUID（UUID）：${Font} $(info_extraction '\"id\"')" >> ${v2ray_info_file}
    echo -e "${Red} AlterID（alterId）：${Font} $(info_extraction '\"aid\"')" >> ${v2ray_info_file}
    echo -e "${Red} encryption method (security):（security）：${Font} adaotive " >> ${v2ray_info_file}
    echo -e "${Red} transmission protocol（network）：${Font} $(info_extraction '\"net\"') " >> ${v2ray_info_file}
    echo -e "${Red} camouflage type（type）：${Font} none " >> ${v2ray_info_file}
    echo -e "${Red} path (don't drop /): ${Font} $(info_extraction '\"path\"') " >> ${v2ray_info_file}
    echo -e "${Red} underlying transmission security:${Font} tls " >> ${v2ray_info_file}
}
show_information(){
    cat ${v2ray_info_file}
}
ssl_judge_and_install(){
    if [[ -f "/data/v2ray.key" || -f "/data/v2ray.crt" ]];then
        echo "Certificate file already exists in / data directory"
        echo -e "${OK} ${GreenBG} delete [Y / N]? ${Font}"
        read -r ssl_delete
        case $ssl_delete in
            [yY][eE][sS]|[yY])
                rm -rf /data/*
                echo -e "${OK} ${GreenBG} has been deleted ${Font}"
                ;;
            *)
                ;;
        esac
    fi

    if [[ -f "/data/v2ray.key" || -f "/data/v2ray.crt" ]];then
        echo "Certificate file already exists"
    elif [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]];then
        echo "Certificate file already exists"
        $HOME/.acme.sh/acme.sh --installcert -d ${domain} --fullchainpath /data/v2ray.crt --keypath /data/v2ray.key --ecc
        judge "Certificate Application"
    else
        ssl_install
        acme
    fi
}

nginx_systemd(){
    cat>$nginx_systemd_file<<EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/etc/nginx/logs/nginx.pid
ExecStartPre=/etc/nginx/sbin/nginx -t
ExecStart=/etc/nginx/sbin/nginx -c ${nginx_dir}/conf/nginx.conf
ExecReload=/etc/nginx/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

judge "Nginx systemd ServerFile added"
systemctl daemon-reload
}

tls_type(){
    if [[ -f "/etc/nginx/sbin/nginx" ]] && [[ -f "$nginx_conf" ]] && [[ "$shell_mode" == "ws" ]];then
        echo "Please select a supported TLS version (default: 3):"
        echo "Please note that if you use Quantaumlt X / router / old Shadowrocket / V2ray core lower than 4.18.1 please select compatibility mode"
        echo "1: TLS1.1 TLS1.2 and TLS1.3 (compatibility mode)"
        echo "2: 2: TLS1.2 and TLS1.3 (compatibility mode)"
        echo "3: TLS1.3 only"
        read -p  "Please enter:" tls_version
        [[ -z ${tls_version} ]] && tls_version=3
        if [[ $tls_version == 3 ]];then
            sed -i 's/ssl_protocols.*/ssl_protocols         TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} has switched to TLS1.3 only ${Font}"
        elif [[ $tls_version == 1 ]];then
            sed -i 's/ssl_protocols.*/ssl_protocols         TLSv1.1 TLSv1.2 TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} switched to TLS1.1 TLS1.2 and TLS1.3 ${Font}"
        else
            sed -i 's/ssl_protocols.*/ssl_protocols         TLSv1.2 TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} switched to TLS1.2 and TLS1.3 ${Font}"
        fi
        systemctl restart nginx
        judge "Nginx restart "
    else
        echo -e "${Error} ${RedBG} Nginx or configuration file does not exist or the currently installed version is h2, please execute ${Font} after installing the script correctly"
    fi
}
show_access_log(){
    [ -f ${v2ray_access_log} ] && tail -f ${v2ray_access_log} || echo -e "${RedBG} log file does not exist ${Font}"
}
show_error_log(){
    [ -f ${v2ray_error_log} ] && tail -f ${v2ray_error_log} || echo -e  "${RedBG} log file does not exist ${Font}"
}
ssl_update_manuel(){
    [ -f ${amce_sh_file} ] && "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" || echo -e  "${RedBG} certificate signing tool Does not exist, please confirm that you used your own certificate ${Font}"
    domain="$(info_extraction '\"add\"')"
    $HOME/.acme.sh/acme.sh --installcert -d ${domain} --fullchainpath /data/v2ray.crt --keypath /data/v2ray.key --ecc
}
bbr_boost_sh(){
    [ -f "tcp.sh" ] && rm -rf ./tcp.sh
    wget -N --no-check-certificate "https://github.com/ylx2016/Linux-NetSpeed/releases/download/sh/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
}
mtproxy_sh(){
    [ -f "mtproxy_go.sh" ] && rm -rf ./mtproxy_go.sh
    wget -N --no-check-certificate https://github.com/whunt1/onekeymakemtg/raw/master/mtproxy_go.sh && chmod +x mtproxy_go.sh && ./mtproxy_go.sh
}

uninstall_all(){
    stop_process_systemd
    [[ -f $nginx_systemd_file ]] && rm -f $nginx_systemd_file
    [[ -f $v2ray_systemd_file ]] && rm -f $v2ray_systemd_file
    [[ -d $v2ray_bin_file ]] && rm -rf $v2ray_bin_file
    if [[ -d $nginx_dir ]]
    then
        echo -e "${OK} ${Green} Uninstall Nginx [Y/N]? ${Font}"
        read -r uninstall_nginx
        case $uninstall_nginx in
            [yY][eE][sS]|[yY])
                rm -rf $nginx_dir
                echo -e "${OK} ${Green} Uninstalled Nginx ${Font}"
                ;;
            *)
                ;;
        esac
    fi
    [[ -d $v2ray_conf_dir ]] && rm -rf $v2ray_conf_dir
    [[ -d $web_dir ]] && rm -rf $web_dir
    systemctl daemon-reload
    echo -e "${OK} ${GreenBG} has been uninstalled, and the SSL certificate file has been retained ${Font}"
}
judge_mode(){
    if [ -f $v2ray_qr_config_file ]
    then
        if [[ -n $(grep "ws" $v2ray_qr_config_file) ]]
        then
            shell_mode="ws"
        elif [[ -n $(grep "h2" $v2ray_qr_config_file) ]]
        then
            shell_mode="h2"
        fi
    fi
}
install_v2ray_ws_tls(){
    is_root
    check_system
    chrony_install
    dependency_install
    basic_optimization
    domain_check
    old_config_exist_check
    port_alterid_set
    v2ray_install
    port_exist_check 80
    port_exist_check ${port}
    nginx_exist_check
    v2ray_conf_add_tls
    nginx_conf_add
    web_camouflage
    ssl_judge_and_install
    nginx_systemd
    vmess_qr_config_tls_ws
    basic_information
    vmess_qr_link_image
    tls_type
    show_information
    start_process_systemd
    enable_process_systemd
    acme_cron_update
}
install_v2_h2(){
    is_root
    check_system
    chrony_install
    dependency_install
    basic_optimization
    domain_check
    old_config_exist_check
    port_alterid_set
    v2ray_install
    port_exist_check 80
    port_exist_check ${port}
    v2ray_conf_add_h2
    ssl_judge_and_install
    vmess_qr_config_h2
    basic_information
    vmess_qr_link_image
    show_information
    start_process_systemd
    enable_process_systemd

}
update_sh(){
    ol_version=$(curl -L -s https://raw.githubusercontent.com/Chifth/V2Ray_ws-tls_bash_onekey/${github_branch}/install.sh | grep "shell_version=" | head -1 |awk -F '=|"' '{print $3}')
    echo "$ol_version" > $version_cmp
    echo "$shell_version" >> $version_cmp
    if [[ "$shell_version" < "$(sort -rV $version_cmp | head -1)" ]]
    then
        echo -e "${OK} ${Green} is it updated [Y/N]? ${Font}"
        read -r update_confirm
        case $update_confirm in
            [yY][eE][sS]|[yY])
                wget -N --no-check-certificate https://raw.githubusercontent.com/Chifth/V2Ray_ws-tls_bash_onekey/${github_branch}/install.sh
                echo -e "${OK} ${Green} update completed ${Font}"
                exit 0
                ;;
            *)
                ;;
        esac
    else
        echo -e "${OK} ${Green} The current version is the latest version ${Font}"
    fi

}
maintain(){
    echo -e "${RedBG} This option is temporarily unavailable for ${Font}"
    echo -e "${RedBG}$1${Font}"
    exit 0
}
list(){
    case $1 in
        tls_modify)
            tls_type
            ;;
        uninstall)
            uninstall_all
            ;;
        crontab_modify)
            acme_cron_update
            ;;
        boost)
            bbr_boost_sh
            ;;
        *)
            menu
            ;;
    esac
}

menu(){
    update_sh
    echo -e "\t V2ray installation management script ${Red}[${shell_version}]${Font}"
    echo -e "\t---authored by wulabing---"
    echo -e "\thttps://github.com/wulabing\n"
    echo -e "Currently installed version: ${shell_mode}\n"

    echo -e "—————————————— Installation Wizard ——————————————"
    echo -e "${Green}0.${Font}  upgrade script"
    echo -e "${Green}1.${Font}  Install V2Ray (Nginx + ws + tls)"
    echo -e "${Green}2.${Font}  Install  V2Ray (http/2)"
    echo -e "${Green}3.${Font}  upgrade V2Ray core"
    echo -e "—————————————— Configuration change ——————————————"
    echo -e "${Green}4.${Font}  change  UUID"
    echo -e "${Green}5.${Font}  change  alterid"
    echo -e "${Green}6.${Font}  change  port"
    echo -e "${Green}7.${Font}  change  TLS version (only ws + tls is valid)"
    echo -e "—————————————— View information ——————————————"
    echo -e "${Green}8.${Font}  View the real-time access log"
    echo -e "${Green}9.${Font}  View the real-time error log"
    echo -e "${Green}10.${Font} View V2Ray configuration information"
    echo -e "—————————————— Other options ——————————————"
    echo -e "${Green}11.${Font} install 4 in 1 bbr sharp install script"
    echo -e "${Green}12.${Font} install MTproxy (supports TLS obfuscation)"
    echo -e "${Green}13.${Font} Certificate Validity Update"
    echo -e "${Green}14.${Font} uninstall  V2Ray"
    echo -e "${Green}15.${Font} update certificate crontab schedule task"
    echo -e "${Green}16.${Font} exit \n"

    read -p "Please enter a number: " menu_num
    case $menu_num in
        0)
          update_sh
          ;;
        1)
          shell_mode="ws"
          install_v2ray_ws_tls
          ;;
        2)
          shell_mode="h2"
          install_v2_h2
          ;;
        3)
          bash <(curl -L -s https://install.direct/go.sh)
          ;;
        4)
          read -p "Please enter UUID:" UUID
          modify_UUID
          start_process_systemd
          ;;
        5)
          read -p "Please enter alterID:" alterID
          modify_alterid
          start_process_systemd
          ;;
        6)
          read -p "Please enter the connection port:" port
          if [[ -n $(grep "ws" $v2ray_qr_config_file) ]]
          then
              modify_nginx_port
          elif [[ -n $(grep "h2" $v2ray_qr_config_file) ]]
          then
              modify_inbound_port
          fi
          start_process_systemd
          ;;
        7)
          tls_type
          ;;
        8)
          show_access_log
          ;;
        9)
          show_error_log
          ;;
        10)
          basic_information
          vmess_qr_link_image
          show_information
          ;;
        11)
          bbr_boost_sh
          ;;
        12)
          mtproxy_sh
          ;;
        13)
          stop_process_systemd
          ssl_update_manuel
          start_process_systemd
          ;;
        14)
          uninstall_all
          ;;
        15)
          acme_cron_update
          ;;
        16)
          exit 0
          ;;
        *)
          echo -e "${RedBG} Please enter the correct number ${Font}"
          ;;
    esac
}

judge_mode
list $1

