#!/bin/bash

#====================================================
#	System Request:Debian 7+/Ubuntu 14.04+/Centos 6+
#	Author:	wulabing
#	Dscription: V2ray ws+tls onekey 
#	Version: 3.3.1
#	Blog: https://www.wulabing.com
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
Info="${Green}[信息]${Font}"
OK="${Green}[OK]${Font}"
Error="${Red}[错误]${Font}"

v2ray_conf_dir="/etc/v2ray"
v2ray_conf="${v2ray_conf_dir}/config.json"
client_conf="${v2ray_conf_dir}/client.json"

#生成伪装路径
camouflage=`cat /dev/urandom | head -n 10 | md5sum | head -c 8`

source /etc/os-release

#从VERSION中提取发行版系统的英文名称，为了在debian/ubuntu下添加相对应的Nginx apt源
VERSION=`echo ${VERSION} | awk -F "[()]" '{print $2}'`

check_system(){
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]];then
        echo -e "${OK} ${GreenBG} 当前系统为 Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum"
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]];then
        echo -e "${OK} ${GreenBG} 当前系统为 Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt"
        $INS update
        ## 添加 Nginx apt源
    elif [[ "${ID}" == "ubuntu" && `echo "${VERSION_ID}" | cut -d '.' -f1` -ge 16 ]];then
        echo -e "${OK} ${GreenBG} 当前系统为 Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS="apt"
        $INS update
    else
        echo -e "${Error} ${RedBG} 当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内，安装中断 ${Font}"
        exit 1
    fi

    $INS install dbus
    systemctl stop firewalld && systemctl disable firewalld
    echo -e "${OK} ${GreenBG} firewalld 已关闭 ${Font}"
}

is_root(){
    if [ `id -u` == 0 ]
        then echo -e "${OK} ${GreenBG} 当前用户是root用户，进入安装流程 ${Font} "
        sleep 3
    else
        echo -e "${Error} ${RedBG} 当前用户不是root用户，请切换到root用户后重新执行脚本 ${Font}" 
        exit 1
    fi
}
judge(){
    if [[ $? -eq 0 ]];then
        echo -e "${OK} ${GreenBG} $1 完成 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} $1 失败${Font}"
        exit 1
    fi
}

# 旧版本遗弃代码

#ntpdate_install(){
#    if [[ "${ID}" == "centos" ]];then
#        ${INS} install ntpdate -y
#    else
#        ${INS} update
#        ${INS} install ntpdate -y
#    fi
#    judge "安装 NTPdate 时间同步服务 "
#}
#time_modify(){
#
#    ntpdate_install
#
#    systemctl stop ntp &>/dev/null
#
#    echo -e "${Info} ${GreenBG} 正在进行时间同步 ${Font}"
#    ntpdate time.nist.gov
#
#    if [[ $? -eq 0 ]];then
#        echo -e "${OK} ${GreenBG} 时间同步成功 ${Font}"
#        echo -e "${OK} ${GreenBG} 当前系统时间 `date -R`（请注意时区间时间换算，换算后时间误差应为三分钟以内）${Font}"
#        sleep 1
#    else
#        echo -e "${Error} ${RedBG} 时间同步失败，请检查ntpdate服务是否正常工作 ${Font}"
#    fi
#}

chrony_install(){
    ${INS} -y install chrony
    judge "安装 chrony 时间同步服务 "

    timedatectl set-ntp true

    if [[ "${ID}" == "centos" ]];then
       systemctl enable chronyd && systemctl restart chronyd
    else
       systemctl enable chrony && systemctl restart chrony
    fi

    judge "chronyd 启动 "

    timedatectl set-timezone Asia/Shanghai

    echo -e "${OK} ${GreenBG} 等待时间同步 ${Font}"
    sleep 10

    chronyc sourcestats -v
    chronyc tracking -v
    date
    read -p "请确认时间是否准确,误差范围±3分钟(Y/N): " chrony_install
    [[ -z ${chrony_install} ]] && chrony_install="Y"
    case $chrony_install in
        [yY][eE][sS]|[yY])
            echo -e "${GreenBG} 继续安装 ${Font}"
            sleep 2
            ;;
        *)
            echo -e "${RedBG} 安装终止 ${Font}"
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
    judge "安装 crontab"

    if [[ "${ID}" == "centos" ]];then
       touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
       systemctl start crond && systemctl enable crond
    else
       touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
       systemctl start cron && systemctl enable cron

    fi
    judge "crontab 自启动配置 "



    ${INS} -y install bc
    judge "安装 bc"

    ${INS} -y install unzip
    judge "安装 unzip"

    ${INS} -y install qrencode
    judge "安装 qrencode"


}
port_alterid_set(){
    stty erase '^H' && read -p "请输入连接端口（default:443）:" port
    [[ -z ${port} ]] && port="443"
    stty erase '^H' && read -p "请输入alterID（default:2 仅允许填数字）:" alterID
    [[ -z ${alterID} ]] && alterID="2"
}

random_UUID(){
    let PORT=$RANDOM+10000
    UUID=$(cat /proc/sys/kernel/random/uuid)
}

modify_port_UUID(){
    sed -i "/\"port\": 443/c  \    \"port\": ${port}," ${1}
    sed -i "/\"id\"/c \\\t  \"id\":\"${UUID}\"," ${1}
    sed -i "/\"alterId\"/c \\\t  \"alterId\":${alterID}" ${1}
    sed -i "/\"path\"/c \\\t  \"path\":\"\/${camouflage}\/\"" ${1}
    sed -i "/\"address\"/c \\\t  \"address\":\"${domain}\"," ${1}
}
v2ray_install(){
    if [[ -d /root/v2ray ]];then
        rm -rf /root/v2ray
    fi

    mkdir -p /root/v2ray && cd /root/v2ray
    wget  --no-check-certificate https://install.direct/go.sh

    ## wget http://install.direct/go.sh
    
    if [[ -f go.sh ]];then
        bash go.sh --force
        judge "安装 V2ray"
    else
        echo -e "${Error} ${RedBG} V2ray 安装文件下载失败，请检查下载地址是否可用 ${Font}"
        exit 4
    fi
}
ssl_install(){
    if [[ "${ID}" == "centos" ]];then
        ${INS} install socat nc -y        
    else
        ${INS} install socat netcat -y
    fi
    judge "安装 SSL 证书生成脚本依赖"

    curl  https://get.acme.sh | sh
    judge "安装 SSL 证书生成脚本"

}
domain_check(){
    stty erase '^H' && read -p "请输入你的域名信息(eg:www.wulabing.com):" domain
    domain_ip=`ping ${domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
    echo -e "${OK} ${GreenBG} 正在获取 公网ip 信息，请耐心等待 ${Font}"
    local_ip=`curl -4 ip.sb`
    echo -e "域名dns解析IP：${domain_ip}"
    echo -e "本机IP: ${local_ip}"
    sleep 2
    if [[ $(echo ${local_ip}|tr '.' '+'|bc) -eq $(echo ${domain_ip}|tr '.' '+'|bc) ]];then
        echo -e "${OK} ${GreenBG} 域名dns解析IP 与 本机IP 匹配 ${Font}"
        sleep 2
    else
        echo -e "${Error} ${RedBG} 域名dns解析IP 与 本机IP 不匹配 是否继续安装？（y/n）${Font}" && read install
        case $install in
        [yY][eE][sS]|[yY])
            echo -e "${GreenBG} 继续安装 ${Font}" 
            sleep 2
            ;;
        *)
            echo -e "${RedBG} 安装终止 ${Font}" 
            exit 2
            ;;
        esac
    fi
}

port_exist_check(){
    if [[ 0 -eq `lsof -i:"$1" | wc -l` ]];then
        echo -e "${OK} ${GreenBG} $1 端口未被占用 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} 检测到 $1 端口被占用，以下为 $1 端口占用信息 ${Font}"
        lsof -i:"$1"
        echo -e "${OK} ${GreenBG} 5s 后将尝试自动 kill 占用进程 ${Font}"
        sleep 5
        lsof -i:"$1" | awk '{print $2}'| grep -v "PID" | xargs kill -9
        echo -e "${OK} ${GreenBG} kill 完成 ${Font}"
        sleep 1
    fi
}
acme(){
    ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --force
    if [[ $? -eq 0 ]];then
        echo -e "${OK} ${GreenBG} SSL 证书生成成功 ${Font}"
        sleep 2
        mkdir /data
        ~/.acme.sh/acme.sh --installcert -d ${domain} --fullchainpath /data/v2ray.crt --keypath /data/v2ray.key --ecc
        if [[ $? -eq 0 ]];then
        echo -e "${OK} ${GreenBG} 证书配置成功 ${Font}"
        sleep 2
        fi
    else
        echo -e "${Error} ${RedBG} SSL 证书生成失败 ${Font}"
        exit 1
    fi
}
start_process_systemd(){
    systemctl restart v2ray
    judge "V2ray 启动"

    systemctl enable v2ray
    judge "设置 v2ray 开机自启"
}

v2ray_conf_add(){
    rm -rf ${v2ray_conf}
    rm -rf ${client_conf}
    cd /etc/v2ray
    wget  https://raw.githubusercontent.com/wulabing/V2Ray_ws-tls_bash_onekey/master/http2/config.json
    judge "config.json 下载"
    wget  https://raw.githubusercontent.com/wulabing/V2Ray_ws-tls_bash_onekey/master/http2/client.json
    judge "client.json 下载"
    random_UUID
    modify_port_UUID ${v2ray_conf}
    judge "config.json 配置变更"
    modify_port_UUID ${client_conf}
    judge "client.json 配置变更"
    json_addr=`curl --upload-file ${client_conf} https://transfer.sh/wulabing_${camouflage}_${UUID}.json`
}

vmess_qr_config(){
    cat >/etc/v2ray/vmess_qr.json <<-EOF
{
  "v": "2",
  "ps": "wulabing_${domain}",
  "add": "${domain}",
  "port": "${port}",
  "id": "${UUID}",
  "aid": "${alterID}",
  "net": "h2",
  "type": "none",
  "path": "/${camouflage}/",
  "tls": "tls"
}
EOF

    vmess_link="vmess://$(cat /etc/v2ray/vmess_qr.json | base64 -w 0)"
    echo -e "${Red} URL导入链接:${vmess_link} ${Font}" >>./v2ray_info.txt
    echo -e "${Red} 二维码: ${Font}" >>./v2ray_info.txt
    echo -n "${vmess_link}"| qrencode -o - -t utf8 >>./v2ray_info.txt
}

show_information(){
    clear
    cd ~

    echo -e "${OK} ${Green} V2ray http2 over tls 安装成功 " >./v2ray_info.txt
    echo -e "${Red} V2ray 配置信息 ${Font}" >>./v2ray_info.txt
    echo -e "${Red} 地址（address）:${Font} ${domain} " >>./v2ray_info.txt
    echo -e "${Red} 端口（port）：${Font} ${port} " >>./v2ray_info.txt
    echo -e "${Red} 用户id（UUID）：${Font} ${UUID}" >>./v2ray_info.txt
    echo -e "${Red} 额外id（alterId）：${Font} ${alterID}" >>./v2ray_info.txt
    echo -e "${Red} 加密方式（security）：${Font} 自适应 " >>./v2ray_info.txt
    echo -e "${Red} 传输协议（network）：${Font} h2 " >>./v2ray_info.txt
    echo -e "${Red} 伪装类型（type）：${Font} none " >>./v2ray_info.txt
    echo -e "${Red} 伪装域名（不要落下/）：${Font} /${camouflage}/ " >>./v2ray_info.txt
    echo -e "${Red} 底层传输安全：${Font} tls " >>./v2ray_info.txt
    echo -e "${OK} ${GreenBG} 配置地址（方便下载）： ${json_addr} ${Font}" >>./v2ray_info.txt
    echo -e "${OK} ${GreenBG} 配置地址（服务器本地备份）：/etc/v2ray/client.json ${Font}" >>./v2ray_info.txt
    vmess_qr_config
    cat ./v2ray_info.txt

}



ssl_judge_and_install(){
    if [[ -f "/data/v2ray.key" && -f "/data/v2ray.crt" ]];then
        echo "证书文件已存在"
    elif [[ -f "~/.acme.sh/${domain}_ecc/${domain}.key" && -f "~/.acme.sh/${domain}_ecc/${domain}.cer" ]];then
        echo "证书文件已存在"
        ~/.acme.sh/acme.sh --installcert -d ${domain} --fullchainpath /data/v2ray.crt --keypath /data/v2ray.key --ecc
        judge "证书应用"
    else
        ssl_install
        acme
    fi
}

main(){
    is_root
    check_system
    chrony_install
    dependency_install
    domain_check
    port_alterid_set
    v2ray_install
    port_exist_check ${port}
    v2ray_conf_add
    
    #将证书生成放在最后，尽量避免多次尝试脚本从而造成的多次证书申请
    ssl_judge_and_install

    show_information
    start_process_systemd
}

main
