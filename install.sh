#!/bin/bash

#fonts color
yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}
green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}
red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}
working_dir=$(dirname $(readlink -f $0))


if [[ -f /etc/redhat-release ]]; then
    release="centos"
    systemPackage="yum"
    systempwd="/usr/lib/systemd/system/"
elif cat /etc/issue | grep -Eqi "debian"; then
    release="debian"
    systemPackage="apt-get"
    systempwd="/lib/systemd/system/"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    release="ubuntu"
    systemPackage="apt-get"
    systempwd="/lib/systemd/system/"
elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
    systemPackage="yum"
    systempwd="/usr/lib/systemd/system/"
elif cat /proc/version | grep -Eqi "debian"; then
    release="debian"
    systemPackage="apt-get"
    systempwd="/lib/systemd/system/"
elif cat /proc/version | grep -Eqi "ubuntu"; then
    release="ubuntu"
    systemPackage="apt-get"
    systempwd="/lib/systemd/system/"
elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
    release="centos"
    systemPackage="yum"
    systempwd="/usr/lib/systemd/system/"
fi

function install_ostrich(){

if [ "$release" == "centos" ]; then
    if  [ -n "$(grep ' 6\.' /etc/redhat-release)" ] ;then
    red "==============="
    red "当前系统不受支持"
    red "==============="
    exit
    fi
    if  [ -n "$(grep ' 5\.' /etc/redhat-release)" ] ;then
    red "==============="
    red "当前系统不受支持"
    red "==============="
    exit
    fi
    systemctl stop firewalld
    systemctl disable firewalld
    rpm -Uvh http://nginx.org/packages/centos/7/noarch/RPMS/nginx-release-centos-7-0.el7.ngx.noarch.rpm
elif [ "$release" == "ubuntu" ]; then
    if  [ -n "$(grep ' 14\.' /etc/os-release)" ] ;then
    red "==============="
    red "当前系统不受支持"
    red "==============="
    exit
    fi
    if  [ -n "$(grep ' 12\.' /etc/os-release)" ] ;then
    red "==============="
    red "当前系统不受支持"
    red "==============="
    exit
    fi
    systemctl stop ufw
    systemctl disable ufw
    apt-get update
    apt dist-upgrade
elif [ "$release" == "debian" ]; then
#    systemctl stop ufw
#    systemctl disable ufw
cat > /etc/apt/sources.list <<-EOF
    deb http://deb.debian.org/debian bullseye main contrib non-free
    deb-src http://deb.debian.org/debian bullseye main contrib non-free

    deb http://deb.debian.org/debian-security/ bullseye-security main contrib non-free
    deb-src http://deb.debian.org/debian-security/ bullseye-security main contrib non-free

    deb http://deb.debian.org/debian bullseye-updates main contrib non-free
    deb-src http://deb.debian.org/debian bullseye-updates main contrib non-free

EOF
    ufw disable
    apt-get update
    apt dist-upgrade
    #tool for killall to restart service
    apt install psmisc
fi
$systemPackage -y install  wget unzip zip curl tar git make libssl-dev build-essential pkg-config >/dev/null 2>&1

green "======================="
yellow "请输入绑定到本VPS的域名"
green "======================="
read your_domain
real_addr=`ping ${your_domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
local_addr=`curl ipv4.icanhazip.com`
if [ $real_addr == $local_addr ] ; then
	green "=========================================="
	green "       域名解析正常，开始安装ostrich"
	green "=========================================="
	sleep 1s

    #设置伪装站

    ostrich_passwd=$(cat /dev/urandom | head -1 | md5sum | head -c 8)
    mkdir -p /etc/ostrich/conf /etc/ostrich/certs/tmp /etc/ostrich/db
cat > /etc/ostrich/conf/ostrich.json <<-EOF
{
    "run_type": "server",
    "local_addr": "$your_domain",
    "local_ip": "$local_addr",
    "local_port": 443,
    "remote_addr": "$your_domain",
    "remote_port": 9443,
    "password": [
        "$ostrich_passwd"
    ],
    "log_level": 1,
    "ssl": {
      "cert": "/etc/ostrich/certs/fullchain.cer",
      "key": "/etc/ostrich/certs/private.key",
      "key_password": "",
      "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384",
      "cipher_tls13": "TLS13_AES_128_GCM_SHA256:TLS13_CHACHA20_POLY1305_SHA256:TLS13_AES_256_GCM_SHA384",
      "prefer_server_cipher": true,
      "alpn": [
        "http/1.1"
      ],
      "alpn_port_override": {
        "h2": 81
      },
      "reuse_session": true,
      "session_ticket": false,
      "session_timeout": 600,
      "plain_http_response": "",
      "curves": "",
      "dhparam": ""
    },
    "tcp": {
      "prefer_ipv4": false,
      "no_delay": true,
      "keep_alive": true,
      "reuse_port": false,
      "fast_open": false,
      "fast_open_qlen": 20
    },
    "mysql": {
        "enabled": false,
        "server_addr": "/etc/ostrich/db/",
        "server_port": 3306,
        "database": "trojan",
        "username": "trojan",
        "password": "",
        "key": "",
        "cert": "",
        "ca": ""
    }
}
EOF
    acmed_host=$(cat /dev/urandom | head -1 | md5sum | head -c 8)
    acmed_user=$(cat /dev/urandom | head -1 | md5sum | head -c 8)
cat > /etc/ostrich/conf/acmed.json <<-EOF
{
   "certs": [
      {
         "name": "$your_domain",
         "dns_names": ["$your_domain"]
      }
   ],
   "acme": {
      "acme_url": "https://acme-v02.api.letsencrypt.org/directory",
      "acme_email": "$acmed_user@$acmed_host.com",
      "renew_if_days_left": 1
   },
   "system": {
      "chall_dir": "/etc/ostrich/certs/tmp",
      "data_dir": "/etc/ostrich/certs/tmp"
   }
}
EOF
#	#增加启动脚本
#cat > ${systempwd}ostrich_service.service <<-EOF
#[Unit]
#Description=ostrich service
#After=network.target
#
#[Service]
#Type=simple
#PIDFile=/etc/ostrich/ostrich_service.pid
#ExecStart=/usr/bin/ostrich_service -c "/etc/ostrich/conf/ostrich.json"
#ExecReload=
#ExecStop=
#PrivateTmp=true
#
#[Install]
#WantedBy=multi-user.target
#EOF

	#增加启动脚本
cat > ${systempwd}ostrich_node.service <<-EOF
[Unit]
Description=ostrich node
After=network.target

[Service]
Type=simple
PIDFile=/etc/ostrich/ostrich_node.pid
ExecStart=/usr/bin/ostrich_node -c "/etc/ostrich/conf/ostrich.json"
TimeoutStartSec=3
TimeoutStopSec=5
Restart=on-failure
KillSignal=SIGINT
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

#    chmod +x ${systempwd}ostrich_service.service
    chmod +x ${systempwd}ostrich_node.service
  #	systemctl start trojan.service
#    systemctl enable ostrich_service.service
    systemctl enable ostrich_node.service
    cp ${working_dir}/ostrich/ostrich_node  /usr/bin
#    cp ${working_dir}/ostrich/ostrich_service  /usr/bin
    cp ${working_dir}/ostrich/ostrich_cli  /usr/bin
    chmod +x /usr/bin/ostrich_node
#    chmod +x /usr/bin/ostrich_service
    chmod +x /usr/bin/ostrich_cli
#    systemctl start ostrich_service.service
    green "======================================================================"
    green                             "Ostrich已安装完成"
    green "======================================================================"
else
	red "================================"
	red "域名解析地址与本VPS IP地址不一致"
	red "本次安装失败，请确保域名解析正常"
	red "================================"
fi
}

function remove_ostrich(){
    red "================================"
    red          "即将卸载Ostrich"
    red "================================"
    systemctl stop ostrich_node
#    systemctl stop ostrich_service
    systemctl disable ostrich_node
#    systemctl disable ostrich_service
    rm -f ${systempwd}trojan.service
    if [ "$release" == "centos" ]; then
        yum remove -y nginx
    else
        apt autoremove -y nginx
    fi
    rm -rf /etc/ostrich/*
    rm /usr/bin/ostrich*
    green "=============="
    green "Ostrich删除完毕"
    green "=============="
}

start_menu(){
    clear
    green "===================================="
    green "        Ostrich 一键安装自动脚本"
    green "===================================="
    echo
    red   "===================================="
    yellow "         0. 一键安装 Ostrich"
    red   "===================================="
    yellow "         1. 一键卸载 Ostrich"
    red   "===================================="
    yellow "         2. 退出脚本"
    red   "===================================="
    echo
    read -p "请输入数字:" num
    case "$num" in
    0)
    install_ostrich
    ;;
    1)
    remove_ostrich
    ;;
    2)
    exit 1
    ;;
    *)
    clear
    red "请输入正确数字"
    sleep 1s
    start_menu
    ;;
    esac
}

start_menu