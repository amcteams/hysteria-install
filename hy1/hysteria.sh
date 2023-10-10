#!/bin/bash

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN='\033[0m'

red() {
    echo -e "\033[31m\033[01m$1\033[0m"
}

green() {
    echo -e "\033[32m\033[01m$1\033[0m"
}

yellow() {
    echo -e "\033[33m\033[01m$1\033[0m"
}

REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'" "fedora" "alpine")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS" "Fedora" "Alpine")
PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update" "yum -y update" "apk update -f")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "yum -y install" "apk add -f")
PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "yum -y autoremove" "yum -y autoremove" "apk del -f")

[[ $EUID -ne 0 ]] && red "注意：请在root用户下运行脚本" && exit 1

CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

for i in "${CMD[@]}"; do
    SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
    if [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]]; then
        SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
    fi
done

[[ -z $SYSTEM ]] && red "不支持当前VPS系统, 请使用主流的操作系统" && exit 1

realip(){
    ip=$(curl -s4m8 ip.sb -k) || ip=$(curl -s6m8 ip.sb -k)
}

inst_cert(){
    green "Hysteria 协议证书申请方式如下："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 必应自签证书 ${YELLOW}（默认）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} Acme 脚本自动申请"
    echo -e " ${GREEN}3.${PLAIN} 自定义证书路径"
    echo ""
    read -rp "请输入选项 [1-3]: " certInput
    if [[ $certInput == 2 ]]; then
        cert_path="/root/cert.crt"
        key_path="/root/private.key"
        if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]] && [[ -f /root/ca.log ]]; then
            domain=$(cat /root/ca.log)
            green "检测到原有域名：$domain 的证书，正在应用"
            hy_ym=$domain
        else
            WARPv4Status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            WARPv6Status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then
                wg-quick down wgcf >/dev/null 2>&1
                systemctl stop warp-go >/dev/null 2>&1
                realip
                wg-quick up wgcf >/dev/null 2>&1
                systemctl start warp-go >/dev/null 2>&1
            else
                realip
            fi
            
            read -p "请输入需要申请证书的域名：" domain
            [[ -z $domain ]] && red "未输入域名，无法执行操作！" && exit 1
            green "已输入的域名：$domain" && sleep 1
            domainIP=$(curl -sm8 ipget.net/?ip="${domain}")
            if [[ $domainIP == $ip ]]; then
                ${PACKAGE_INSTALL[int]} curl wget sudo socat openssl
                if [[ $SYSTEM == "CentOS" ]]; then
                    ${PACKAGE_INSTALL[int]} cronie
                    systemctl start crond
                    systemctl enable crond
                else
                    ${PACKAGE_INSTALL[int]} cron
                    systemctl start cron
                    systemctl enable cron
                fi
                curl https://get.acme.sh | sh -s email=$(date +%s%N | md5sum | cut -c 1-16)@gmail.com
                source ~/.bashrc
                bash ~/.acme.sh/acme.sh --upgrade --auto-upgrade
                bash ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
                if [[ -n $(echo $ip | grep ":") ]]; then
                    bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --listen-v6 --insecure
                else
                    bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --insecure
                fi
                bash ~/.acme.sh/acme.sh --install-cert -d ${domain} --key-file /root/private.key --fullchain-file /root/cert.crt --ecc
                if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]]; then
                    echo $domain > /root/ca.log
                    sed -i '/--cron/d' /etc/crontab >/dev/null 2>&1
                    echo "0 0 * * * root bash /root/.acme.sh/acme.sh --cron -f >/dev/null 2>&1" >> /etc/crontab
                    green "证书申请成功! 脚本申请到的证书 (cert.crt) 和私钥 (private.key) 文件已保存到 /root 文件夹下"
                    yellow "证书crt文件路径如下: /root/cert.crt"
                    yellow "私钥key文件路径如下: /root/private.key"
                    hy_ym=$domain
                fi
            else
                red "当前域名解析的IP与当前VPS使用的真实IP不匹配"
                green "建议如下："
                yellow "1. 请确保CloudFlare小云朵为关闭状态(仅限DNS), 其他域名解析或CDN网站设置同理"
                yellow "2. 请检查DNS解析设置的IP是否为VPS的真实IP"
                yellow "3. 脚本可能跟不上时代, 建议截图发布到GitHub Issues、GitLab Issues、论坛或TG群询问"
                exit 1
            fi
        fi
    elif [[ $certInput == 3 ]]; then
        read -p "请输入公钥文件 crt 的路径：" certpath
        yellow "公钥文件 crt 的路径：$certpath "
        read -p "请输入密钥文件 key 的路径：" keypath
        yellow "密钥文件 key 的路径：$keypath "
        read -p "请输入证书的域名：" domain
        yellow "证书域名：$domain"
        hy_ym=$domain
    else
        green "将使用必应自签证书作为 Hysteria 的节点证书"

        cert_path="/etc/hysteria/cert.crt"
        key_path="/etc/hysteria/private.key"
        openssl ecparam -genkey -name prime256v1 -out /etc/hysteria/private.key
        openssl req -new -x509 -days 36500 -key /etc/hysteria/private.key -out /etc/hysteria/cert.crt -subj "/CN=www.bing.com"
        chmod 777 /etc/hysteria/cert.crt
        chmod 777 /etc/hysteria/private.key
        hy_ym="www.bing.com"
        domain="www.bing.com"
    fi
}

inst_pro(){
    green "Hysteria 节点协议如下："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} UDP ${YELLOW}（默认）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} wechat-video"
    echo -e " ${GREEN}3.${PLAIN} faketcp"
    echo ""
    read -rp "请输入选项 [1-3]: " proInput
    if [[ $proInput == 2 ]]; then
        protocol="wehcat-video"
    elif [[ $proInput == 3 ]]; then
        protocol="faketcp"
    else
        protocol="udp"
    fi
    yellow "将使用 $protocol 作为 Hysteria 的节点协议"
}

inst_port(){
    iptables -t nat -F PREROUTING >/dev/null 2>&1

    read -p "设置 Hysteria 端口[1-65535]（回车则随机分配端口）：" port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} $port ${PLAIN} 端口已经被其他程序占用，请更换端口重试！"
            read -p "设置 Hysteria 端口[1-65535]（回车则随机分配端口）：" port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        fi
    done

    yellow "将在 Hysteria 节点使用的端口是：$port"

    if [[ $protocol == "udp" ]]; then
        inst_jump
    fi
}

inst_jump(){
    yellow "你当前选择的协议是 udp，可支持端口跳跃功能"
    green "Hysteria 端口使用模式如下："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 单端口 ${YELLOW}（默认）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} 端口跳跃"
    echo ""
    read -rp "请输入选项 [1-2]: " jumpInput
    if [[ $jumpInput == 2 ]]; then
        read -p "设置范围端口的起始端口 (建议10000-65535之间)：" firstport
        read -p "设置一个范围端口的末尾端口 (建议10000-65535之间，一定要比上面起始端口大)：" endport
        if [[ $firstport -ge $endport ]]; then
            until [[ $firstport -le $endport ]]; do
                if [[ $firstport -ge $endport ]]; then
                    red "你设置的起始端口小于末尾端口，请重新输入起始和末尾端口"
                    read -p "设置范围端口的起始端口 (建议10000-65535之间)：" firstport
                    read -p "设置一个范围端口的末尾端口 (建议10000-65535之间，一定要比上面起始端口大)：" endport
                fi
            done
        fi
        iptables -t nat -A PREROUTING -p udp --dport $firstport:$endport  -j DNAT --to-destination :$port
        ip6tables -t nat -A PREROUTING -p udp --dport $firstport:$endport  -j DNAT --to-destination :$port
        netfilter-persistent save >/dev/null 2>&1
    else
        red "将继续使用单端口模式"
    fi
}

inst_pwd(){
    read -p "设置 Hysteria 密码（回车跳过为随机字符）：" auth_pwd
    [[ -z $auth_pwd ]] && auth_pwd=$(date +%s%N | md5sum | cut -c 1-8)
    yellow "使用在 Hysteria 节点的密码为：$auth_pwd"
}

inst_resolv(){
    green "Hysteria 域名解析模式如下："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} IPv4 优先 ${YELLOW}（默认）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} IPv6 优先"
    echo ""
    read -rp "请输入选项 [1-2]: " resolvInput
    if [[ $resolvInput == 2 ]]; then
        yellow "Hysteria 域名解析模式已设置成 IPv6 优先"
        resolv=64
    else
        yellow "Hysteria 域名解析模式已设置成 IPv4 优先"
        resolv=46
    fi
}

inst_hy(){
    if [[ ! $SYSTEM == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl wget sudo qrencode procps iptables-persistent netfilter-persistent

    wget -N https://raw.githubusercontent.com/Misaka-blog/hysteria-install/main/hy1/install_server.sh
    bash install_server.sh
    rm -f install_server.sh

    if [[ -f "/usr/local/bin/hysteria" ]]; then
        green "Hysteria 安装成功！"
    else
        red "Hysteria 安装失败！"
    fi

    # 询问用户 Hysteria 配置
    inst_cert
    inst_pro
    inst_port
    inst_pwd
    inst_resolv

    # 设置 Hysteria 配置文件
    cat <<EOF > /etc/hysteria/config.json
{
    "protocol": "$protocol",
    "listen": ":$port",
    "resolve_preference": "$resolv",
    "cert": "$cert_path",
    "key": "$key_path",
    "alpn": "h3",
    "auth": {
        "mode": "password",
        "config": {
            "password": "$auth_pwd"
        }
    }
}
EOF

    # 确定最终入站端口范围
    if [[ -n $firstport ]]; then
        last_port="$port,$firstport-$endport"
    else
        last_port=$port
    fi

    # 给 IPv6 地址加中括号
    if [[ -n $(echo $ip | grep ":") ]]; then
        last_ip="[$ip]"
    else
        last_ip=$ip
    fi

    # 判断证书是否为必应自签，如是则使用 IP 作为节点入站
    if [[ $hy_ym == "www.bing.com" ]]; then
        WARPv4Status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
        WARPv6Status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
        if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then
            wg-quick down wgcf >/dev/null 2>&1
            systemctl stop warp-go >/dev/null 2>&1
            hy_ym=$last_ip
            wg-quick up wgcf >/dev/null 2>&1
            systemctl start warp-go >/dev/null 2>&1
        else
            hy_ym=$last_ip
        fi
    fi

    # 设置 V2rayN 及 Clash Meta 配置文件
    mkdir /root/hy >/dev/null 2>&1
    cat <<EOF > /root/hy/hy-client.json
{
    "protocol": "$protocol",
    "server": "$hy_ym:$last_port",
    "server_name": "$domain",
    "alpn": "h3",
    "up_mbps": 20,
    "down_mbps": 100,
    "auth_str": "$auth_pwd",
    "insecure": true,
    "retry": 3,
    "retry_interval": 3,
    "fast_open": true,
    "lazy_start": true,
    "hop_interval": 60,
    "socks5": {
        "listen": "127.0.0.1:5080"
    }
}
EOF

    cat <<EOF > /root/hy/clash-meta.yaml
mixed-port: 7890
external-controller: 127.0.0.1:9090
allow-lan: false
mode: rule
log-level: debug
ipv6: true
dns:
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  nameserver:
    - 8.8.8.8
    - 1.1.1.1
    - 114.114.114.114
proxies:
  - name: Misaka-Hysteria
    type: hysteria
    server: $hy_ym
    port: $port
    auth_str: $auth_pwd
    alpn:
      - h3
    protocol: $protocol
    up: 20
    down: 100
    sni: $domain
    skip-cert-verify: true
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - Misaka-Hysteria
      
rules:
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
EOF
    url="hysteria://$hy_ym:$port?protocol=$protocol&auth=$auth_pwd&peer=$domain&insecure=$true&upmbps=20&downmbps=100&alpn=h3#Misaka-Hysteria"
    echo $url > /root/hy/url.txt

    systemctl daemon-reload
    systemctl enable hysteria-server
    systemctl start hysteria-server

    if [[ -n $(systemctl status hysteria-server 2>/dev/null | grep -w active) && -f '/etc/hysteria/config.json' ]]; then
        green "Hysteria 服务启动成功"
    else
        red "Hysteria-server 服务启动失败，请运行 systemctl status hysteria-server 查看服务状态并反馈，脚本退出" && exit 1
    fi

    green "Hysteria 代理服务安装完成"
    yellow "客户端配置文件 hy-client.json 内容如下，并保存到 /root/hy/hy-client.json"
    cat /root/hy/hy-client.json
    yellow "Clash Meta 客户端配置文件已保存到 /root/hy/clash-meta.yaml"
    yellow "Hysteria 节点分享链接如下，并保存到 /root/hy/url.txt"
    red $(cat /root/hy/url.txt)
}

uninst_hy(){
    systemctl stop hysteria-server.service >/dev/null 2>&1
    systemctl disable hysteria-server.service >/dev/null 2>&1
    rm -f /lib/systemd/system/hysteria-server.service /lib/systemd/system/hysteria-server@.service
    rm -rf /usr/local/bin/hysteria /etc/hysteria /root/hy /root/hysteria.sh
    iptables -t nat -F PREROUTING >/dev/null 2>&1
    netfilter-persistent save >/dev/null 2>&1
    green "Hysteria 已彻底卸载完成！"
}

starthy(){
    systemctl start hysteria-server
    systemctl enable hysteria-server >/dev/null 2>&1
}

stophy(){
    systemctl stop hysteria-server
    systemctl disable hysteria-server >/dev/null 2>&1
}

hyswitch(){
    yellow "请选择你需要的操作："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 启动 Hysteria"
    echo -e " ${GREEN}2.${PLAIN} 关闭 Hysteria"
    echo -e " ${GREEN}3.${PLAIN} 重启 Hysteria"
    echo ""
    read -rp "请输入选项 [0-3]: " switchInput
    case $switchInput in
        1 ) starthy ;;
        2 ) stophy ;;
        3 ) stophy && starthy ;;
        * ) exit 1 ;;
    esac
}

change_cert(){
    old_cert=$(cat /etc/hysteria/config.json | grep cert | awk -F " " '{print $2}' | sed "s/\"//g" | sed "s/,//g")
    old_key=$(cat /etc/hysteria/config.json | grep key | awk -F " " '{print $2}' | sed "s/\"//g" | sed "s/,//g")
    old_hyym=$(cat /root/hy/hy-client.json | grep server | awk -F " " '{print $2}' | sed "s/\"//g" | sed "s/,//g" | awk -F ":" '{print $1}')
    old_domain=$(cat /root/hy/hy-client.json | grep server_name | awk -F " " '{print $2}' | sed "s/\"//g" | sed "s/,//g")
    inst_cert
    if [[ $hy_ym == "www.bing.com" ]]; then
        WARPv4Status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
        WARPv6Status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
        if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then
            wg-quick down wgcf >/dev/null 2>&1
            systemctl stop warp-go >/dev/null 2>&1
            hy_ym=$(curl -s4m8 ip.sb -k) || hy_ym="[$(curl -s6m8 ip.sb -k)]"
            wg-quick up wgcf >/dev/null 2>&1
            systemctl start warp-go >/dev/null 2>&1
        else
            hy_ym=$(curl -s4m8 ip.sb -k) || hy_ym="[$(curl -s6m8 ip.sb -k)]"
        fi
    fi
    sed -i "s!$old_cert!$cert_path!g" /etc/hysteria/config.json
    sed -i "s!$old_key!$key_path!g" /etc/hysteria/config.json
    sed -i "s/$old_hyym/$hy_ym/g" /root/hy/hy-client.json
    sed -i "s/$old_hyym/$hy_ym/g" /root/hy/clash-meta.yaml
    sed -i "s/$old_hyym/$hy_ym/g" /root/hy/url.txt
    stophy && starthy
    green "修改配置成功，请重新导入节点配置文件"
}

change_pro(){
    old_pro=$(cat /etc/hysteria/config.json | grep protocol | awk -F " " '{print $2}' | sed "s/\"//g" | sed "s/,//g")
    inst_pro
    sed -i "s/$old_pro/$protocol" /etc/hysteria/config.json
    sed -i "s/$old_pro/$protocol" /root/hy/hy-client.json
    sed -i "s/$old_pro/$protocol" /root/hy/clash-meta.yaml
    sed -i "s/$old_pro/$protocol" /root/hy/url.txt
    stophy && starthy
    green "修改配置成功，请重新导入节点配置文件"
}

change_port(){
    old_port=$(cat /etc/hysteria/config.json | grep listen | awk -F " " '{print $2}' | sed "s/\"//g" | sed "s/,//g" | sed "s/://g")
    inst_port

    iptables -t nat -F PREROUTING >/dev/null 2>&1
    netfilter-persistent save >/dev/null 2>&1

    if [[ -n $firstport ]]; then
        last_port="$port,$firstport-$endport"
    else
        last_port=$port
    fi

    sed -i "s/$old_port/$port" /etc/hysteria/config.json
    sed -i "s/$old_port/$last_port" /root/hy/hy-client.json
    sed -i "s/$old_port/$last_port" /root/hy/clash-meta.yaml
    sed -i "s/$old_port/$last_port" /root/hy/url.txt

    stophy && starthy
    green "修改配置成功，请重新导入节点配置文件"
}

change_pwd(){
    old_pwd=$(cat /etc/hysteria/config.json | grep password | sed -n 2p | awk -F " " '{print $2}' | sed "s/\"//g" | sed "s/,//g")
    inst_pwd
    sed -i "s/$old_pwd/$auth_pwd" /etc/hysteria/config.json
    sed -i "s/$old_pwd/$auth_pwd" /root/hy/hy-client.json
    sed -i "s/$old_pwd/$auth_pwd" /root/hy/clash-meta.yaml
    sed -i "s/$old_pwd/$auth_pwd" /root/hy/url.txt
    stophy && starthy
    green "修改配置成功，请重新导入节点配置文件"
}

change_resolv(){
    old_resolv=$(cat /etc/hysteria/config.json | grep resolv | awk -F " " '{print $2}' | sed "s/\"//g" | sed "s/,//g")
    inst_resolv
    sed -i "s/$old_resolv/$resolv" /etc/hysteria/config.json
    stophy && starthy
    green "修改配置成功，请重新导入节点配置文件"
}

editconf(){
    green "Hysteria 配置变更选择如下:"
    echo -e " ${GREEN}1.${PLAIN} 修改证书类型"
    echo -e " ${GREEN}2.${PLAIN} 修改传输协议"
    echo -e " ${GREEN}3.${PLAIN} 修改连接端口"
    echo -e " ${GREEN}4.${PLAIN} 修改认证密码"
    echo -e " ${GREEN}5.${PLAIN} 修改域名解析优先级"
    echo ""
    read -p " 请选择操作 [1-5]：" confAnswer
    case $confAnswer in
        1 ) change_cert ;;
        2 ) change_pro ;;
        3 ) change_port ;;
        4 ) change_pwd ;;
        5 ) change_resolv ;;
        * ) exit 1 ;;
    esac
}

showconf(){
    yellow "客户端配置文件 hy-client.json 内容如下，并保存到 /root/hy/hy-client.json"
    cat /root/hy/hy-client.json
    yellow "Clash Meta 客户端配置文件已保存到 /root/hy/clash-meta.yaml"
    yellow "Hysteria 节点分享链接如下，并保存到 /root/hy/url.txt"
    red $(cat /root/hy/url.txt)
}

menu() {
    clear
    echo "#############################################################"
    echo -e "#                  ${RED}Hysteria 2 一键安装脚本${PLAIN}                #"
    echo -e "# ${GREEN}作者${PLAIN}: AMCTEAMS AMC跨境社区                            #"
    echo -e "# ${GREEN}博客${PLAIN}: https://www.tkstart.com                        #"
    echo -e "# ${GREEN}GitHub 项目${PLAIN}: https://github.com/amcteams             #"
    echo -e "# ${GREEN}GitLab 项目${PLAIN}: https://gitlab.com/amcteams             #"
    echo -e "# ${GREEN}Telegram 频道${PLAIN}: https://t.me/amcteams                 #"
    echo -e "# ${GREEN}Telegram 群组${PLAIN}: https://t.me/+OpogS1V6Q8dlOWVh        #"
    echo -e "# ${GREEN}YouTube 频道${PLAIN}: https://www.youtube.com/@amcteams      #"
    echo "#############################################################"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 安装 Hysteria"
    echo -e " ${GREEN}2.${PLAIN} ${RED}卸载 Hysteria${PLAIN}"
    echo " -------------"
    echo -e " ${GREEN}3.${PLAIN} 关闭、开启、重启 Hysteria"
    echo -e " ${GREEN}4.${PLAIN} 修改 Hysteria 配置"
    echo -e " ${GREEN}5.${PLAIN} 显示 Hysteria 配置文件"
    echo " -------------"
    echo -e " ${GREEN}0.${PLAIN} 退出脚本"
    echo ""
    read -rp "请输入选项 [0-5]: " menuInput
    case $menuInput in
        1 ) inst_hy ;;
        2 ) uninst_hy ;;
        3 ) hyswitch ;;
        4 ) editconf ;;
        5 ) showconf ;;
        * ) exit 1 ;;
    esac
}

menu
