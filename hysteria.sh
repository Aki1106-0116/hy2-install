#!/bin/bash

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}

green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}

yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}

REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "amazon linux" "fedora")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS" "Fedora")
PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "yum -y install")

[[ $EUID -ne 0 ]] && red "注意: 请在root用户下运行脚本" && exit 1

CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

for i in "${CMD[@]}"; do
    SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
    [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
done

[[ -z $SYSTEM ]] && red "目前暂不支持你的VPS的操作系统！" && exit 1

if [[ -z $(type -P curl) ]]; then
    if [[ ! $SYSTEM == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl
fi

realip(){
    ip=$(curl -s4m8 ip.sb -k) || ip=$(curl -s6m8 ip.sb -k)
}

save_iptables_rules(){
    if [[ $SYSTEM == "CentOS" ]]; then
        if [[ -f /usr/libexec/iptables/iptables.init ]]; then
            service iptables save >/dev/null 2>&1
            service ip6tables save >/dev/null 2>&1
        else
            iptables-save > /etc/sysconfig/iptables 2>/dev/null
            ip6tables-save > /etc/sysconfig/ip6tables 2>/dev/null
        fi
    else
        netfilter-persistent save >/dev/null 2>&1
    fi
}

install_iptables_persistent(){
    if [[ $SYSTEM == "CentOS" ]]; then
        ${PACKAGE_INSTALL[int]} iptables-services
        systemctl enable iptables >/dev/null 2>&1
        systemctl enable ip6tables >/dev/null 2>&1
        systemctl start iptables >/dev/null 2>&1
        systemctl start ip6tables >/dev/null 2>&1
    else
        ${PACKAGE_INSTALL[int]} iptables-persistent netfilter-persistent
    fi
}

inst_cert(){
    # [关键修复] 统一将证书存放在 /etc/hysteria 目录下，解决 Permission denied 问题
    mkdir -p /etc/hysteria

    green "请选择 Hysteria 2 协议的证书申请方式："
    echo ""
    
    echo -e " ${GREEN}1.${PLAIN} 使用自签证书 (必应伪装) ${YELLOW}（默认）${PLAIN}"
    echo -e "    ${PLAIN}说明：${RED}不推荐！安全性较低，伪装效果差，流量易被识别阻断。${PLAIN}"
    echo -e "          仅建议完全没有域名，或仅想快速测试连接的用户选择。"
    echo ""
    
    echo -e " ${GREEN}2.${PLAIN} 使用 ACME 脚本自动申请证书 ${YELLOW}（推荐）${PLAIN}"
    echo -e "    ${PLAIN}说明：需要你拥有一个域名。脚本会自动申请并更新证书。"
    echo -e "          ${YELLOW}注意：请确保域名 DNS 已正确解析到本机 IP。${PLAIN}"
    echo -e "          ${YELLOW}若使用 Cloudflare，请务必关闭代理状态（即小云朵变灰）。${PLAIN}"
    echo ""
    
    echo -e " ${GREEN}3.${PLAIN} 使用本地已有的证书文件"
    echo -e "    ${PLAIN}说明：如果你已经拥有有效的证书文件 (crt/key)，请选择此项手动指定路径。"
    echo ""
    
    read -rp "请输入选项 [1-3]: " certInput
    
    if [[ $certInput == 2 ]]; then
        # 路径改为标准目录
        cert_path="/etc/hysteria/cert.crt"
        key_path="/etc/hysteria/private.key"

        # 检查是否已存在证书
        if [[ -f $cert_path && -f $key_path && -s $cert_path && -s $key_path ]] && [[ -f /root/ca.log ]]; then
            domain=$(cat /root/ca.log)
            green "检测到原有域名：$domain 的证书，正在应用"
            hy_domain=$domain
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
            
            # 安装证书到 /etc/hysteria 目录
            bash ~/.acme.sh/acme.sh --install-cert -d ${domain} --key-file /etc/hysteria/private.key --fullchain-file /etc/hysteria/cert.crt --ecc
            
            if [[ -f /etc/hysteria/cert.crt && -f /etc/hysteria/private.key ]]; then
                echo $domain > /root/ca.log
                sed -i '/--cron/d' /etc/crontab >/dev/null 2>&1
                echo "0 0 * * * root bash /root/.acme.sh/acme.sh --cron -f >/dev/null 2>&1" >> /etc/crontab
                
                # [关键] 修正权限：证书可读，私钥仅所有者可读
                chmod 644 /etc/hysteria/cert.crt
                chmod 600 /etc/hysteria/private.key
                
                green "证书申请成功!"
                hy_domain=$domain
            else
                red "证书申请失败！"
                exit 1
            fi
        fi
    elif [[ $certInput == 3 ]]; then
        read -p "请输入公钥文件 crt 的路径：" cert_path
        read -p "请输入密钥文件 key 的路径：" key_path
        read -p "请输入证书的域名：" domain
        hy_domain=$domain
    else
        green "将使用必应自签证书作为 Hysteria 2 的节点证书"
        
        cert_path="/etc/hysteria/cert.crt"
        key_path="/etc/hysteria/private.key"
        openssl ecparam -genkey -name prime256v1 -out /etc/hysteria/private.key
        openssl req -new -x509 -days 36500 -key /etc/hysteria/private.key -out /etc/hysteria/cert.crt -subj "/CN=www.bing.com"
        chmod 644 /etc/hysteria/cert.crt
        chmod 600 /etc/hysteria/private.key
        hy_domain="www.bing.com"
        domain="www.bing.com"
    fi
}

inst_port_config(){
    iptables -t nat -F PREROUTING >/dev/null 2>&1
    ip6tables -t nat -F PREROUTING >/dev/null 2>&1
    
    echo ""
    green "请选择端口使用模式："
    echo -e " ${GREEN}1.${PLAIN} 端口跳跃 (Port Hopping) ${YELLOW}（默认，强烈推荐）${PLAIN}"
    echo -e "    ${PLAIN}说明：自动在多个端口间切换，有效对抗运营商针对性阻断和限速，连接更稳。"
    echo -e " ${GREEN}2.${PLAIN} 单端口模式"
    echo ""
    read -rp "请输入选项 [1-2]: " portMode
    
    if [[ $portMode == 2 ]]; then
        read -p "设置 Hysteria 2 端口 [1-65535]（回车随机 2000-65535）：" port
        [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        
        until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
            echo -e "${RED} $port ${PLAIN} 端口已被占用，请更换！"
            read -p "设置 Hysteria 2 端口 [1-65535]：" port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        done
        
        firstport=""
        endport=""
        
        # [关键修复] 显式放行主端口，防止防火墙拦截
        iptables -I INPUT -p udp --dport $port -j ACCEPT
        ip6tables -I INPUT -p udp --dport $port -j ACCEPT
        
        yellow "Hysteria 2 将运行在单端口：$port"
        
    else
        green "已选择端口跳跃模式。"
        yellow "注意：请仔细检查服务器是否存在端口冲突（如Web服务的80/443等）。"
        yellow "推荐：结束端口与起始端口的差值建议在 100 以内。"
        echo ""
        
        read -p "请输入起始端口/主端口 [建议2500-10000] (回车随机生成): " firstport
        if [[ -z $firstport ]]; then
            firstport=$(shuf -i 2500-10000 -n 1)
        fi
        
        until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$firstport") ]]; do
            echo -e "${RED} $firstport ${PLAIN} 端口已被占用，请更换！"
            read -p "请输入起始端口/主端口：" firstport
            [[ -z $firstport ]] && firstport=$(shuf -i 2500-10000 -n 1)
        done
        
        default_endport=$((firstport + 75))
        read -p "请输入结束端口 (回车默认为 起始端口+75 -> $default_endport): " endport
        [[ -z $endport ]] && endport=$default_endport

        if [[ $firstport -ge $endport ]]; then
            until [[ $firstport -lt $endport ]]; do
                red "起始端口必须小于结束端口！"
                read -p "请重新输入起始端口：" firstport
                read -p "请重新输入结束端口：" endport
            done
        fi
        
        port=$firstport
        
        # 应用 DNAT 转发
        iptables -t nat -A PREROUTING -p udp --dport $firstport:$endport -j DNAT --to-destination :$port
        ip6tables -t nat -A PREROUTING -p udp --dport $firstport:$endport -j DNAT --to-destination :$port
        
        # [关键修复] 显式放行端口范围，防止防火墙拦截
        iptables -I INPUT -p udp --dport $firstport:$endport -j ACCEPT
        ip6tables -I INPUT -p udp --dport $firstport:$endport -j ACCEPT
        
        save_iptables_rules
        
        yellow "端口跳跃设置完成：$firstport - $endport (主监听端口: $port)"
    fi
}

inst_pwd(){
    read -p "设置 Hysteria 2 密码（回车跳过为随机字符）：" auth_pwd
    [[ -z $auth_pwd ]] && auth_pwd=$(date +%s%N | md5sum | cut -c 1-8)
    yellow "使用在 Hysteria 2 节点的密码为：$auth_pwd"
}

inst_site(){
    echo ""
    green "设置 Hysteria 2 伪装形式："
    
    echo -e " ${GREEN}1.${PLAIN} 返回 403 Forbidden 页面 ${YELLOW}（默认，强烈推荐）${PLAIN}"
    echo -e "    ${PLAIN}说明：模拟 Nginx 私有服务器拒绝访问。${GREEN}性能最优，CPU占用最低，隐蔽性极佳。${PLAIN}"
    echo ""
    
    echo -e " ${GREEN}2.${PLAIN} 伪装成其他网页 (Proxy 模式)"
    echo -e "    ${PLAIN}说明：反代目标网站。${RED}不推荐！会消耗额外 CPU/带宽，容易被识别为跳板攻击，伪装效果往往不如静态页面。${PLAIN}"
    echo ""
    
    read -rp "请输入选项 [1-2]: " masqInput
    
    if [[ $masqInput == 2 ]]; then
        masq_type="proxy"
        read -rp "请输入 Hysteria 2 的伪装网站地址 （去除https://） [默认首尔大学]：" proxysite
        [[ -z $proxysite ]] && proxysite="en.snu.ac.kr"
        yellow "Hysteria 2 将伪装成：$proxysite (性能较低)"
    else
        masq_type="string"
        proxysite=""
        green "Hysteria 2 将使用 403 Forbidden 页面作为伪装 (性能最优)"
    fi
}

inst_bandwidth(){
    echo ""
    green "设置服务端带宽限制 (速度限制)："
    echo -e " ${GREEN}1.${PLAIN} 开启 100 Mbps 限制 ${YELLOW}（默认，推荐）${PLAIN}"
    echo -e "    ${PLAIN}说明：${GREEN}100M 对于 4K 视频绰绰有余。${PLAIN}保持带宽克制能显著降低被运营商QoS(限速)或阻断的风险，使连接更持久稳定。"
    echo -e " ${GREEN}2.${PLAIN} 不限制带宽 (不推荐)"
    echo ""
    
    read -rp "请输入选项 [1-2]: " bwInput
    
    if [[ $bwInput == 2 ]]; then
        limit_bandwidth="no"
        bandwidth_value=""
        yellow "已选择：不限制带宽"
    else
        limit_bandwidth="yes"
        bandwidth_value="100"
        yellow "已选择：限制服务端带宽为 100 Mbps (上下行)"
    fi
}

generate_config(){
    mkdir -p /etc/hysteria

    # 针对 IPv6 环境优化：监听 [::]:port
    cat << EOF > /etc/hysteria/config.yaml
listen: "[::]:$port"

tls:
  cert: $cert_path
  key: $key_path

quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432

auth:
  type: password
  password: $auth_pwd

EOF

    if [[ $limit_bandwidth == "yes" ]]; then
        cat << EOF >> /etc/hysteria/config.yaml
bandwidth:
  up: ${bandwidth_value:-100} mbps
  down: ${bandwidth_value:-100} mbps

EOF
    fi

    cat << EOF >> /etc/hysteria/config.yaml
masquerade:
EOF
    if [[ $masq_type == "proxy" ]]; then
        cat << EOF >> /etc/hysteria/config.yaml
  type: proxy
  proxy:
    url: https://$proxysite
    rewriteHost: true
EOF
    else
        cat << EOF >> /etc/hysteria/config.yaml
  type: string
  string:
    content: "<h1>403 Forbidden</h1><p>You don't have permission to access this resource.</p><hr><address>Nginx</address>"
    headers:
      Content-Type: text/html; charset=utf-8
      Server: nginx
    statusCode: 403
EOF
    fi
}

generate_client_config(){
    realip
    
    if [[ -n $firstport ]]; then
        server_port_string="$port,$firstport-$endport"
    else
        server_port_string=$port
    fi

    if [[ -n $(echo $ip | grep ":") ]]; then
        last_ip="[$ip]"
    else
        last_ip=$ip
    fi

    mkdir -p /root/hy
    cat << EOF > /root/hy/hy-client.yaml
server: $last_ip:$server_port_string

auth: $auth_pwd

tls:
  sni: $hy_domain
  insecure: true

quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432

fastOpen: true

socks5:
  listen: 127.0.0.1:5678

transport:
  udp:
    hopInterval: 25s 
EOF
    
    cat << EOF > /root/hy/hy-client.json
{
  "server": "$last_ip:$server_port_string",
  "auth": "$auth_pwd",
  "tls": {
    "sni": "$hy_domain",
    "insecure": true
  },
  "quic": {
    "initStreamReceiveWindow": 16777216,
    "maxStreamReceiveWindow": 16777216,
    "initConnReceiveWindow": 33554432,
    "maxConnReceiveWindow": 33554432
  },
  "socks5": {
    "listen": "127.0.0.1:5678"
  },
  "transport": {
    "udp": {
      "hopInterval": "25s"
    }
  }
}
EOF

    url="hysteria2://${auth_pwd}@${last_ip}:${port}?security=tls&insecure=1&sni=${hy_domain}&mportHopInt=25"
    
    if [[ -n $firstport ]]; then
        url="${url}&mport=${firstport}-${endport}"
    fi
    
    url="${url}#Hysteria2"
    
    echo "$url" > /root/hy/url.txt
}

read_current_config(){
    if [[ -f /etc/hysteria/config.yaml ]]; then
        port=$(grep "^listen:" /etc/hysteria/config.yaml | awk '{print $2}' | sed 's/://g;s/\[//g;s/\]//g')
        cert_path=$(grep "cert:" /etc/hysteria/config.yaml | awk '{print $2}')
        key_path=$(grep "key:" /etc/hysteria/config.yaml | awk '{print $2}')
        auth_pwd=$(grep "password:" /etc/hysteria/config.yaml | awk '{print $2}')
        
        if grep -q "type: proxy" /etc/hysteria/config.yaml; then
            masq_type="proxy"
            proxysite=$(grep "url:" /etc/hysteria/config.yaml | sed 's/.*https:\/\///g' | sed 's/ //g')
        else
            masq_type="string"
            proxysite=""
        fi
        
        if grep -q "bandwidth:" /etc/hysteria/config.yaml; then
            limit_bandwidth="yes"
            bandwidth_value=$(grep "up:" /etc/hysteria/config.yaml | head -1 | awk '{print $2}')
        else
            limit_bandwidth="no"
            bandwidth_value=""
        fi
        
        if [[ -f /root/hy/hy-client.yaml ]]; then
            hy_domain=$(grep "sni:" /root/hy/hy-client.yaml | awk '{print $2}')
        else
            hy_domain=$(openssl x509 -in "$cert_path" -noout -subject 2>/dev/null | sed 's/.*CN = //;s/,.*//')
            [[ -z $hy_domain ]] && hy_domain="www.bing.com"
        fi
        
        port_hop_rule=$(iptables -t nat -L PREROUTING -n 2>/dev/null | grep -E "dpts?:[0-9]+" | head -1)
        if [[ -n $port_hop_rule ]]; then
            firstport=$(echo "$port_hop_rule" | grep -oP 'dpts:\K[0-9]+' | head -1)
            endport=$(echo "$port_hop_rule" | grep -oP 'dpts:[0-9]+:\K[0-9]+')
            if [[ -z $endport ]]; then
                port_range=$(echo "$port_hop_rule" | grep -oP 'dpt[s]?:[0-9:]+' | sed 's/dpts\?://')
                firstport=$(echo "$port_range" | cut -d: -f1)
                endport=$(echo "$port_range" | cut -d: -f2)
            fi
        else
            firstport=""
            endport=""
        fi
        
        return 0
    else
        return 1
    fi
}

insthysteria(){
    warpv6=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    warpv4=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    if [[ $warpv4 =~ on|plus || $warpv6 =~ on|plus ]]; then
        wg-quick down wgcf >/dev/null 2>&1
        systemctl stop warp-go >/dev/null 2>&1
        realip
        systemctl start warp-go >/dev/null 2>&1
        wg-quick up wgcf >/dev/null 2>&1
    else
        realip
    fi

    if [[ ! ${SYSTEM} == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl wget sudo qrencode procps
    
    install_iptables_persistent

    wget -N https://raw.githubusercontent.com/Misaka-blog/hysteria-install/main/hy2/install_server.sh
    bash install_server.sh
    rm -f install_server.sh

    inst_cert
    inst_port_config
    inst_pwd
    inst_site
    inst_bandwidth
    generate_config
    generate_client_config

    systemctl daemon-reload
    systemctl enable hysteria-server
    
    # [关键修复] 等待5秒让 WARP 网络就绪，防止启动过快导致失败
    echo "正在等待网络环境就绪..."
    sleep 5
    systemctl start hysteria-server
    
    if [[ ! -f /usr/bin/hy2 ]]; then
        cp -f "$0" /usr/bin/hy2
        chmod +x /usr/bin/hy2
    fi

    if [[ -n $(systemctl status hysteria-server 2>/dev/null | grep -w active) && -f '/etc/hysteria/config.yaml' ]]; then
        green "Hysteria 2 服务启动成功"
    else
        red "Hysteria 2 服务启动失败" && exit 1
    fi
    red "======================================================================================"
    green "Hysteria 2 代理服务安装完成"
    
    green "======================================================================================"
    green "               管理命令：${YELLOW}hy2${GREEN} (直接输入 hy2 即可)"
    green "        输入 ${YELLOW}hy2${GREEN} 即可再次召唤本主界面，进行配置管理"
    green "======================================================================================"
    
    yellow "Hysteria 2 客户端 YAML 配置文件 hy-client.yaml 内容如下"
    red "$(cat /root/hy/hy-client.yaml)"
    yellow "Hysteria 2 客户端 JSON 配置文件 hy-client.json 内容如下"
    red "$(cat /root/hy/hy-client.json)"
    yellow "Hysteria 2 节点分享链接如下"
    red "$(cat /root/hy/url.txt)"
}

unsthysteria(){
    systemctl stop hysteria-server.service >/dev/null 2>&1
    systemctl disable hysteria-server.service >/dev/null 2>&1
    rm -f /lib/systemd/system/hysteria-server.service /lib/systemd/system/hysteria-server@.service
    rm -rf /usr/local/bin/hysteria /etc/hysteria /root/hy /root/hysteria.sh
    rm -f /usr/bin/hy2
    iptables -t nat -F PREROUTING >/dev/null 2>&1
    ip6tables -t nat -F PREROUTING >/dev/null 2>&1
    save_iptables_rules
    green "Hysteria 2 已彻底卸载完成！"
}

starthysteria(){
    systemctl start hysteria-server
    systemctl enable hysteria-server >/dev/null 2>&1
}

stophysteria(){
    systemctl stop hysteria-server
    systemctl disable hysteria-server >/dev/null 2>&1
}

hysteriaswitch(){
    yellow "请选择你需要的操作："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 启动 Hysteria 2"
    echo -e " ${GREEN}2.${PLAIN} 关闭 Hysteria 2"
    echo -e " ${GREEN}3.${PLAIN} 重启 Hysteria 2"
    echo ""
    read -rp "请输入选项 [0-3]: " switchInput
    case $switchInput in
        1 ) starthysteria ;;
        2 ) stophysteria ;;
        3 ) stophysteria && starthysteria ;;
        * ) exit 1 ;;
    esac
}

changebandwidth(){
    read_current_config
    
    echo ""
    green "请选择是否开启带宽限速 (推荐开启以防止阻断)："
    echo -e " ${GREEN}1.${PLAIN} 开启 100 Mbps 限制"
    echo -e " ${GREEN}2.${PLAIN} 自定义限速数值"
    echo -e " ${GREEN}3.${PLAIN} 关闭限速 (不限制)"
    echo ""
    read -rp "请输入选项 [1-3]: " bwChange
    
    if [[ $bwChange == 1 ]]; then
        limit_bandwidth="yes"
        bandwidth_value="100"
        yellow "已设置为：100 Mbps 限速"
    elif [[ $bwChange == 2 ]]; then
        read -p "请输入限速数值 (单位 mbps，例如 50): " custBw
        [[ -z $custBw ]] && custBw=100
        limit_bandwidth="yes"
        bandwidth_value="$custBw"
        yellow "已设置为：$custBw Mbps 限速"
    else
        limit_bandwidth="no"
        bandwidth_value=""
        yellow "已关闭带宽限制"
    fi

    generate_config
    stophysteria && starthysteria
    green "带宽限制配置已更新！"
}

changeport(){
    read_current_config
    inst_port_config
    generate_config
    generate_client_config
    stophysteria && starthysteria
    green "Hysteria 2 端口配置已更新！"
    showconf
}

changepasswd(){
    read_current_config
    read -p "设置 Hysteria 2 密码（回车跳过为随机字符）：" new_pwd
    [[ -z $new_pwd ]] && new_pwd=$(date +%s%N | md5sum | cut -c 1-8)
    auth_pwd=$new_pwd
    generate_config
    generate_client_config
    stophysteria && starthysteria
    green "Hysteria 2 节点密码已成功修改为：$auth_pwd"
    showconf
}

change_cert(){
    read_current_config
    inst_cert
    generate_config
    generate_client_config
    stophysteria && starthysteria
    green "Hysteria 2 节点证书类型已成功修改"
    showconf
}

changeproxysite(){
    read_current_config
    inst_site
    generate_config
    stophysteria && starthysteria
    green "Hysteria 2 节点伪装形式已修改成功！"
}

changeconf(){
    green "Hysteria 2 配置变更选择如下:"
    echo -e " ${GREEN}1.${PLAIN} 修改端口 (重新配置)"
    echo -e " ${GREEN}2.${PLAIN} 修改密码"
    echo -e " ${GREEN}3.${PLAIN} 修改证书类型"
    echo -e " ${GREEN}4.${PLAIN} 修改伪装形式"
    echo -e " ${GREEN}5.${PLAIN} 编辑带宽限速"
    echo ""
    read -p " 请选择操作 [1-5]：" confAnswer
    case $confAnswer in
        1 ) changeport ;;
        2 ) changepasswd ;;
        3 ) change_cert ;;
        4 ) changeproxysite ;;
        5 ) changebandwidth ;;
        * ) exit 1 ;;
    esac
}

showconf(){
    if [[ ! -f /root/hy/hy-client.yaml ]]; then
        red "未找到客户端配置文件，请先安装 Hysteria 2"
        return 1
    fi
    yellow "Hysteria 2 客户端 YAML 配置文件 hy-client.yaml 内容如下"
    red "$(cat /root/hy/hy-client.yaml)"
    yellow "Hysteria 2 客户端 JSON 配置文件 hy-client.json 内容如下"
    red "$(cat /root/hy/hy-client.json)"
    yellow "Hysteria 2 节点分享链接如下"
    red "$(cat /root/hy/url.txt)"
}

menu() {
    clear
    echo "#############################################################"
    echo -e "#                  ${GREEN}Hysteria 2 一键安装脚本${PLAIN}                  #"
    echo "#############################################################"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} ${GREEN}安装 Hysteria 2${PLAIN}"
    echo -e " ${RED}2.${PLAIN} ${RED}卸载 Hysteria 2${PLAIN}"
    echo " ------------------------------------------------------------"
    echo -e " 3. 关闭、开启、重启 Hysteria 2"
    echo -e " 4. 修改 Hysteria 2 配置"
    echo -e " 5. 显示 Hysteria 2 配置文件"
    echo " ------------------------------------------------------------"
    echo -e " 0. 退出脚本"
    echo ""
    read -rp "请输入选项 [0-5]: " menuInput
    case $menuInput in
        1 ) insthysteria ;;
        2 ) unsthysteria ;;
        3 ) hysteriaswitch ;;
        4 ) changeconf ;;
        5 ) showconf ;;
        * ) exit 1 ;;
    esac
}

menu
