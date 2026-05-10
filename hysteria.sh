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

IPTABLES_NAT_COMMENT="hy2-port-hop"
IPTABLES_INPUT_COMMENT="hy2-udp-input"
PORT_STATE_FILE="/etc/hysteria/port_state.conf"

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

iptables_do() {
    local bin="$1"
    shift
    if has_cmd "$bin"; then
        "$bin" -w 5 "$@" 2>/dev/null || "$bin" "$@" 2>/dev/null
    else
        return 1
    fi
}

is_ipv4() {
    [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

is_ipv6() {
    [[ $1 == *:* ]]
}

strip_url_scheme() {
    local v="$1"
    v="${v#http://}"
    v="${v#https://}"
    printf "%s" "$v"
}


[[ $EUID -ne 0 ]] && red "注意: 请在root用户下运行脚本" && exit 1

CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

SYS=""
for i in "${CMD[@]}"; do
    SYS="$i" && [[ -n $SYS ]] && break
done

SYSTEM=""
int=0
for ((int = 0; int < ${#REGEX[@]}; int++)); do
    if [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]]; then
        SYSTEM="${RELEASE[int]}"
        [[ -n $SYSTEM ]] && break
    fi
done

[[ -z $SYSTEM ]] && red "目前暂不支持你的VPS的操作系统！" && exit 1

if [[ -z $(type -P curl) ]]; then
    if [[ ! $SYSTEM == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl
fi

# URL编码函数
urlencode() {
    local string="$1"
    local strlen=${#string}
    local encoded=""
    local pos c o

    for (( pos=0 ; pos<strlen ; pos++ )); do
        c=${string:$pos:1}
        case "$c" in
            [-_.~a-zA-Z0-9] ) o="$c" ;;
            * ) printf -v o '%%%02X' "'$c" ;;
        esac
        encoded+="$o"
    done
    echo "$encoded"
}

# YAML 单引号字符串转义函数
yaml_escape() {
    local string="$1"
    string=${string//\'/\'\'}
    printf "'%s'" "$string"
}


# YAML 单引号字符串反转义函数
yaml_unescape() {
    local string="$1"
    string="${string#"${string%%[![:space:]]*}"}"
    string="${string%"${string##*[![:space:]]}"}"
    if [[ $string == \'*\' ]]; then
        string=${string:1:${#string}-2}
        string=${string//\'\'/\'}
    elif [[ $string == \"*\" ]]; then
        string=${string:1:${#string}-2}
    fi
    printf "%s" "$string"
}

# JSON 字符串转义函数
json_escape() {
    local string="$1"
    string=${string//\\/\\\\}
    string=${string//\"/\\\"}
    string=${string//$'\n'/\\n}
    string=${string//$'\r'/\\r}
    string=${string//$'\t'/\\t}
    string=${string//$'\b'/\\b}
    string=${string//$'\f'/\\f}
    printf "%s" "$string"
}

# 生成更高复杂度的随机密码
generate_password() {
    LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 32
}

is_number() {
    [[ $1 =~ ^[0-9]+$ ]]
}

valid_port() {
    is_number "$1" && (( 10#$1 >= 1 && 10#$1 <= 65535 ))
}

valid_hop_interval() {
    is_number "$1" && (( 10#$1 >= 5 ))
}

is_udp_port_in_use() {
    local check_port="$1"
    if ! has_cmd ss; then
        return 1
    fi
    ss -H -uln 2>/dev/null | awk '{print $5}' | sed 's/.*://g' | grep -w "$check_port" >/dev/null 2>&1
}

check_udp_range_conflict() {
    local start="$1"
    local end="$2"
    local p
    local conflicts=()
    local shown=0

    for ((p=start; p<=end; p++)); do
        if is_udp_port_in_use "$p"; then
            conflicts+=("$p")
            ((shown++))
            [[ $shown -ge 8 ]] && break
        fi
    done

    if [[ ${#conflicts[@]} -gt 0 ]]; then
        red "端口范围内发现 UDP 端口已被占用：${conflicts[*]}"
        red "端口跳跃会接管整个范围，请更换一个完全空闲的范围。"
        return 1
    fi

    return 0
}

remove_rules_by_comment() {
    local bin="$1"
    local table="$2"
    local chain="$3"
    local comment="$4"
    local line
    local count=0

    if ! has_cmd "$bin"; then
        return 0
    fi

    while true; do
        if [[ -n "$table" ]]; then
            line=$("$bin" -t "$table" -L "$chain" --line-numbers -n -v 2>/dev/null | grep -F "$comment" | awk '{print $1}' | head -n 1)
        else
            line=$("$bin" -L "$chain" --line-numbers -n -v 2>/dev/null | grep -F "$comment" | awk '{print $1}' | head -n 1)
        fi

        [[ -z "$line" ]] && break

        if [[ -n "$table" ]]; then
            "$bin" -t "$table" -D "$chain" "$line" >/dev/null 2>&1 || break
        else
            "$bin" -D "$chain" "$line" >/dev/null 2>&1 || break
        fi

        ((count++))
        [[ $count -gt 100 ]] && break
    done
}

remove_hy2_iptables_rules() {
    remove_rules_by_comment iptables nat PREROUTING "$IPTABLES_NAT_COMMENT"
    remove_rules_by_comment ip6tables nat PREROUTING "$IPTABLES_NAT_COMMENT"
    remove_rules_by_comment iptables "" INPUT "$IPTABLES_INPUT_COMMENT"
    remove_rules_by_comment ip6tables "" INPUT "$IPTABLES_INPUT_COMMENT"
}

add_udp_input_rule() {
    local range="$1"
    local ok=1

    iptables_do iptables -I INPUT -p udp --dport "$range" -m comment --comment "$IPTABLES_INPUT_COMMENT" -j ACCEPT && ok=0
    iptables_do ip6tables -I INPUT -p udp --dport "$range" -m comment --comment "$IPTABLES_INPUT_COMMENT" -j ACCEPT && ok=0

    return "$ok"
}

add_port_hop_redirect_rule() {
    local range="$1"
    local target_port="$2"
    local ok=1

    iptables_do iptables -t nat -A PREROUTING -p udp --dport "$range" -m comment --comment "$IPTABLES_NAT_COMMENT" -j REDIRECT --to-ports "$target_port" && ok=0
    iptables_do ip6tables -t nat -A PREROUTING -p udp --dport "$range" -m comment --comment "$IPTABLES_NAT_COMMENT" -j REDIRECT --to-ports "$target_port" && ok=0

    return "$ok"
}

save_port_state() {
    mkdir -p /etc/hysteria
    cat > "$PORT_STATE_FILE" << EOF
PORT='$port'
FIRSTPORT='$firstport'
ENDPORT='$endport'
HOP_INTERVAL='$hop_interval'
MIN_HOP_INTERVAL='$min_hop_interval'
MAX_HOP_INTERVAL='$max_hop_interval'
EOF
    chmod 600 "$PORT_STATE_FILE"
}

load_port_state() {
    if [[ -f "$PORT_STATE_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$PORT_STATE_FILE"
        port="$PORT"
        firstport="$FIRSTPORT"
        endport="$ENDPORT"
        hop_interval="$HOP_INTERVAL"
        min_hop_interval="$MIN_HOP_INTERVAL"
        max_hop_interval="$MAX_HOP_INTERVAL"
        return 0
    fi
    return 1
}

grant_traverse_permission() {
    local target_path="$1"
    local dir
    local current_path=""
    local part

    dir=$(dirname "$target_path")
    IFS='/' read -ra path_parts <<< "$dir"
    for part in "${path_parts[@]}"; do
        [[ -z "$part" ]] && continue
        current_path="$current_path/$part"
        if id "hysteria" &>/dev/null && has_cmd setfacl; then
            setfacl -m u:hysteria:--x "$current_path" 2>/dev/null || true
        else
            chmod o+x "$current_path" 2>/dev/null || true
        fi
    done
}

grant_cert_read_permissions() {
    local cert_file="$1"
    local key_file="$2"
    local real_cert_path
    local real_key_path

    real_cert_path=$(readlink -f "$cert_file" 2>/dev/null || echo "$cert_file")
    real_key_path=$(readlink -f "$key_file" 2>/dev/null || echo "$key_file")

    grant_traverse_permission "$real_cert_path"
    grant_traverse_permission "$real_key_path"

    if id "hysteria" &>/dev/null && has_cmd setfacl; then
        setfacl -m u:hysteria:r "$real_cert_path" "$real_key_path" 2>/dev/null || true
        setfacl -d -m u:hysteria:r "$(dirname "$real_cert_path")" 2>/dev/null || true
        setfacl -d -m u:hysteria:r "$(dirname "$real_key_path")" 2>/dev/null || true
    elif id "hysteria" &>/dev/null; then
        chgrp hysteria "$real_cert_path" "$real_key_path" 2>/dev/null || true
        chmod g+r "$real_cert_path" "$real_key_path" 2>/dev/null || true
    else
        chmod o+r "$real_cert_path" "$real_key_path" 2>/dev/null || true
    fi

    # 最大兼容兜底：如果没有 setfacl/chgrp 或续签后新文件未继承 ACL，仍允许服务读取。
    # 这里不复制、不搬运证书，只对原路径授予读取权限。
    chmod o+r "$real_cert_path" "$real_key_path" 2>/dev/null || true
}


install_cert_permission_helper() {
    mkdir -p /usr/local/bin
    cat > /usr/local/bin/hy2-fix-cert-perms <<'EOS'
#!/bin/bash

CONFIG_FILE="/etc/hysteria/config.yaml"

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

yaml_unescape_local() {
    local string="$1"
    string="${string#"${string%%[![:space:]]*}"}"
    string="${string%"${string##*[![:space:]]}"}"
    if [[ $string == \'*\' ]]; then
        string=${string:1:${#string}-2}
        string=${string//\'\'/\'}
    elif [[ $string == \"*\" ]]; then
        string=${string:1:${#string}-2}
    fi
    printf "%s" "$string"
}

grant_traverse_permission_local() {
    local target_path="$1"
    local dir
    local current_path=""
    local part

    dir=$(dirname "$target_path")
    IFS='/' read -ra path_parts <<< "$dir"
    for part in "${path_parts[@]}"; do
        [[ -z "$part" ]] && continue
        current_path="$current_path/$part"
        if id "hysteria" &>/dev/null && has_cmd setfacl; then
            setfacl -m u:hysteria:--x "$current_path" 2>/dev/null || true
        else
            chmod o+x "$current_path" 2>/dev/null || true
        fi
    done
}

grant_cert_read_permissions_local() {
    local cert_file="$1"
    local key_file="$2"
    local real_cert_path
    local real_key_path

    real_cert_path=$(readlink -f "$cert_file" 2>/dev/null || echo "$cert_file")
    real_key_path=$(readlink -f "$key_file" 2>/dev/null || echo "$key_file")

    [[ -f "$real_cert_path" && -f "$real_key_path" ]] || exit 0

    grant_traverse_permission_local "$real_cert_path"
    grant_traverse_permission_local "$real_key_path"

    if id "hysteria" &>/dev/null && has_cmd setfacl; then
        setfacl -m u:hysteria:r "$real_cert_path" "$real_key_path" 2>/dev/null || true
        setfacl -d -m u:hysteria:r "$(dirname "$real_cert_path")" 2>/dev/null || true
        setfacl -d -m u:hysteria:r "$(dirname "$real_key_path")" 2>/dev/null || true
    elif id "hysteria" &>/dev/null; then
        chgrp hysteria "$real_cert_path" "$real_key_path" 2>/dev/null || true
        chmod g+r "$real_cert_path" "$real_key_path" 2>/dev/null || true
    fi

    # 兼容优先：不搬运证书，直接确保原始目标文件可被服务读取。
    chmod o+r "$real_cert_path" "$real_key_path" 2>/dev/null || true
}

[[ -f "$CONFIG_FILE" ]] || exit 0
cert_path=$(yaml_unescape_local "$(grep "^[[:space:]]*cert:" "$CONFIG_FILE" | head -1 | sed 's/^[[:space:]]*cert:[[:space:]]*//')")
key_path=$(yaml_unescape_local "$(grep "^[[:space:]]*key:" "$CONFIG_FILE" | head -1 | sed 's/^[[:space:]]*key:[[:space:]]*//')")
[[ -n "$cert_path" && -n "$key_path" ]] || exit 0

grant_cert_read_permissions_local "$cert_path" "$key_path"
EOS
    chmod +x /usr/local/bin/hy2-fix-cert-perms

    # Certbot 续签后自动重新授权。这个 hook 不复制、不搬运证书，只重授读取权限。
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy 2>/dev/null || true
    if [[ -d /etc/letsencrypt/renewal-hooks/deploy ]]; then
        cat > /etc/letsencrypt/renewal-hooks/deploy/hy2-fix-cert-perms <<'EOS'
#!/bin/bash
/usr/local/bin/hy2-fix-cert-perms >/dev/null 2>&1 || true
systemctl try-restart hysteria-server >/dev/null 2>&1 || true
EOS
        chmod +x /etc/letsencrypt/renewal-hooks/deploy/hy2-fix-cert-perms
    fi
}

install_management_command() {
    local src=""

    if [[ -n ${BASH_SOURCE[0]} && -f ${BASH_SOURCE[0]} ]]; then
        src="${BASH_SOURCE[0]}"
    elif [[ -f "$0" && "$0" != "bash" && "$0" != "-bash" ]]; then
        src="$0"
    fi

    if [[ -n "$src" ]]; then
        install -m 755 "$src" /usr/bin/hy2
    else
        red "无法自动写入 /usr/bin/hy2：请将脚本保存为文件后运行，或手动复制到 /usr/bin/hy2"
        return 1
    fi
}

realip(){
    ip=$(curl -s4m8 https://ip.sb -k 2>/dev/null | tr -d '\r\n[:space:]')
    if [[ -z $ip ]]; then
        ip=$(curl -s6m8 https://ip.sb -k 2>/dev/null | tr -d '\r\n[:space:]')
    fi
    if [[ -z $ip ]]; then
        red "无法获取服务器公网 IP，请检查网络。"
        exit 1
    fi
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
        # 非交互式安装 iptables-persistent
        echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections 2>/dev/null
        echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections 2>/dev/null
        DEBIAN_FRONTEND=noninteractive ${PACKAGE_INSTALL[int]} iptables-persistent netfilter-persistent
    fi
}

fix_permissions(){
    if id "hysteria" &>/dev/null; then
        chown -R hysteria:hysteria /etc/hysteria
    fi
    chmod 755 /etc/hysteria
    if [[ -f /etc/hysteria/cert.crt ]]; then
        chmod 644 /etc/hysteria/cert.crt
    fi
    if [[ -f /etc/hysteria/private.key ]]; then
        chmod 600 /etc/hysteria/private.key
    fi
}

inst_cert(){
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
        cert_path="/etc/hysteria/cert.crt"
        key_path="/etc/hysteria/private.key"
        # ACME申请的证书是受信任的，不需要跳过验证
        insecure=0

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
            
            read -rp "请输入需要申请证书的域名：" domain
            [[ -z $domain ]] && red "未输入域名，无法执行操作！" && exit 1
            green "已输入的域名：$domain" && sleep 1
            
            ${PACKAGE_INSTALL[int]} curl wget sudo socat openssl acl
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
                bash ~/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --listen-v6 --insecure
            else
                bash ~/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --insecure
            fi
            
            bash ~/.acme.sh/acme.sh --install-cert -d "${domain}" --key-file /etc/hysteria/private.key --fullchain-file /etc/hysteria/cert.crt --ecc --reloadcmd "chown hysteria:hysteria /etc/hysteria/cert.crt /etc/hysteria/private.key 2>/dev/null || true; chmod 644 /etc/hysteria/cert.crt 2>/dev/null || true; chmod 600 /etc/hysteria/private.key 2>/dev/null || true; systemctl try-restart hysteria-server >/dev/null 2>&1 || true"
            
            if [[ -f /etc/hysteria/cert.crt && -f /etc/hysteria/private.key ]] && [[ -s /etc/hysteria/cert.crt && -s /etc/hysteria/private.key ]]; then
                echo "$domain" > /root/ca.log
                install_cert_permission_helper
                sed -i '/--cron/d' /etc/crontab >/dev/null 2>&1
                echo "0 0 * * * root bash /root/.acme.sh/acme.sh --cron -f >/dev/null 2>&1" >> /etc/crontab
                
                green "证书申请成功!"
                hy_domain=$domain
            else
                red "证书申请失败！"
                exit 1
            fi
        fi
    elif [[ $certInput == 3 ]]; then
        read -rp "请输入公钥文件 crt 的路径：" cert_path
        read -rp "请输入密钥文件 key 的路径：" key_path
        read -rp "请输入证书的域名：" domain
        
        if [[ ! -f $cert_path ]]; then
            red "证书文件不存在：$cert_path"
            exit 1
        fi
        if [[ ! -f $key_path ]]; then
            red "密钥文件不存在：$key_path"
            exit 1
        fi
        
        # 不搬运、不复制证书：只对用户提供的原始证书路径授予 Hysteria 读取权限。
        grant_cert_read_permissions "$cert_path" "$key_path"
        install_cert_permission_helper

        hy_domain=$domain
        # 用户提供的证书默认是受信任的，不需要跳过验证
        insecure=0
        
        green "已授予 Hysteria 读取证书文件的权限"
    else
        green "将使用必应自签证书作为 Hysteria 2 的节点证书"
        
        cert_path="/etc/hysteria/cert.crt"
        key_path="/etc/hysteria/private.key"
        openssl ecparam -genkey -name prime256v1 -out /etc/hysteria/private.key
        openssl req -new -x509 -days 36500 -key /etc/hysteria/private.key -out /etc/hysteria/cert.crt -subj "/CN=www.bing.com"
        hy_domain="www.bing.com"
        domain="www.bing.com"
        # 自签证书需要跳过验证
        insecure=1
    fi
}

inst_port_config(){
    remove_hy2_iptables_rules
    
    echo ""
    green "请选择端口使用模式："
    echo -e " ${GREEN}1.${PLAIN} 端口跳跃 (Port Hopping) ${YELLOW}（默认，强烈推荐）${PLAIN}"
    echo -e "    ${PLAIN}说明：自动在多个端口间切换，有效对抗运营商针对性阻断和限速，连接更稳。"
    echo -e " ${GREEN}2.${PLAIN} 单端口模式"
    echo ""
    read -rp "请输入选项 [1-2]: " portMode
    
    if [[ $portMode == 2 ]]; then
        while true; do
            read -rp "设置 Hysteria 2 端口 [1-65535]（回车随机 2000-65535）：" port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
            
            if ! valid_port "$port"; then
                red "端口必须是 1-65535 之间的数字！"
                continue
            fi
            port=$((10#$port))
            
            if is_udp_port_in_use "$port"; then
                echo -e "${RED} $port ${PLAIN} 端口已被占用，请更换！"
                continue
            fi
            
            break
        done
        
        firstport=""
        endport=""
        hop_interval=""
        min_hop_interval=""
        max_hop_interval=""
        
        if ! add_udp_input_rule "$port"; then
            yellow "警告：未能自动添加防火墙放行规则，请确认服务器安全组/防火墙已放行 UDP $port。"
        fi
        save_port_state
        save_iptables_rules
        
        yellow "Hysteria 2 将运行在单端口：$port"
        
    else
        green "已选择端口跳跃模式。"
        yellow "注意：请仔细检查服务器是否存在端口冲突（如Web服务的80/443等）。"
        yellow "推荐：结束端口与起始端口的差值建议在 100 以内。"
        echo ""
        
        while true; do
            read -rp "请输入起始端口/主端口 [建议2500-10000] (回车随机生成): " firstport
            [[ -z $firstport ]] && firstport=$(shuf -i 2500-10000 -n 1)
            
            if ! valid_port "$firstport"; then
                red "起始端口必须是 1-65535 之间的数字！"
                continue
            fi
            firstport=$((10#$firstport))
            
            if [[ $firstport -ge 65535 ]]; then
                red "端口跳跃模式下起始端口必须小于 65535！"
                continue
            fi
            
            if is_udp_port_in_use "$firstport"; then
                echo -e "${RED} $firstport ${PLAIN} 端口已被占用，请更换！"
                continue
            fi
            
            break
        done
        
        while true; do
            default_endport=$((firstport + 75))
            [[ $default_endport -gt 65535 ]] && default_endport=65535
            read -rp "请输入结束端口 (回车默认为 起始端口+75 -> $default_endport): " endport
            [[ -z $endport ]] && endport=$default_endport
            
            if ! valid_port "$endport"; then
                red "结束端口必须是 1-65535 之间的数字！"
                continue
            fi
            endport=$((10#$endport))
            
            if [[ $firstport -ge $endport ]]; then
                red "起始端口必须小于结束端口！"
                continue
            fi

            if ! check_udp_range_conflict "$firstport" "$endport"; then
                continue
            fi

            break
        done
        
        # 设置端口跳跃间隔
        echo ""
        green "请选择端口跳跃时间模式："
        echo -e " ${GREEN}1.${PLAIN} 固定跳跃时间 ${YELLOW}（默认）${PLAIN}"
        echo -e " ${GREEN}2.${PLAIN} 随机跳跃时间"
        echo -e "    ${YELLOW}注意：低版本的代理软件可能不支持随机跳跃时间，Xray 内核系列可能不支持。${PLAIN}"
        echo ""
        read -rp "请输入选项 [1-2]: " hopTimeMode
        
        if [[ $hopTimeMode == 2 ]]; then
            hop_interval=""
            while true; do
                read -rp "请输入最低跳跃时间秒数 [默认15]: " min_hop_interval
                [[ -z $min_hop_interval ]] && min_hop_interval=15
                read -rp "请输入最高跳跃时间秒数 [默认25]: " max_hop_interval
                [[ -z $max_hop_interval ]] && max_hop_interval=25
                
                if ! valid_hop_interval "$min_hop_interval"; then
                    red "最低跳跃时间必须是数字，且至少为 5 秒！"
                    continue
                fi
                min_hop_interval=$((10#$min_hop_interval))
                
                if ! is_number "$max_hop_interval"; then
                    red "最高跳跃时间必须是数字！"
                    continue
                fi
                max_hop_interval=$((10#$max_hop_interval))
                
                if [[ $max_hop_interval -le $min_hop_interval ]]; then
                    red "最高跳跃时间必须大于最低跳跃时间，不能等于或小于！"
                    continue
                fi
                
                break
            done
        else
            min_hop_interval=""
            max_hop_interval=""
            while true; do
                read -rp "请输入端口跳跃间隔秒数 [默认25]: " hop_interval
                [[ -z $hop_interval ]] && hop_interval=25
                
                if ! valid_hop_interval "$hop_interval"; then
                    red "端口跳跃间隔必须是数字，且至少为 5 秒！"
                    continue
                fi
                hop_interval=$((10#$hop_interval))
                
                break
            done
        fi
        
        port=$firstport
        
        if ! add_port_hop_redirect_rule "$firstport:$endport" "$port"; then
            red "端口跳跃转发规则添加失败，请确认 iptables/ip6tables 可用。"
            return 1
        fi
        if ! add_udp_input_rule "$firstport:$endport"; then
            yellow "警告：未能自动添加防火墙放行规则，请确认服务器安全组/防火墙已放行 UDP $firstport-$endport。"
        fi
        save_port_state
        save_iptables_rules

        if [[ -n $min_hop_interval && -n $max_hop_interval ]]; then
            yellow "端口跳跃设置完成：$firstport - $endport (主监听端口: $port, 随机跳跃间隔: ${min_hop_interval}-${max_hop_interval}s)"
        else
            yellow "端口跳跃设置完成：$firstport - $endport (主监听端口: $port, 跳跃间隔: ${hop_interval}s)"
        fi
    fi
}

inst_pwd(){
    read -rp "设置 Hysteria 2 密码（回车跳过为随机字符）：" auth_pwd
    [[ -z $auth_pwd ]] && auth_pwd=$(generate_password)
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
        proxysite=$(strip_url_scheme "$proxysite")
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

    yaml_cert_path=$(yaml_escape "$cert_path")
    yaml_key_path=$(yaml_escape "$key_path")
    yaml_auth_pwd=$(yaml_escape "$auth_pwd")
    yaml_proxy_url=$(yaml_escape "https://$proxysite")

    cat << EOF > /etc/hysteria/config.yaml
listen: :$port

tls:
  cert: $yaml_cert_path
  key: $yaml_key_path

quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432

auth:
  type: password
  password: $yaml_auth_pwd

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
    url: $yaml_proxy_url
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
    
    if [[ -n $firstport && -n $endport ]]; then
        server_port_string="$port,$firstport-$endport"
    else
        server_port_string=$port
    fi

    if [[ -n $(echo $ip | grep ":") ]]; then
        last_ip="[$ip]"
    else
        last_ip=$ip
    fi

    # 根据 insecure 变量设置布尔值
    if [[ $insecure == 1 ]]; then
        insecure_bool="true"
    else
        insecure_bool="false"
    fi

    mkdir -p /root/hy

    yaml_server=$(yaml_escape "$last_ip:$server_port_string")
    yaml_auth_pwd=$(yaml_escape "$auth_pwd")
    yaml_hy_domain=$(yaml_escape "$hy_domain")
    json_server=$(json_escape "$last_ip:$server_port_string")
    json_auth_pwd=$(json_escape "$auth_pwd")
    json_hy_domain=$(json_escape "$hy_domain")
    encoded_pwd=$(urlencode "$auth_pwd")
    encoded_sni=$(urlencode "$hy_domain")
    
    # 生成 YAML 客户端配置
    cat << EOF > /root/hy/hy-client.yaml
server: $yaml_server

auth: $yaml_auth_pwd

tls:
  sni: $yaml_hy_domain
  insecure: $insecure_bool

quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432

fastOpen: true

socks5:
  listen: 127.0.0.1:5678

EOF

    # 仅在端口跳跃模式下添加 transport 配置
    if [[ -n $firstport && -n $endport ]]; then
        cat << EOF >> /root/hy/hy-client.yaml
transport:
  type: udp
  udp:
EOF
        if [[ -n $min_hop_interval && -n $max_hop_interval ]]; then
            cat << EOF >> /root/hy/hy-client.yaml
    minHopInterval: ${min_hop_interval:-15}s
    maxHopInterval: ${max_hop_interval:-25}s
EOF
        else
            cat << EOF >> /root/hy/hy-client.yaml
    hopInterval: ${hop_interval:-25}s
EOF
        fi
    fi
    
    # 生成 JSON 配置
    if [[ -n $firstport && -n $endport ]]; then
        if [[ -n $min_hop_interval && -n $max_hop_interval ]]; then
            cat << EOF > /root/hy/hy-client.json
{
  "server": "$json_server",
  "auth": "$json_auth_pwd",
  "tls": {
    "sni": "$json_hy_domain",
    "insecure": $insecure_bool
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
    "type": "udp",
    "udp": {
      "minHopInterval": "${min_hop_interval:-15}s",
      "maxHopInterval": "${max_hop_interval:-25}s"
    }
  }
}
EOF
        else
            cat << EOF > /root/hy/hy-client.json
{
  "server": "$json_server",
  "auth": "$json_auth_pwd",
  "tls": {
    "sni": "$json_hy_domain",
    "insecure": $insecure_bool
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
    "type": "udp",
    "udp": {
      "hopInterval": "${hop_interval:-25}s"
    }
  }
}
EOF
        fi
    else
        cat << EOF > /root/hy/hy-client.json
{
  "server": "$json_server",
  "auth": "$json_auth_pwd",
  "tls": {
    "sni": "$json_hy_domain",
    "insecure": $insecure_bool
  },
  "quic": {
    "initStreamReceiveWindow": 16777216,
    "maxStreamReceiveWindow": 16777216,
    "initConnReceiveWindow": 33554432,
    "maxConnReceiveWindow": 33554432
  },
  "socks5": {
    "listen": "127.0.0.1:5678"
  }
}
EOF
    fi
    
    # 生成订阅链接 - 按照标准格式
    if [[ -n $firstport && -n $endport ]]; then
        # 端口跳跃模式
        if [[ -n $min_hop_interval && -n $max_hop_interval ]]; then
            url="hysteria2://${encoded_pwd}@${last_ip}:${port}?security=tls&mportHopInt=${min_hop_interval:-15}-${max_hop_interval:-25}&insecure=${insecure}&mport=${firstport}-${endport}&sni=${encoded_sni}#Hysteria2"
        else
            url="hysteria2://${encoded_pwd}@${last_ip}:${port}?security=tls&mportHopInt=${hop_interval:-25}&insecure=${insecure}&mport=${firstport}-${endport}&sni=${encoded_sni}#Hysteria2"
        fi
    else
        # 单端口模式
        url="hysteria2://${encoded_pwd}@${last_ip}:${port}?security=tls&insecure=${insecure}&sni=${encoded_sni}#Hysteria2"
    fi
    
    echo "$url" > /root/hy/url.txt
}

read_current_config(){
    if [[ -f /etc/hysteria/config.yaml ]]; then
        # 更准确的端口解析
        port=$(grep "^listen:" /etc/hysteria/config.yaml | sed 's/listen://g' | sed 's/[[:space:]]//g' | sed 's/\[.*\]//g' | sed 's/://g')
        cert_path=$(yaml_unescape "$(grep "^[[:space:]]*cert:" /etc/hysteria/config.yaml | sed 's/^[[:space:]]*cert:[[:space:]]*//')")
        key_path=$(yaml_unescape "$(grep "^[[:space:]]*key:" /etc/hysteria/config.yaml | sed 's/^[[:space:]]*key:[[:space:]]*//')")
        auth_pwd=$(yaml_unescape "$(grep "^[[:space:]]*password:" /etc/hysteria/config.yaml | sed 's/^[[:space:]]*password:[[:space:]]*//')")
        
        if grep -q "type: proxy" /etc/hysteria/config.yaml; then
            masq_type="proxy"
            proxysite=$(yaml_unescape "$(grep "^[[:space:]]*url:" /etc/hysteria/config.yaml | sed 's/^[[:space:]]*url:[[:space:]]*//')")
            proxysite=$(echo "$proxysite" | sed 's#^https://##')
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
            hy_domain=$(yaml_unescape "$(grep "^[[:space:]]*sni:" /root/hy/hy-client.yaml | sed 's/^[[:space:]]*sni:[[:space:]]*//')")
            # 读取跳跃间隔
            hop_interval=$(grep "hopInterval:" /root/hy/hy-client.yaml | awk '{print $2}' | sed 's/s$//')
            min_hop_interval=$(grep "minHopInterval:" /root/hy/hy-client.yaml | awk '{print $2}' | sed 's/s$//')
            max_hop_interval=$(grep "maxHopInterval:" /root/hy/hy-client.yaml | awk '{print $2}' | sed 's/s$//')
            # 读取 insecure 设置
            insecure_value=$(grep "insecure:" /root/hy/hy-client.yaml | awk '{print $2}')
            if [[ $insecure_value == "true" ]]; then
                insecure=1
            else
                insecure=0
            fi
        else
            hy_domain=$(openssl x509 -in "$cert_path" -noout -subject 2>/dev/null | sed 's/.*CN = //;s/,.*//' | sed 's/.*CN=//;s/,.*//')
            [[ -z $hy_domain ]] && hy_domain="www.bing.com"
            hop_interval=25
            min_hop_interval=""
            max_hop_interval=""
            # 如果是 bing.com 则认为是自签证书
            if [[ $hy_domain == "www.bing.com" ]]; then
                insecure=1
            else
                insecure=0
            fi
        fi
        
        # 优先读取脚本自己的端口状态文件，避免误读系统里其他服务的 iptables 规则。
        if ! load_port_state; then
            port_hop_rule=$(iptables -t nat -S PREROUTING 2>/dev/null | grep -F "$IPTABLES_NAT_COMMENT" | head -n 1)
            port_range=$(echo "$port_hop_rule" | sed -nE 's/.*--dport ([0-9]+):([0-9]+).*/\1:\2/p')
            if [[ -n $port_range ]]; then
                firstport=$(echo "$port_range" | cut -d: -f1)
                endport=$(echo "$port_range" | cut -d: -f2)
            else
                firstport=""
                endport=""
            fi
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
    if [[ $SYSTEM == "CentOS" ]]; then
        ${PACKAGE_INSTALL[int]} curl wget sudo qrencode procps openssl iproute acl
    else
        ${PACKAGE_INSTALL[int]} curl wget sudo qrencode procps openssl iproute2 acl
    fi

    install_iptables_persistent

    bash <(curl -fsSL https://get.hy2.sh/)

    if [[ ! -f /usr/local/bin/hysteria ]]; then
        red "Hysteria 2 安装失败！"
        exit 1
    fi

    inst_cert
    inst_port_config
    inst_pwd
    inst_site
    inst_bandwidth
    generate_config
    generate_client_config

    fix_permissions

    systemctl daemon-reload
    systemctl enable hysteria-server
    
    echo "正在等待网络环境就绪..."
    sleep 5
    systemctl start hysteria-server
    
    install_management_command

    sleep 2
    if systemctl is-active --quiet hysteria-server && [[ -f '/etc/hysteria/config.yaml' ]]; then
        green "Hysteria 2 服务启动成功"
    else
        red "Hysteria 2 服务启动失败，请检查日志：journalctl -u hysteria-server -e" && exit 1
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
    rm -f /etc/systemd/system/hysteria-server.service /etc/systemd/system/hysteria-server@.service
    rm -rf /usr/local/bin/hysteria /etc/hysteria /root/hy /root/hysteria.sh
    rm -f /usr/bin/hy2 /usr/local/bin/hy2-fix-cert-perms /etc/letsencrypt/renewal-hooks/deploy/hy2-fix-cert-perms
    remove_hy2_iptables_rules
    save_iptables_rules
    systemctl daemon-reload
    green "Hysteria 2 已彻底卸载完成！"
}

starthysteria(){
    systemctl start hysteria-server
    systemctl enable hysteria-server >/dev/null 2>&1
    if systemctl is-active --quiet hysteria-server; then
        green "Hysteria 2 启动成功"
    else
        red "Hysteria 2 启动失败，请查看日志：journalctl -u hysteria-server -e"
        return 1
    fi
}

stophysteria(){
    systemctl stop hysteria-server
    systemctl disable hysteria-server >/dev/null 2>&1
    green "Hysteria 2 已停止"
}

hysteriaswitch(){
    yellow "请选择你需要的操作："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 启动 Hysteria 2"
    echo -e " ${GREEN}2.${PLAIN} 关闭 Hysteria 2"
    echo -e " ${GREEN}3.${PLAIN} 重启 Hysteria 2"
    echo ""
    read -rp "请输入选项 [1-3]: " switchInput
    case $switchInput in
        1 ) starthysteria ;;
        2 ) stophysteria ;;
        3 ) stophysteria && starthysteria ;;
        * ) exit 1 ;;
    esac
}

changebandwidth(){
    if ! read_current_config; then
        red "未找到配置文件，请先安装 Hysteria 2"
        return 1
    fi
    
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
        while true; do
            read -rp "请输入限速数值 (单位 mbps，例如 50): " custBw
            [[ -z $custBw ]] && custBw=100
            if ! is_number "$custBw" || (( 10#$custBw <= 0 )); then
                red "限速数值必须是正整数！"
                continue
            fi
            custBw=$((10#$custBw))
            break
        done
        limit_bandwidth="yes"
        bandwidth_value="$custBw"
        yellow "已设置为：$custBw Mbps 限速"
    else
        limit_bandwidth="no"
        bandwidth_value=""
        yellow "已关闭带宽限制"
    fi

    generate_config
    fix_permissions
    stophysteria && starthysteria
    green "带宽限制配置已更新！"
}

changeport(){
    if ! read_current_config; then
        red "未找到配置文件，请先安装 Hysteria 2"
        return 1
    fi
    systemctl stop hysteria-server >/dev/null 2>&1
    inst_port_config
    generate_config
    generate_client_config
    fix_permissions
    starthysteria
    green "Hysteria 2 端口配置已更新！"
    showconf
}

changepasswd(){
    if ! read_current_config; then
        red "未找到配置文件，请先安装 Hysteria 2"
        return 1
    fi
    read -rp "设置 Hysteria 2 密码（回车跳过为随机字符）：" new_pwd
    [[ -z $new_pwd ]] && new_pwd=$(generate_password)
    auth_pwd=$new_pwd
    generate_config
    generate_client_config
    fix_permissions
    stophysteria && starthysteria
    green "Hysteria 2 节点密码已成功修改为：$auth_pwd"
    showconf
}

change_cert(){
    if ! read_current_config; then
        red "未找到配置文件，请先安装 Hysteria 2"
        return 1
    fi
    inst_cert
    generate_config
    generate_client_config
    fix_permissions
    stophysteria && starthysteria
    green "Hysteria 2 节点证书类型已成功修改"
    showconf
}

changeproxysite(){
    if ! read_current_config; then
        red "未找到配置文件，请先安装 Hysteria 2"
        return 1
    fi
    inst_site
    generate_config
    fix_permissions
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
    read -rp " 请选择操作 [1-5]：" confAnswer
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
        0 ) exit 0 ;;
        * ) exit 1 ;;
    esac
}

menu
