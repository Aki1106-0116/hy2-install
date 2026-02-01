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

[[ $EUID -ne 0 ]] && red "请注意：必须使用 root 用户才能运行此脚本！" && exit 1

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

[[ -z $SYSTEM ]] && red "抱歉，脚本目前不支持您的 VPS 操作系统！" && exit 1

if [[ -z $(type -P curl) ]]; then
    if [[ ! $SYSTEM == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl
fi

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

escape_json_string() {
    local string="$1"
    string="${string//\\/\\\\}"
    string="${string//\"/\\\"}"
    string="${string//$'\n'/\\n}"
    string="${string//$'\r'/\\r}"
    string="${string//$'\t'/\\t}"
    echo "$string"
}

escape_yaml_string() {
    local string="$1"
    if [[ "$string" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "$string"
    else
        string="${string//\\/\\\\}"
        string="${string//\"/\\\"}"
        string="${string//	/\\t}"
        echo "\"$string\""
    fi
}

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

get_cert_domains(){
    local cert_file="$1"
    
    if [[ ! -f "$cert_file" ]]; then
        echo ""
        return
    fi
    
    local cn=$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | sed -n 's/.*CN\s*=\s*\([^,/]*\).*/\1/p' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    local san=$(openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep -A1 "Subject Alternative Name" | tail -1 | sed 's/DNS://g' | tr ',' '\n' | sed 's/^[[:space:]]*//' | tr '\n' ' ')
    
    echo "$cn $san" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ' | sed 's/[[:space:]]*$//'
}

cert_contains_domain(){
    local cert_file="$1"
    local target_domain="$2"
    
    local cert_domains=$(get_cert_domains "$cert_file")
    
    for d in $cert_domains; do
        if [[ "$d" == "$target_domain" ]]; then
            return 0
        fi
        if [[ "$d" == "*."* ]]; then
            local wildcard_base="${d#\*.}"
            if [[ "$target_domain" == *".$wildcard_base" ]] || [[ "$target_domain" == "$wildcard_base" ]]; then
                return 0
            fi
        fi
    done
    return 1
}

get_cert_primary_domain(){
    local cert_file="$1"
    
    if [[ ! -f "$cert_file" ]]; then
        echo ""
        return
    fi
    
    local cn=$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | sed -n 's/.*CN\s*=\s*\([^,/]*\).*/\1/p' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    
    if [[ -n "$cn" ]]; then
        echo "$cn"
        return
    fi
    
    local san=$(openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep -A1 "Subject Alternative Name" | tail -1 | sed 's/DNS://g' | tr ',' '\n' | sed 's/^[[:space:]]*//' | head -1)
    
    echo "$san"
}

save_cert_config(){
    local mode="$1"
    local domain="$2"
    local source_cert="$3"
    local source_key="$4"
    
    mkdir -p /etc/hysteria
    
    cat << EOF > /etc/hysteria/cert_source.conf
CERT_MODE=$mode
CERT_DOMAIN=$domain
SOURCE_CERT_PATH=$source_cert
SOURCE_KEY_PATH=$source_key
EOF
    
    chmod 600 /etc/hysteria/cert_source.conf
}

read_cert_config(){
    if [[ -f /etc/hysteria/cert_source.conf ]]; then
        source /etc/hysteria/cert_source.conf
        return 0
    fi
    return 1
}

create_cert_sync_script(){
    cat << 'SYNCEOF' > /etc/hysteria/sync_cert.sh
#!/bin/bash

LOG_FILE="/etc/hysteria/sync_cert.log"
CONF_FILE="/etc/hysteria/cert_source.conf"
LOCK_FILE="/tmp/hysteria_cert_sync.lock"

exec 200>"$LOCK_FILE"
flock -n 200 || exit 0

log(){
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" >> "$LOG_FILE"
    local line_count=$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)
    if [[ "$line_count" -gt 200 ]]; then
        local tmp_file=$(mktemp)
        tail -100 "$LOG_FILE" > "$tmp_file" && mv "$tmp_file" "$LOG_FILE"
    fi
}

if [[ ! -f "$CONF_FILE" ]]; then
    exit 0
fi

source "$CONF_FILE"

if [[ "$CERT_MODE" == "selfsigned" ]]; then
    exit 0
fi

if [[ -z "$SOURCE_CERT_PATH" ]] || [[ -z "$SOURCE_KEY_PATH" ]] || [[ -z "$CERT_DOMAIN" ]]; then
    log "ERROR: 配置不完整"
    exit 1
fi

sleep 2

REAL_CERT_PATH=$(readlink -f "$SOURCE_CERT_PATH" 2>/dev/null || echo "$SOURCE_CERT_PATH")
REAL_KEY_PATH=$(readlink -f "$SOURCE_KEY_PATH" 2>/dev/null || echo "$SOURCE_KEY_PATH")

if [[ ! -f "$REAL_CERT_PATH" ]] || [[ ! -f "$REAL_KEY_PATH" ]]; then
    log "ERROR: 源文件不存在 (cert: $REAL_CERT_PATH, key: $REAL_KEY_PATH)"
    exit 1
fi

SOURCE_HASH=$(cat "$REAL_CERT_PATH" "$REAL_KEY_PATH" 2>/dev/null | md5sum | cut -d' ' -f1)
DEST_HASH=""
if [[ -f /etc/hysteria/cert.crt ]] && [[ -f /etc/hysteria/private.key ]]; then
    DEST_HASH=$(cat /etc/hysteria/cert.crt /etc/hysteria/private.key 2>/dev/null | md5sum | cut -d' ' -f1)
fi

if [[ "$SOURCE_HASH" == "$DEST_HASH" ]] && [[ -n "$DEST_HASH" ]]; then
    exit 0
fi

if ! openssl x509 -in "$REAL_CERT_PATH" -noout -checkend 0 2>/dev/null; then
    log "ERROR: 源证书已过期或无效"
    exit 1
fi

CERT_CN=$(openssl x509 -in "$REAL_CERT_PATH" -noout -subject 2>/dev/null | sed -n 's/.*CN\s*=\s*\([^,/]*\).*/\1/p')

log "INFO: 检测到证书更新，开始同步 (CN=$CERT_CN, 配置域名=$CERT_DOMAIN)"

cp -f "$REAL_CERT_PATH" /etc/hysteria/cert.crt.new
cp -f "$REAL_KEY_PATH" /etc/hysteria/private.key.new

if [[ ! -s /etc/hysteria/cert.crt.new ]] || [[ ! -s /etc/hysteria/private.key.new ]]; then
    log "ERROR: 复制失败"
    rm -f /etc/hysteria/cert.crt.new /etc/hysteria/private.key.new
    exit 1
fi

mv -f /etc/hysteria/cert.crt.new /etc/hysteria/cert.crt
mv -f /etc/hysteria/private.key.new /etc/hysteria/private.key

if id "hysteria" &>/dev/null; then
    chown hysteria:hysteria /etc/hysteria/cert.crt /etc/hysteria/private.key
fi
chmod 644 /etc/hysteria/cert.crt
chmod 600 /etc/hysteria/private.key

if systemctl is-active hysteria-server &>/dev/null; then
    if systemctl reload hysteria-server 2>/dev/null; then
        log "SUCCESS: 证书同步完成，服务已重载"
    elif systemctl restart hysteria-server 2>/dev/null; then
        log "SUCCESS: 证书同步完成，服务已重启"
    else
        log "ERROR: 服务重启失败"
        exit 1
    fi
else
    log "INFO: 证书已同步（服务未运行）"
fi
SYNCEOF
    chmod +x /etc/hysteria/sync_cert.sh
}

create_cert_watcher_script(){
    cat << 'WATCHEOF' > /etc/hysteria/cert_watcher.sh
#!/bin/bash

CONF_FILE="/etc/hysteria/cert_source.conf"
LOG_FILE="/etc/hysteria/sync_cert.log"

log(){
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WATCHER] $1" >> "$LOG_FILE"
}

if [[ ! -f "$CONF_FILE" ]]; then
    log "ERROR: 配置文件不存在，退出监控"
    exit 1
fi

source "$CONF_FILE"

if [[ "$CERT_MODE" == "selfsigned" ]]; then
    log "INFO: 自签证书模式，无需监控"
    exit 0
fi

if [[ -z "$SOURCE_CERT_PATH" ]] || [[ -z "$SOURCE_KEY_PATH" ]]; then
    log "ERROR: 源路径未配置，退出监控"
    exit 1
fi

REAL_CERT_PATH=$(readlink -f "$SOURCE_CERT_PATH" 2>/dev/null || echo "$SOURCE_CERT_PATH")
REAL_KEY_PATH=$(readlink -f "$SOURCE_KEY_PATH" 2>/dev/null || echo "$SOURCE_KEY_PATH")

CERT_DIR=$(dirname "$REAL_CERT_PATH")
KEY_DIR=$(dirname "$REAL_KEY_PATH")

ORIG_CERT_DIR=$(dirname "$SOURCE_CERT_PATH")
ORIG_KEY_DIR=$(dirname "$SOURCE_KEY_PATH")

declare -A WATCH_DIRS
for dir in "$CERT_DIR" "$KEY_DIR" "$ORIG_CERT_DIR" "$ORIG_KEY_DIR"; do
    if [[ -d "$dir" ]]; then
        WATCH_DIRS["$dir"]=1
    fi
done

if [[ ${#WATCH_DIRS[@]} -eq 0 ]]; then
    log "ERROR: 没有可监控的目录"
    exit 1
fi

DIRS_TO_WATCH="${!WATCH_DIRS[*]}"
log "INFO: 开始监控目录: $DIRS_TO_WATCH"

inotifywait -m -q -e close_write,moved_to,create,attrib --format '%w%f' $DIRS_TO_WATCH 2>/dev/null | while read FILE; do
    BASENAME=$(basename "$FILE")
    if [[ "$FILE" == "$SOURCE_CERT_PATH" ]] || [[ "$FILE" == "$SOURCE_KEY_PATH" ]] || \
       [[ "$FILE" == "$REAL_CERT_PATH" ]] || [[ "$FILE" == "$REAL_KEY_PATH" ]] || \
       [[ "$BASENAME" == *"fullchain"* ]] || [[ "$BASENAME" == *".crt" ]] || \
       [[ "$BASENAME" == *".pem" ]] || [[ "$BASENAME" == *".cer" ]] || [[ "$BASENAME" == *".key" ]]; then
        log "INFO: 检测到文件变化: $FILE"
        sleep 3
        /etc/hysteria/sync_cert.sh
    fi
done
WATCHEOF
    chmod +x /etc/hysteria/cert_watcher.sh
}

create_watcher_service(){
    cat << 'EOF' > /etc/systemd/system/hysteria-cert-watcher.service
[Unit]
Description=Hysteria Certificate Watcher
After=network.target
Wants=hysteria-server.service

[Service]
Type=simple
ExecStart=/etc/hysteria/cert_watcher.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
}

create_sync_timer(){
    cat << 'EOF' > /etc/systemd/system/hysteria-cert-sync.service
[Unit]
Description=Hysteria Certificate Sync
After=network.target

[Service]
Type=oneshot
ExecStart=/etc/hysteria/sync_cert.sh
EOF

    cat << 'EOF' > /etc/systemd/system/hysteria-cert-sync.timer
[Unit]
Description=Hysteria Certificate Sync Timer

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
AccuracySec=1min

[Install]
WantedBy=timers.target
EOF
    
    systemctl daemon-reload
}

setup_certbot_hook(){
    local source_cert="$1"
    
    if [[ "$source_cert" == *"/etc/letsencrypt/"* ]]; then
        if command -v certbot &>/dev/null; then
            mkdir -p /etc/letsencrypt/renewal-hooks/deploy
            cat << 'EOF' > /etc/letsencrypt/renewal-hooks/deploy/hysteria-sync.sh
#!/bin/bash
/etc/hysteria/sync_cert.sh
EOF
            chmod +x /etc/letsencrypt/renewal-hooks/deploy/hysteria-sync.sh
            return 0
        fi
    fi
    return 1
}

setup_acme_reloadcmd(){
    local domain="$1"
    local acme_home="${HOME}/.acme.sh"
    
    if [[ -f "$acme_home/acme.sh" ]]; then
        local conf_file=""
        if [[ -f "$acme_home/${domain}_ecc/${domain}.conf" ]]; then
            conf_file="$acme_home/${domain}_ecc/${domain}.conf"
        elif [[ -f "$acme_home/${domain}/${domain}.conf" ]]; then
            conf_file="$acme_home/${domain}/${domain}.conf"
        fi
        
        if [[ -n "$conf_file" ]]; then
            if ! grep -q "hysteria" "$conf_file" 2>/dev/null; then
                bash "$acme_home/acme.sh" --install-cert -d "$domain" \
                    --reloadcmd "/etc/hysteria/sync_cert.sh" \
                    --ecc 2>/dev/null || true
            fi
        fi
    fi
}

setup_cert_monitoring(){
    local source_cert="$1"
    local source_key="$2"
    
    yellow "正在配置证书自动同步功能..."
    
    create_cert_sync_script
    
    local has_inotify=0
    if command -v inotifywait &>/dev/null; then
        has_inotify=1
    else
        yellow "正在安装实时监控工具 (inotify-tools)..."
        ${PACKAGE_INSTALL[int]} inotify-tools 2>/dev/null
        if command -v inotifywait &>/dev/null; then
            has_inotify=1
        fi
    fi
    
    if [[ $has_inotify -eq 1 ]]; then
        green "✓ 已启用实时监控模式"
        create_cert_watcher_script
        create_watcher_service
        
        systemctl stop hysteria-cert-watcher 2>/dev/null
        systemctl disable hysteria-cert-watcher 2>/dev/null
        
        systemctl enable hysteria-cert-watcher
        systemctl start hysteria-cert-watcher
        
        if systemctl is-active hysteria-cert-watcher &>/dev/null; then
            green "✓ 实时监控服务已运行"
        else
            yellow "⚠ 监控服务启动异常，将转为定时检查"
        fi
    else
        yellow "⚠ 未找到实时监控工具，将使用定时检查（每5分钟）"
    fi
    
    create_sync_timer
    systemctl enable hysteria-cert-sync.timer
    systemctl start hysteria-cert-sync.timer
    green "✓ 定时同步任务已启动"
    
    if setup_certbot_hook "$source_cert"; then
        green "✓ 已配置 Certbot 自动同步钩子"
    fi
    
    sed -i '/hysteria.*sync_cert/d' /etc/crontab 2>/dev/null
    crontab -l 2>/dev/null | grep -v "hysteria.*sync_cert" | crontab - 2>/dev/null
    
    echo ""
    green "证书同步系统配置完毕！"
}

stop_cert_monitoring(){
    systemctl stop hysteria-cert-watcher 2>/dev/null
    systemctl disable hysteria-cert-watcher 2>/dev/null
    systemctl stop hysteria-cert-sync.timer 2>/dev/null
    systemctl disable hysteria-cert-sync.timer 2>/dev/null
    rm -f /etc/systemd/system/hysteria-cert-watcher.service
    rm -f /etc/systemd/system/hysteria-cert-sync.service
    rm -f /etc/systemd/system/hysteria-cert-sync.timer
    systemctl daemon-reload
    
    rm -f /etc/letsencrypt/renewal-hooks/deploy/hysteria-sync.sh 2>/dev/null
    sed -i '/hysteria.*sync_cert/d' /etc/crontab 2>/dev/null
    
    rm -f /etc/hysteria/sync_cert.sh
    rm -f /etc/hysteria/cert_watcher.sh
    rm -f /etc/hysteria/sync_cert.log
    rm -f /etc/hysteria/cert_source.conf
    rm -f /root/ca.log
}

get_acme_cert_paths(){
    local domain="$1"
    local acme_home=""
    
    if [[ -d "${HOME}/.acme.sh" ]]; then
        acme_home="${HOME}/.acme.sh"
    elif [[ -d "/root/.acme.sh" ]]; then
        acme_home="/root/.acme.sh"
    else
        return 1
    fi
    
    local ecc_dir="${acme_home}/${domain}_ecc"
    if [[ -d "$ecc_dir" ]]; then
        local cert_file="${ecc_dir}/fullchain.cer"
        local key_file="${ecc_dir}/${domain}.key"
        if [[ -f "$cert_file" && -f "$key_file" ]]; then
            echo "$cert_file|$key_file"
            return 0
        fi
    fi
    
    local rsa_dir="${acme_home}/${domain}"
    if [[ -d "$rsa_dir" ]]; then
        local cert_file="${rsa_dir}/fullchain.cer"
        local key_file="${rsa_dir}/${domain}.key"
        if [[ -f "$cert_file" && -f "$key_file" ]]; then
            echo "$cert_file|$key_file"
            return 0
        fi
    fi
    
    return 1
}

check_port_in_use(){
    local port=$1
    if ss -tunlp 2>/dev/null | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -qw "$port"; then
        return 0
    fi
    return 1
}

inst_port_config(){
    iptables -t nat -F PREROUTING >/dev/null 2>&1
    ip6tables -t nat -F PREROUTING >/dev/null 2>&1
    
    echo ""
    green "请选择端口模式："
    echo -e " ${GREEN}1.${PLAIN} 端口跳跃 (抗封锁，推荐)"
    echo -e " ${GREEN}2.${PLAIN} 单端口模式"
    echo ""
    read -rp "请输入选项 [1-2]: " portMode
    
    if [[ $portMode == 2 ]]; then
        while true; do
            read -p "请输入运行端口 (1-65535) [回车随机]: " port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
            
            if [[ ! $port =~ ^[0-9]+$ ]] || [[ $port -lt 1 ]] || [[ $port -gt 65535 ]]; then
                red "端口必须是 1 到 65535 之间的数字！"
                continue
            fi
            
            if check_port_in_use "$port"; then
                red "端口 $port 已被占用，请更换！"
                continue
            fi
            
            break
        done
        
        firstport=""
        endport=""
        hop_interval=""
        
        iptables -I INPUT -p udp --dport $port -j ACCEPT
        ip6tables -I INPUT -p udp --dport $port -j ACCEPT
        save_iptables_rules
        
        yellow "将运行在单端口：$port"
        
    else
        green "已启用端口跳跃模式"
        echo ""
        
        while true; do
            read -p "请输入起始端口 [建议 20000 以上] (回车随机): " firstport
            [[ -z $firstport ]] && firstport=$(shuf -i 2500-10000 -n 1)
            
            if [[ ! $firstport =~ ^[0-9]+$ ]] || [[ $firstport -lt 1 ]] || [[ $firstport -gt 65535 ]]; then
                red "请输入有效的数字端口！"
                continue
            fi
            
            if check_port_in_use "$firstport"; then
                red "起始端口 $firstport 已被占用，请更换！"
                continue
            fi
            
            break
        done
        
        while true; do
            default_endport=$((firstport + 75))
            [[ $default_endport -gt 65535 ]] && default_endport=65535
            read -p "请输入结束端口 (回车默认 $default_endport): " endport
            [[ -z $endport ]] && endport=$default_endport
            
            if [[ ! $endport =~ ^[0-9]+$ ]] || [[ $endport -lt 1 ]] || [[ $endport -gt 65535 ]]; then
                red "请输入有效的数字端口！"
                continue
            fi
            
            if [[ $firstport -ge $endport ]]; then
                red "起始端口必须小于结束端口！"
                continue
            fi
            
            local conflict_port=""
            for ((p=firstport; p<=endport; p++)); do
                if check_port_in_use "$p"; then
                    conflict_port=$p
                    break
                fi
            done
            
            if [[ -n $conflict_port ]]; then
                red "范围内的端口 $conflict_port 已被占用，请调整范围！"
                continue
            fi
            
            break
        done
        
        read -p "跳跃间隔秒数 [默认 25s]: " hop_interval
        [[ -z $hop_interval ]] && hop_interval=25
        [[ ! $hop_interval =~ ^[0-9]+$ ]] && hop_interval=25
        
        port=$firstport
        
        iptables -t nat -A PREROUTING -p udp --dport $firstport:$endport -j DNAT --to-destination :$port
        ip6tables -t nat -A PREROUTING -p udp --dport $firstport:$endport -j DNAT --to-destination :$port
        
        iptables -I INPUT -p udp --dport $firstport:$endport -j ACCEPT
        ip6tables -I INPUT -p udp --dport $firstport:$endport -j ACCEPT
        save_iptables_rules
        
        yellow "跳跃范围：$firstport - $endport (主端口: $port, 间隔: ${hop_interval}s)"
    fi
}

inst_pwd(){
    read -p "请设置连接密码（直接回车随机生成）：" auth_pwd
    [[ -z $auth_pwd ]] && auth_pwd=$(date +%s%N | md5sum | cut -c 1-8)
    yellow "密码已设置为：$auth_pwd"
}

inst_site(){
    echo ""
    green "请选择伪装页面："
    echo -e " ${GREEN}1.${PLAIN} 模拟网站不存在 (403 Forbidden) ${YELLOW}（最快，推荐）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} 伪装成其他网站 (Proxy)"
    echo ""
    read -rp "请输入选项 [1-2]: " masqInput
    
    if [[ $masqInput == 2 ]]; then
        masq_type="proxy"
        read -rp "请输入要伪装的目标域名（不带 https://）[默认首尔大学]：" proxysite
        [[ -z $proxysite ]] && proxysite="en.snu.ac.kr"
        yellow "已设置为伪装：$proxysite"
    else
        masq_type="string"
        proxysite=""
        green "已选择 403 伪装模式"
    fi
}

inst_bandwidth(){
    echo ""
    green "是否限制服务器带宽？(建议限制以防被运营商检测)："
    echo -e " ${GREEN}1.${PLAIN} 限制为 100 Mbps ${YELLOW}（推荐）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} 不限制速度"
    echo ""
    read -rp "请输入选项 [1-2]: " bwInput
    
    if [[ $bwInput == 2 ]]; then
        limit_bandwidth="no"
        bandwidth_value=""
    else
        limit_bandwidth="yes"
        bandwidth_value="100"
    fi
}

generate_config(){
    mkdir -p /etc/hysteria
    local yaml_pwd=$(escape_yaml_string "$auth_pwd")

    cat << EOF > /etc/hysteria/config.yaml
listen: :$port

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
  password: $yaml_pwd

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

    if [[ $insecure == 1 ]]; then
        insecure_bool="true"
    else
        insecure_bool="false"
    fi

    mkdir -p /root/hy
    local yaml_pwd=$(escape_yaml_string "$auth_pwd")
    
    cat << EOF > /root/hy/hy-client.yaml
server: $last_ip:$server_port_string

auth: $yaml_pwd

tls:
  sni: $hy_domain
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

    if [[ -n $firstport && -n $endport ]]; then
        cat << EOF >> /root/hy/hy-client.yaml
transport:
  udp:
    hopInterval: ${hop_interval:-25}s
EOF
    fi
    
    local json_pwd=$(escape_json_string "$auth_pwd")
    
    if [[ -n $firstport && -n $endport ]]; then
        cat << EOF > /root/hy/hy-client.json
{
  "server": "$last_ip:$server_port_string",
  "auth": "$json_pwd",
  "tls": {
    "sni": "$hy_domain",
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
    "udp": {
      "hopInterval": "${hop_interval:-25}s"
    }
  }
}
EOF
    else
        cat << EOF > /root/hy/hy-client.json
{
  "server": "$last_ip:$server_port_string",
  "auth": "$json_pwd",
  "tls": {
    "sni": "$hy_domain",
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

    encoded_pwd=$(urlencode "$auth_pwd")
    
    if [[ -n $firstport && -n $endport ]]; then
        url="hysteria2://${encoded_pwd}@${last_ip}:${port}?security=tls&mportHopInt=${hop_interval:-25}&insecure=${insecure}&mport=${firstport}-${endport}&sni=${hy_domain}#Hysteria2"
    else
        url="hysteria2://${encoded_pwd}@${last_ip}:${port}?security=tls&insecure=${insecure}&sni=${hy_domain}#Hysteria2"
    fi
    
    echo "$url" > /root/hy/url.txt
}

read_current_config(){
    if [[ -f /etc/hysteria/config.yaml ]]; then
        port=$(grep "^listen:" /etc/hysteria/config.yaml | sed 's/listen://g' | sed 's/[[:space:]]//g' | sed 's/\[.*\]//g' | sed 's/://g')
        cert_path=$(grep "cert:" /etc/hysteria/config.yaml | awk '{print $2}')
        key_path=$(grep "key:" /etc/hysteria/config.yaml | awk '{print $2}')
        auth_pwd=$(grep "password:" /etc/hysteria/config.yaml | sed 's/.*password:[[:space:]]*//' | sed 's/^"//' | sed 's/"$//' | sed "s/^'//" | sed "s/'$//")
        
        if grep -q "type: proxy" /etc/hysteria/config.yaml; then
            masq_type="proxy"
            proxysite=$(grep "url:" /etc/hysteria/config.yaml | sed 's/.*https:\/\///g' | sed 's/[[:space:]]//g')
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
        
        if read_cert_config; then
            hy_domain="$CERT_DOMAIN"
            [[ "$CERT_MODE" == "selfsigned" ]] && insecure=1 || insecure=0
        elif [[ -f /root/hy/hy-client.yaml ]]; then
            hy_domain=$(grep "sni:" /root/hy/hy-client.yaml | awk '{print $2}')
            [[ $(grep "insecure:" /root/hy/hy-client.yaml | awk '{print $2}') == "true" ]] && insecure=1 || insecure=0
        else
            hy_domain=$(get_cert_primary_domain "$cert_path")
            [[ -z $hy_domain ]] && hy_domain="www.bing.com"
            [[ $hy_domain == "www.bing.com" ]] && insecure=1 || insecure=0
        fi
        
        [[ -f /root/hy/hy-client.yaml ]] && hop_interval=$(grep "hopInterval:" /root/hy/hy-client.yaml | awk '{print $2}' | sed 's/s$//') || hop_interval=25
        
        port_hop_rule=$(iptables -t nat -L PREROUTING -n 2>/dev/null | grep "dpts:" | head -1)
        if [[ -n $port_hop_rule ]]; then
            port_range=$(echo "$port_hop_rule" | grep -o 'dpts:[0-9]*:[0-9]*' | sed 's/dpts://')
            if [[ -n $port_range ]]; then
                firstport=$(echo "$port_range" | cut -d: -f1)
                endport=$(echo "$port_range" | cut -d: -f2)
            else
                firstport=""
                endport=""
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
    ${PACKAGE_INSTALL[int]} curl wget sudo qrencode procps openssl

    install_iptables_persistent

    wget -N https://raw.githubusercontent.com/Misaka-blog/hysteria-install/main/hy2/install_server.sh
    bash install_server.sh
    rm -f install_server.sh

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
    
    sleep 3
    systemctl start hysteria-server
    
    [[ ! -f /usr/bin/hy2 ]] && cp -f "$0" /usr/bin/hy2 && chmod +x /usr/bin/hy2

    sleep 2
    if [[ -n $(systemctl status hysteria-server 2>/dev/null | grep -w active) ]]; then
        green "Hysteria 2 服务启动成功"
    else
        red "启动失败，请查看日志：journalctl -u hysteria-server -e" && exit 1
    fi
    
    echo ""
    green "====================================="
    green "  Hysteria 2 安装完成！"
    green "  管理命令：hy2"
    green "====================================="
    echo ""
    
    yellow "客户端 YAML 配置："
    cat /root/hy/hy-client.yaml
    echo ""
    yellow "客户端 JSON 配置："
    cat /root/hy/hy-client.json
    echo ""
    yellow "分享链接："
    cat /root/hy/url.txt
}

unsthysteria(){
    systemctl stop hysteria-server.service >/dev/null 2>&1
    systemctl disable hysteria-server.service >/dev/null 2>&1
    rm -f /lib/systemd/system/hysteria-server.service /lib/systemd/system/hysteria-server@.service
    rm -f /etc/systemd/system/hysteria-server.service /etc/systemd/system/hysteria-server@.service
    rm -rf /usr/local/bin/hysteria /etc/hysteria /root/hy /root/hysteria.sh
    rm -f /usr/bin/hy2
    rm -f /root/ca.log
    
    stop_cert_monitoring
    
    iptables -t nat -F PREROUTING >/dev/null 2>&1
    ip6tables -t nat -F PREROUTING >/dev/null 2>&1
    save_iptables_rules
    systemctl daemon-reload
    
    green "Hysteria 2 已卸载！"
    echo ""
    yellow "重要说明："
    echo "  • acme.sh 配置未受影响，所有域名证书正常续期"
    echo "  • certbot 配置未受影响，所有域名证书正常续期"
    echo "  • 如需删除证书，请手动操作 acme.sh 或 certbot"
}

starthysteria(){
    systemctl start hysteria-server
    systemctl enable hysteria-server >/dev/null 2>&1
    [[ -n $(systemctl status hysteria-server 2>/dev/null | grep -w active) ]] && green "启动成功" || red "启动失败"
}

stophysteria(){
    systemctl stop hysteria-server
    systemctl disable hysteria-server >/dev/null 2>&1
    green "已停止"
}

hysteriaswitch(){
    echo -e " ${GREEN}1.${PLAIN} 启动"
    echo -e " ${GREEN}2.${PLAIN} 停止"
    echo -e " ${GREEN}3.${PLAIN} 重启"
    read -rp "选项 [1-3]: " switchInput
    case $switchInput in
        1 ) starthysteria ;;
        2 ) stophysteria ;;
        3 ) stophysteria && starthysteria ;;
        * ) exit 1 ;;
    esac
}

changebandwidth(){
    read_current_config || { red "未安装"; return 1; }
    
    echo -e " ${GREEN}1.${PLAIN} 限制 100 Mbps"
    echo -e " ${GREEN}2.${PLAIN} 自定义"
    echo -e " ${GREEN}3.${PLAIN} 不限制"
    read -rp "选项 [1-3]: " bwChange
    
    case $bwChange in
        1 ) limit_bandwidth="yes"; bandwidth_value="100" ;;
        2 ) read -p "限速 (mbps): " custBw; limit_bandwidth="yes"; bandwidth_value="${custBw:-100}" ;;
        * ) limit_bandwidth="no"; bandwidth_value="" ;;
    esac

    generate_config
    fix_permissions
    stophysteria && starthysteria
    green "配置已更新！"
}

changeport(){
    read_current_config || { red "未安装"; return 1; }
    inst_port_config
    generate_config
    generate_client_config
    fix_permissions
    stophysteria && starthysteria
    green "端口已更新！"
    showconf
}

changepasswd(){
    read_current_config || { red "未安装"; return 1; }
    read -p "新密码（回车随机）：" new_pwd
    [[ -z $new_pwd ]] && new_pwd=$(date +%s%N | md5sum | cut -c 1-8)
    auth_pwd=$new_pwd
    generate_config
    generate_client_config
    fix_permissions
    stophysteria && starthysteria
    green "密码已修改为：$auth_pwd"
    showconf
}

change_cert(){
    read_current_config || { red "未安装"; return 1; }
    inst_cert
    generate_config
    generate_client_config
    fix_permissions
    stophysteria && starthysteria
    green "证书已修改"
    showconf
}

changeproxysite(){
    read_current_config || { red "未安装"; return 1; }
    inst_site
    generate_config
    fix_permissions
    stophysteria && starthysteria
    green "伪装已修改！"
}

sync_cert_now(){
    [[ ! -f /etc/hysteria/sync_cert.sh ]] && { red "同步脚本不存在"; return 1; }
    read_cert_config && [[ "$CERT_MODE" == "selfsigned" ]] && { yellow "自签证书无需同步"; return 0; }
    
    yellow "正在同步..."
    bash /etc/hysteria/sync_cert.sh
    [[ $? -eq 0 ]] && green "同步完成！" || red "同步失败，查看日志：/etc/hysteria/sync_cert.log"
}

show_cert_status(){
    echo ""
    yellow "==================== 证书状态 ===================="
    
    if read_cert_config; then
        echo -e "证书模式：${GREEN}$CERT_MODE${PLAIN}"
        echo -e "配置域名：${GREEN}$CERT_DOMAIN${PLAIN}"
        
        if [[ -n "$SOURCE_CERT_PATH" ]]; then
            echo ""
            echo "源证书路径：$SOURCE_CERT_PATH"
            local real_path=$(readlink -f "$SOURCE_CERT_PATH" 2>/dev/null)
            if [[ "$real_path" != "$SOURCE_CERT_PATH" ]] && [[ -n "$real_path" ]]; then
                echo "  └─ 实际路径：$real_path"
            fi
            if [[ -f "$SOURCE_CERT_PATH" ]]; then
                echo -e "源证书到期：${GREEN}$(openssl x509 -in "$SOURCE_CERT_PATH" -noout -enddate 2>/dev/null | cut -d= -f2)${PLAIN}"
            else
                echo -e "源证书：${RED}文件不存在！${PLAIN}"
            fi
        fi
        
        echo ""
        echo "--- Hysteria 使用的证书 ---"
        if [[ -f /etc/hysteria/cert.crt ]]; then
            echo -e "证书 CN：${GREEN}$(get_cert_primary_domain /etc/hysteria/cert.crt)${PLAIN}"
            echo -e "到期时间：${GREEN}$(openssl x509 -in /etc/hysteria/cert.crt -noout -enddate 2>/dev/null | cut -d= -f2)${PLAIN}"
        fi
        
        if [[ "$CERT_MODE" != "selfsigned" ]]; then
            echo ""
            echo "--- 同步服务状态 ---"
            
            if systemctl is-active hysteria-cert-watcher &>/dev/null; then
                echo -e "${GREEN}✓ inotify 实时监控运行中${PLAIN}"
            else
                echo -e "${YELLOW}⚠ inotify 实时监控未运行${PLAIN}"
            fi
            
            if systemctl is-active hysteria-cert-sync.timer &>/dev/null; then
                echo -e "${GREEN}✓ 定时同步任务运行中（每5分钟）${PLAIN}"
            fi
            
            if [[ -f /etc/letsencrypt/renewal-hooks/deploy/hysteria-sync.sh ]]; then
                echo -e "${GREEN}✓ Certbot 续期钩子已配置${PLAIN}"
            fi
            
            if [[ -f /etc/hysteria/sync_cert.log ]]; then
                echo ""
                echo "--- 最近同步日志 ---"
                tail -5 /etc/hysteria/sync_cert.log 2>/dev/null
            fi
        fi
        
        echo ""
        echo "--- 证书续期说明 ---"
        case "$CERT_MODE" in
            acme)
                echo "  • acme.sh 独立管理此证书的续期"
                echo "  • 续期由 acme.sh 的 cron 任务自动执行"
                echo "  • 此脚本仅负责同步，不干预续期"
                ;;
            external)
                echo "  • 源证书由原管理工具续期"
                echo "  • 此脚本检测到更新后自动同步"
                ;;
            selfsigned)
                echo "  • 自签证书有效期100年，无需续期"
                ;;
        esac
    else
        yellow "未找到证书配置"
    fi
    
    echo "=================================================="
}

changeconf(){
    green "配置变更："
    echo -e " ${GREEN}1.${PLAIN} 修改端口"
    echo -e " ${GREEN}2.${PLAIN} 修改密码"
    echo -e " ${GREEN}3.${PLAIN} 修改证书"
    echo -e " ${GREEN}4.${PLAIN} 修改伪装"
    echo -e " ${GREEN}5.${PLAIN} 修改带宽"
    echo -e " ${GREEN}6.${PLAIN} 立即同步证书"
    echo -e " ${GREEN}7.${PLAIN} 查看证书状态"
    read -p "选项 [1-7]：" confAnswer
    case $confAnswer in
        1 ) changeport ;;
        2 ) changepasswd ;;
        3 ) change_cert ;;
        4 ) changeproxysite ;;
        5 ) changebandwidth ;;
        6 ) sync_cert_now ;;
        7 ) show_cert_status ;;
        * ) exit 1 ;;
    esac
}

showconf(){
    [[ ! -f /root/hy/hy-client.yaml ]] && { red "未安装"; return 1; }
    yellow "YAML 配置："
    cat /root/hy/hy-client.yaml
    echo ""
    yellow "JSON 配置："
    cat /root/hy/hy-client.json
    echo ""
    yellow "分享链接："
    cat /root/hy/url.txt
}

menu() {
    clear
    echo "#############################################################"
    echo -e "#                  ${GREEN}Hysteria 2 一键安装脚本${PLAIN}                  #"
    echo "#############################################################"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 安装 Hysteria 2"
    echo -e " ${RED}2.${PLAIN} 卸载 Hysteria 2"
    echo " ------------------------------------------------------------"
    echo -e " 3. 启动/停止/重启"
    echo -e " 4. 修改配置"
    echo -e " 5. 显示配置"
    echo " ------------------------------------------------------------"
    echo -e " 0. 退出"
    echo ""
    read -rp "选项 [0-5]: " menuInput
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
